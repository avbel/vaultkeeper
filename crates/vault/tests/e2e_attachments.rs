//! Attachment upload, download and delete against the e2e Vaultwarden. Uses the server URL
//! directly: download links are built from the server's DOMAIN and must match its origin.

#![cfg(feature = "vw-it")]
#![allow(clippy::unwrap_used)]

mod support;

use support::{
    KdfChoice, TestVault, decrypt, drafts, env, raw_session, register, server_cipher_key,
};
use vk_crypto::{SymmetricKey, enc_buffer};
use vk_vault::{Error, VaultService};

/// Deterministic, incompressible-looking bytes (xorshift64*), so no fixture file is needed.
fn sample_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    (0..len)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn attachments_round_trip_without_leftover_temp_files() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let vault = &test.vault;
    let id = vault
        .save(None, drafts::login("With files", "u", "p"))
        .await
        .unwrap();

    let work = test.data_dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let source = work.join("report 2026.pdf");
    let plain = sample_bytes(1_500_000);
    std::fs::write(&source, &plain).unwrap();

    let uploaded = vault.upload_attachment(&id, source.clone()).await.unwrap();
    assert_eq!(&*uploaded.file_name, "report 2026.pdf");
    // type + IV + MAC + PKCS#7-padded ciphertext.
    assert_eq!(
        uploaded.size_bytes,
        1 + 16 + 32 + (plain.len() as u64 / 16 + 1) * 16
    );
    let listed = vault.attachments(&id).unwrap();
    assert_eq!(listed, vec![uploaded.clone()]);

    // What the server stores decrypts with the harness's own view of the keys.
    let server = raw_session(&env, &account).await;
    let stored = server.cipher(&id.0).await;
    let attachment = &stored.attachments.as_deref().unwrap()[0];
    let item_key = server_cipher_key(&stored, &account.user_key);
    assert_eq!(
        decrypt(attachment.file_name.as_deref(), &item_key),
        "report 2026.pdf"
    );
    let file_key = attachment
        .key
        .as_deref()
        .unwrap()
        .parse::<vk_crypto::EncString>()
        .unwrap()
        .decrypt(&item_key)
        .unwrap();
    assert_eq!(file_key.len(), 64);
    let info = server
        .client
        .attachment_info(&server.token, &id.0, &uploaded.id)
        .await
        .unwrap();
    let mut body = Vec::new();
    server
        .client
        .download_attachment(info.url.as_deref().unwrap(), &mut body)
        .await
        .unwrap();
    let file_key = SymmetricKey::from_bytes(&file_key).unwrap();
    assert_eq!(*enc_buffer::decrypt_bytes(&file_key, &body).unwrap(), plain);

    let dest = work.join("downloaded.pdf");
    vault
        .download_attachment(&id, &uploaded.id, dest.clone())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), plain);
    let temp = test
        .account_dir(&vault.active_account_id().unwrap())
        .join("tmp");
    let leftovers: Vec<_> = std::fs::read_dir(&temp).unwrap().collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    let work_files: Vec<_> = std::fs::read_dir(&work)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(work_files.len(), 2, "{work_files:?}");

    let missing = vault
        .download_attachment(&id, "no-such-attachment", work.join("x"))
        .await
        .unwrap_err();
    assert!(matches!(missing, Error::Api(_)), "{missing:?}");
    assert!(!work.join("x").exists());

    vault.delete_attachment(&id, &uploaded.id).await.unwrap();
    assert_eq!(vault.attachments(&id).unwrap(), Vec::new());
    let stored = server.cipher(&id.0).await;
    assert!(stored.attachments.as_ref().is_none_or(Vec::is_empty));
    vault.sync().await.unwrap();
    assert_eq!(vault.attachments(&id).unwrap(), Vec::new());
}
