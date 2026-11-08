//! Attachments: v2 upload with a fresh 64-byte file key wrapped by the cipher key; downloads go
//! to a temp file in the account directory, are MAC-verified, then decrypted to the destination.
//! Neither direction holds the file in memory.

use std::{
    fs::{self, File},
    io::{self, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use bwl_api::models::Attachment;
use bwl_crypto::{EncString, SymmetricKey, enc_buffer};

use super::Inner;
use crate::{
    Error, Result,
    keys::{copy_key, decrypt_text, encrypt_text, parse},
    model::{AttachmentView, ItemId},
    store::create_private_file,
    util::TempFile,
};

impl Inner {
    pub(crate) fn attachment_views(&self, id: &ItemId) -> Result<Vec<AttachmentView>> {
        self.read_unlocked(|_, unlocked| {
            let entry = unlocked.data.entry(&id.0).ok_or(Error::NotFound)?;
            let key = unlocked.keys.cipher_key(&entry.cipher)?;
            entry
                .cipher
                .attachments
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|attachment| {
                    let name = decrypt_text(attachment.file_name.as_deref(), &key)?;
                    Ok(AttachmentView {
                        id: Arc::from(attachment.id.as_str()),
                        file_name: Arc::from(name.as_str()),
                        size_bytes: attachment
                            .size
                            .as_deref()
                            .and_then(|size| size.parse().ok())
                            .unwrap_or_default(),
                    })
                })
                .collect()
        })
    }

    /// An owned copy, so the key outlives the state lock across the transfer's awaits.
    fn cipher_key_copy(&self, id: &str, for_write: bool) -> Result<SymmetricKey> {
        self.read_unlocked(|_, unlocked| {
            let entry = unlocked.data.entry(id).ok_or(Error::NotFound)?;
            if for_write && !entry.cipher.edit {
                return Err(Error::ReadOnly);
            }
            copy_key(&*unlocked.keys.cipher_key(&entry.cipher)?)
        })
    }

    pub(crate) async fn upload_attachment(
        self: &Arc<Self>,
        id: &ItemId,
        source: PathBuf,
    ) -> Result<AttachmentView> {
        let ctx = self.writable_ctx()?;
        let cipher_key = self.cipher_key_copy(&id.0, true)?;
        let file_name = source
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the attachment has no file name",
                )
            })?;
        let file_key = SymmetricKey::generate();
        let enc_key = EncString::encrypt(&file_key.to_bytes(), &cipher_key)?.to_string();
        let enc_name = encrypt_text(&file_name, &cipher_key)?;
        drop(cipher_key);

        let temp = TempFile::new_in(&self.store.temp_dir(&ctx.account_id)?);
        let encrypted_path = temp.path().to_owned();
        let size = self
            .config
            .runtime
            .spawn_blocking(move || encrypt_file(&file_key, &source, &encrypted_path))
            .await
            .map_err(Error::task)??;

        let serial = self.sync_lock.lock().await;
        let (enc_name_ref, enc_key_ref) = (enc_name.as_str(), enc_key.as_str());
        let upload = self
            .call(&ctx, |client, token| async move {
                client
                    .create_attachment(&token, &id.0, enc_name_ref, enc_key_ref, size)
                    .await
            })
            .await?;
        let attachment_id = upload.attachment_id.as_str();
        let encrypted = temp.path();
        let sent = self
            .call(&ctx, |client, token| async move {
                let file = tokio::fs::File::open(encrypted).await?;
                client
                    .upload_attachment_data(
                        &token,
                        &id.0,
                        attachment_id,
                        reqwest::Body::from(file),
                        size,
                    )
                    .await
            })
            .await;
        if let Err(error) = sent {
            // Without its data the attachment record is useless; remove it if the server lets us.
            let cleanup = self
                .call(&ctx, |client, token| async move {
                    client.delete_attachment(&token, &id.0, attachment_id).await
                })
                .await;
            if let Err(cleanup) = cleanup {
                tracing::warn!(%cleanup, "could not remove a half-uploaded attachment");
            }
            return Err(error);
        }
        drop(temp);

        let attachment = Attachment {
            id: upload.attachment_id.clone(),
            url: None,
            file_name: Some(enc_name),
            key: Some(enc_key),
            size: Some(size.to_string()),
            size_name: None,
        };
        self.apply(&ctx, |data, keys| {
            if let Some(entry) = data.entry(&id.0) {
                let mut cipher = entry.cipher.clone();
                cipher.attachments.get_or_insert_default().push(attachment);
                data.upsert_cipher(cipher, keys);
            }
        });
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished.map(|()| AttachmentView {
            id: Arc::from(upload.attachment_id.as_str()),
            file_name: Arc::from(file_name.as_str()),
            size_bytes: size,
        })
    }

    pub(crate) async fn download_attachment(
        self: &Arc<Self>,
        id: &ItemId,
        attachment_id: &str,
        dest: PathBuf,
    ) -> Result<()> {
        let ctx = self.unlocked_ctx()?;
        let cipher_key = self.cipher_key_copy(&id.0, false)?;
        let info = self
            .call(&ctx, |client, token| async move {
                client.attachment_info(&token, &id.0, attachment_id).await
            })
            .await?;
        let file_key = match info.key.as_deref() {
            Some(wrapped) if !wrapped.is_empty() => {
                SymmetricKey::from_bytes(&parse(wrapped)?.decrypt(&cipher_key)?)?
            }
            // Old attachments without their own key are encrypted with the cipher key.
            _ => copy_key(&cipher_key)?,
        };
        drop(cipher_key);
        let url = info.url.as_deref().ok_or(Error::protocol(
            "the server sent no attachment download URL",
        ))?;

        let temp = TempFile::new_in(&self.store.temp_dir(&ctx.account_id)?);
        {
            let mut file = tokio::fs::File::from_std(create_private_file(temp.path())?);
            let downloaded = ctx.client.download_attachment(url, &mut file).await;
            if let Err(error) = &downloaded
                && error.is_offline()
            {
                self.went_offline(&ctx);
            }
            downloaded?;
        }
        let encrypted = temp.path().to_owned();
        self.config
            .runtime
            .spawn_blocking(move || decrypt_file(&file_key, &encrypted, &dest))
            .await
            .map_err(Error::task)??;
        drop(temp);
        Ok(())
    }

    pub(crate) async fn delete_attachment(
        self: &Arc<Self>,
        id: &ItemId,
        attachment_id: &str,
    ) -> Result<()> {
        let ctx = self.writable_ctx()?;
        self.cipher_key_copy(&id.0, true)?;
        let serial = self.sync_lock.lock().await;
        self.call(&ctx, |client, token| async move {
            client.delete_attachment(&token, &id.0, attachment_id).await
        })
        .await?;
        self.apply(&ctx, |data, keys| {
            if let Some(entry) = data.entry(&id.0) {
                let mut cipher = entry.cipher.clone();
                if let Some(list) = &mut cipher.attachments {
                    list.retain(|attachment| attachment.id != attachment_id);
                }
                data.upsert_cipher(cipher, keys);
            }
        });
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished
    }
}

fn encrypt_file(key: &SymmetricKey, source: &Path, encrypted: &Path) -> Result<u64> {
    let reader = BufReader::new(File::open(source)?);
    let mut writer = BufWriter::new(create_private_file(encrypted)?);
    let size = enc_buffer::encrypt_stream(key, reader, &mut writer)?;
    writer.flush()?;
    Ok(size)
}

/// Verifies the whole file before writing any plaintext, then decrypts into a hidden sibling of
/// `dest` that is renamed into place only when complete.
fn decrypt_file(key: &SymmetricKey, encrypted: &Path, dest: &Path) -> Result<()> {
    enc_buffer::verify_stream(key, BufReader::new(File::open(encrypted)?))?;
    let dir = dest.parent().unwrap_or_else(|| Path::new(""));
    let partial = TempFile::new_in(dir);
    let mut writer = BufWriter::new(create_private_file(partial.path())?);
    enc_buffer::decrypt_stream(key, BufReader::new(File::open(encrypted)?), &mut writer)?;
    writer.flush()?;
    drop(writer);
    fs::rename(partial.path(), dest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::temp_root;

    #[test]
    fn file_round_trip_through_the_attachment_format() {
        let dir = temp_root();
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.bin");
        let plain: Vec<u8> = (0..200_000u32)
            .map(|i| (i.wrapping_mul(31) % 251) as u8)
            .collect();
        fs::write(&source, &plain).unwrap();
        let key = SymmetricKey::generate();

        let encrypted = dir.join("encrypted.bin");
        let size = encrypt_file(&key, &source, &encrypted).unwrap();
        assert_eq!(size, fs::metadata(&encrypted).unwrap().len());
        // type byte + IV + MAC, then the PKCS#7-padded ciphertext.
        assert_eq!(size, 1 + 16 + 32 + (plain.len() as u64 / 16 + 1) * 16);

        let dest = dir.join("dest.bin");
        decrypt_file(&key, &encrypted, &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), plain);

        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names
                .iter()
                .all(|name| !name.to_ascii_lowercase().ends_with(".part")),
            "{names:?}"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_tampered_file_leaves_no_plaintext_behind() {
        let dir = temp_root();
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.bin");
        fs::write(&source, vec![7u8; 70_000]).unwrap();
        let key = SymmetricKey::generate();
        let encrypted = dir.join("encrypted.bin");
        encrypt_file(&key, &source, &encrypted).unwrap();
        let mut bytes = fs::read(&encrypted).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&encrypted, bytes).unwrap();

        let dest = dir.join("dest.bin");
        let error = decrypt_file(&key, &encrypted, &dest).unwrap_err();
        assert!(
            matches!(error, Error::Crypto(bwl_crypto::Error::MacMismatch)),
            "{error:?}"
        );
        assert!(!dest.exists());

        let wrong = decrypt_file(&SymmetricKey::generate(), &encrypted, &dest).unwrap_err();
        assert!(matches!(
            wrong,
            Error::Crypto(bwl_crypto::Error::MacMismatch)
        ));
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
        fs::remove_dir_all(dir).unwrap();
    }
}
