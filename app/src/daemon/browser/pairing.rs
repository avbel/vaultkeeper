//! Persistent public-key pairings and proof verification.

use std::{
    fs,
    io::{self, Read},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use vk_ipc::browser::protocol::KnownBrowser;

use crate::os::fs::write_private;

const DOMAIN: &[u8] = b"vaultkeeper-browser-v1\0";
const MAX_STORE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedBrowser {
    pub public_key: String,
    pub browser: KnownBrowser,
    pub caller: String,
    pub added: u64,
}

/// One paired browser as the Settings window lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingEntry {
    pub public_key: String,
    pub browser: KnownBrowser,
    pub caller: String,
    pub added: u64,
    pub fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PairingStore {
    pub paired: Vec<PairedBrowser>,
    pub never_save_salt: String,
    pub never_save: Vec<String>,
    #[serde(skip)]
    path: PathBuf,
}

impl PairingStore {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let mut store: Self = match fs::File::open(path) {
            Ok(file) => {
                let mut data = Vec::new();
                file.take(MAX_STORE_BYTES + 1)
                    .read_to_end(&mut data)
                    .context("read browser pairings")?;
                ensure!(
                    data.len() as u64 <= MAX_STORE_BYTES,
                    "browser pairing store too large"
                );
                serde_json::from_slice(&data).context("decode browser pairings")?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Self {
                paired: Vec::new(),
                never_save_salt: STANDARD.encode(rand::random::<[u8; 16]>()),
                never_save: Vec::new(),
                path: PathBuf::new(),
            },
            Err(error) => return Err(error).context("read browser pairings"),
        };
        ensure!(
            STANDARD
                .decode(&store.never_save_salt)
                .is_ok_and(|salt| salt.len() == 16),
            "invalid browser never-save salt"
        );
        path.clone_into(&mut store.path);
        Ok(store)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let data = serde_json::to_vec(self).context("encode browser pairings")?;
        ensure!(
            data.len() as u64 <= MAX_STORE_BYTES,
            "browser pairing store too large"
        );
        write_private(&self.path, &data).context("write browser pairings")
    }

    /// Re-reads the file under an exclusive lock, applies `change` and writes only when it
    /// returns `true`. The daemon and the UI process both write this file; without the lock and
    /// the re-read one of them would overwrite the other's update.
    fn locked_update(
        path: &Path,
        change: impl FnOnce(&mut Self) -> anyhow::Result<bool>,
    ) -> anyhow::Result<Self> {
        let mut lock_name = path.as_os_str().to_owned();
        lock_name.push(".lock");
        let lock = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(PathBuf::from(lock_name))
            .context("open browser pairing lock")?;
        lock.lock().context("lock browser pairings")?;
        let mut fresh = Self::load(path)?;
        if change(&mut fresh)? {
            fresh.save()?;
        }
        Ok(fresh)
    }

    fn adopt(&mut self, fresh: Self) {
        self.paired = fresh.paired;
        self.never_save_salt = fresh.never_save_salt;
        self.never_save = fresh.never_save;
    }

    /// Persist approval before publishing it in memory; a failed write never approves a key.
    pub fn approve(
        &mut self,
        key: &[u8; 65],
        browser: KnownBrowser,
        caller: &str,
        added: u64,
    ) -> anyhow::Result<()> {
        let fresh = Self::locked_update(&self.path, |fresh| {
            if fresh.contains(key, caller) {
                return Ok(false);
            }
            fresh.paired.push(PairedBrowser {
                public_key: STANDARD.encode(key),
                browser,
                caller: caller.to_owned(),
                added,
            });
            Ok(true)
        })?;
        self.adopt(fresh);
        Ok(())
    }

    /// Drops the pairing with `public_key` (base64) from the file at `path`; `true` when one was
    /// removed. For the UI process, which does not hold a store of its own.
    pub fn remove_key(path: &Path, public_key: &str) -> anyhow::Result<bool> {
        if !path.exists() {
            return Ok(false);
        }
        let mut removed = false;
        Self::locked_update(path, |fresh| {
            let before = fresh.paired.len();
            fresh.paired.retain(|entry| entry.public_key != public_key);
            removed = fresh.paired.len() != before;
            Ok(removed)
        })?;
        Ok(removed)
    }

    /// Re-reads the file, so keys the UI process removed stop being trusted here.
    pub fn reload(&mut self) -> io::Result<()> {
        let fresh = Self::load(&self.path).map_err(io::Error::other)?;
        self.adopt(fresh);
        Ok(())
    }

    /// Entries for display; a key that does not decode to 65 bytes has no fingerprint and is left
    /// out (it can never authenticate either).
    #[must_use]
    pub fn entries(&self) -> Vec<PairingEntry> {
        self.paired
            .iter()
            .filter_map(|entry| {
                let key: [u8; 65] = STANDARD.decode(&entry.public_key).ok()?.try_into().ok()?;
                Some(PairingEntry {
                    public_key: entry.public_key.clone(),
                    browser: entry.browser,
                    caller: entry.caller.clone(),
                    added: entry.added,
                    fingerprint: fingerprint(&key),
                })
            })
            .collect()
    }

    fn domain_hash(&self, domain: &str) -> anyhow::Result<String> {
        use std::fmt::Write as _;
        let salt = STANDARD
            .decode(&self.never_save_salt)
            .context("decode never-save salt")?;
        ensure!(salt.len() == 16, "invalid browser never-save salt");
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(domain.as_bytes());
        let mut hash = String::with_capacity(64);
        for byte in hasher.finalize() {
            write!(hash, "{byte:02x}").expect("writing to a string cannot fail");
        }
        Ok(hash)
    }

    pub fn is_never_save(&self, domain: &str) -> anyhow::Result<bool> {
        Ok(self.never_save.contains(&self.domain_hash(domain)?))
    }

    pub fn never_save(&mut self, domain: &str) -> anyhow::Result<()> {
        let fresh = Self::locked_update(&self.path, |fresh| {
            let hash = fresh.domain_hash(domain)?;
            if fresh.never_save.contains(&hash) {
                return Ok(false);
            }
            fresh.never_save.push(hash);
            Ok(true)
        })?;
        self.adopt(fresh);
        Ok(())
    }

    #[must_use]
    pub fn contains(&self, public_key: &[u8; 65], caller: &str) -> bool {
        let encoded = STANDARD.encode(public_key);
        self.paired
            .iter()
            .any(|entry| entry.public_key == encoded && entry.caller == caller)
    }
}

pub fn public_key(encoded: &str) -> anyhow::Result<[u8; 65]> {
    let decoded = STANDARD.decode(encoded).context("decode public key")?;
    let bytes: [u8; 65] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public key length"))?;
    ensure!(bytes[0] == 4, "public key must be uncompressed");
    VerifyingKey::from_sec1_bytes(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid P-256 public key"))?;
    Ok(bytes)
}

#[must_use]
pub fn fingerprint(public_key: &[u8; 65]) -> String {
    let hash = Sha256::digest(public_key);
    format!(
        "{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]
    )
}

#[must_use]
pub fn verify(public_key: &[u8; 65], challenge: &[u8; 32], caller: &str, signature: &str) -> bool {
    let Ok(key) = VerifyingKey::from_sec1_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = STANDARD.decode(signature) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature) else {
        return false;
    };
    let mut message = Vec::with_capacity(DOMAIN.len() + challenge.len() + caller.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(challenge);
    message.extend_from_slice(caller.as_bytes());
    key.verify(&message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer as _};

    #[test]
    fn verifies_raw_signature_and_binds_challenge_and_caller() {
        let signing = SigningKey::from_bytes((&[7_u8; 32]).into()).expect("key");
        let encoded = signing.verifying_key().to_sec1_point(false);
        let key = public_key(&STANDARD.encode(encoded.as_bytes())).expect("public key");
        let challenge = [42_u8; 32];
        let caller = "browser-extension@vaultkeeper";
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&challenge);
        message.extend_from_slice(caller.as_bytes());
        let signature: Signature = signing.sign(&message);
        let encoded = STANDARD.encode(signature.to_bytes());
        assert!(verify(&key, &challenge, caller, &encoded));
        assert!(!verify(&key, &[43; 32], caller, &encoded));
        assert!(!verify(&key, &challenge, "other", &encoded));
        assert!(!verify(&key, &challenge, caller, "bad"));
        assert!(public_key(&STANDARD.encode([4; 65])).is_err());
        assert_eq!(fingerprint(&key).len(), 19);
    }

    #[test]
    fn oversized_store_fails_closed() {
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("browsers.json");
        std::fs::write(
            &path,
            vec![b' '; usize::try_from(MAX_STORE_BYTES).expect("store limit") + 1],
        )
        .expect("write");
        assert!(PairingStore::load(&path).is_err());
    }

    #[test]
    fn failed_persistence_does_not_grant_pairing_or_never_save() {
        let dir = tempfile::tempdir().expect("directory");
        let mut store = PairingStore::load(&dir.path().join("missing").join("browsers.json"))
            .expect("new store");
        let key = [4; 65];
        assert!(
            store
                .approve(&key, KnownBrowser::Firefox, "extension", 1)
                .is_err()
        );
        assert!(!store.contains(&key, "extension"));
        assert!(store.never_save("example.com").is_err());
        assert!(!store.is_never_save("example.com").expect("lookup"));
    }

    #[test]
    fn store_round_trips_and_rejects_corruption() {
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("browsers.json");
        let mut store = PairingStore::load(&path).expect("new store");
        let key = [4; 65];
        store.paired.push(PairedBrowser {
            public_key: STANDARD.encode(key),
            browser: KnownBrowser::Firefox,
            caller: "extension".into(),
            added: 1,
        });
        store.save().expect("save");
        store.never_save("example.com").expect("never save");
        let loaded = PairingStore::load(&path).expect("load");
        assert!(loaded.is_never_save("example.com").expect("lookup"));
        assert!(!loaded.is_never_save("other.example").expect("lookup"));
        assert!(loaded.contains(&key, "extension"));
        assert!(!loaded.contains(&key, "other"));
        fs::write(&path, b"corrupt").expect("corrupt");
        assert!(PairingStore::load(&path).is_err());
    }

    #[test]
    fn ui_removal_and_daemon_approval_do_not_lose_each_others_updates() {
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("browsers.json");
        let mut daemon = PairingStore::load(&path).expect("daemon store");
        let (first, second) = ([4; 65], [5; 65]);
        daemon
            .approve(&first, KnownBrowser::Firefox, "extension", 1)
            .expect("approve first");
        assert!(PairingStore::remove_key(&path, &STANDARD.encode(first)).expect("remove"));
        assert!(
            daemon.contains(&first, "extension"),
            "memory is stale until reload"
        );
        daemon
            .approve(&second, KnownBrowser::Firefox, "extension", 2)
            .expect("approve second");
        assert!(!daemon.contains(&first, "extension"));
        assert!(daemon.contains(&second, "extension"));
        let on_disk = PairingStore::load(&path).expect("reload");
        assert!(!on_disk.contains(&first, "extension"));
        assert!(on_disk.contains(&second, "extension"));
    }

    #[test]
    fn reload_picks_up_a_removal_and_remove_key_reports_what_it_did() {
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("browsers.json");
        assert!(!PairingStore::remove_key(&path, "missing").expect("no file"));
        let mut daemon = PairingStore::load(&path).expect("daemon store");
        let key = [4; 65];
        daemon
            .approve(&key, KnownBrowser::Chrome, "extension", 1)
            .expect("approve");
        assert!(!PairingStore::remove_key(&path, "unknown").expect("unknown key"));
        assert!(PairingStore::remove_key(&path, &STANDARD.encode(key)).expect("remove"));
        daemon.reload().expect("reload");
        assert!(!daemon.contains(&key, "extension"));
        assert_eq!(daemon.entries().len(), 0);
    }

    #[test]
    fn a_ui_removal_is_not_undone_by_a_later_never_save() {
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("browsers.json");
        let mut daemon = PairingStore::load(&path).expect("daemon store");
        let key = [4; 65];
        daemon
            .approve(&key, KnownBrowser::Firefox, "extension", 1)
            .expect("approve");
        PairingStore::remove_key(&path, &STANDARD.encode(key)).expect("remove");
        daemon.never_save("example.com").expect("never save");
        let on_disk = PairingStore::load(&path).expect("load");
        assert!(on_disk.paired.is_empty());
        assert!(on_disk.is_never_save("example.com").expect("lookup"));
    }

    #[test]
    fn entries_carry_the_fingerprint_and_skip_undecodable_keys() {
        let dir = tempfile::tempdir().expect("directory");
        let mut store = PairingStore::load(&dir.path().join("browsers.json")).expect("store");
        let key = [4; 65];
        store.paired.push(PairedBrowser {
            public_key: "not base64!".into(),
            browser: KnownBrowser::Chrome,
            caller: "a".into(),
            added: 1,
        });
        store.paired.push(PairedBrowser {
            public_key: STANDARD.encode(key),
            browser: KnownBrowser::Firefox,
            caller: "b".into(),
            added: 2,
        });
        let entries = store.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fingerprint, fingerprint(&key));
        assert_eq!(entries[0].public_key, STANDARD.encode(key));
        assert_eq!(entries[0].browser, KnownBrowser::Firefox);
    }
}
