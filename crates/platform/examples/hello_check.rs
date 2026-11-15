//! Manual Windows Hello check against the real Passport key storage provider (spike 4a).
//!
//! ```text
//! cargo run -p vk-platform --example hello_check              # open or create the key, wrap, unwrap
//! cargo run -p vk-platform --example hello_check -- --strict  # same, after harden_process(Daemon)
//! cargo run -p vk-platform --example hello_check -- --delete  # delete the key and exit
//! ```
//!
//! Creating the key may prompt once; the decrypt must show one Hello prompt (face, fingerprint or
//! PIN). Paste the whole output back, including every hex status.

// A manual check that reports on the console; printing is its whole job.
#![allow(clippy::print_stdout, clippy::print_stderr)]
// HRESULTs are i32 on the API and shown as u32; every buffer here is a few hundred bytes.
#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    imp::run()
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::process::ExitCode;
    use std::ptr::{null, null_mut};
    use std::time::Instant;

    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_RSAKEY_BLOB, BCRYPT_RSAPUBLIC_BLOB,
        BCRYPT_SHA256_ALGORITHM, MS_NGC_KEY_STORAGE_PROVIDER, NCRYPT_ALLOW_DECRYPT_FLAG,
        NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG, NCRYPT_PAD_PKCS1_FLAG,
        NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY, NCRYPT_PROV_HANDLE,
        NCRYPT_USE_CONTEXT_PROPERTY, NCRYPT_WINDOW_HANDLE_PROPERTY, NCryptCreatePersistedKey,
        NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptExportKey, NCryptFinalizeKey,
        NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
    };
    use windows_sys::Win32::System::Console::GetConsoleWindow;
    use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
    use zeroize::Zeroizing;

    const NTE_BAD_KEYSET: i32 = 0x8009_0016_u32 as i32;
    const NTE_NO_KEY: i32 = 0x8009_000D_u32 as i32;
    // Hello dialog was not in the foreground; the second attempt usually succeeds.
    const NTE_FOREGROUND: i32 = 0x8009_8044_u32 as i32;
    const KEY_BITS: u32 = 2048;
    const PROMPT: &str = "Vaultkeeper Hello spike: approve the test unlock";

    /// Owns an NCrypt provider or key handle and frees it on drop.
    struct Handle(usize);

    impl Handle {
        fn raw(&self) -> usize {
            self.0
        }

        /// For calls that consume the handle themselves (NCryptDeleteKey).
        fn release(self) -> usize {
            let raw = self.0;
            std::mem::forget(self);
            raw
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: the handle came from an NCrypt call, is owned by this wrapper only and
                // is freed exactly once.
                let status = unsafe { NCryptFreeObject(self.0 as NCRYPT_HANDLE) };
                if status != 0 {
                    eprintln!("NCryptFreeObject failed: {}", hex(status));
                }
            }
        }
    }

    fn hex(status: i32) -> String {
        format!("{:#010x}", status as u32)
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    fn report(step: &str, status: i32) -> Result<(), i32> {
        println!("{step}: {}", hex(status));
        if status == 0 { Ok(()) } else { Err(status) }
    }

    fn set_property(handle: usize, name: windows_sys::core::PCWSTR, value: &[u8]) -> i32 {
        // SAFETY: `name` is a static NUL-terminated string and `value` is a live slice whose
        // length is passed alongside it; the handle is valid for the caller's lifetime.
        unsafe {
            NCryptSetProperty(
                handle as NCRYPT_HANDLE,
                name,
                value.as_ptr(),
                value.len() as u32,
                0,
            )
        }
    }

    fn key_name() -> Result<String, String> {
        let sid = vk_win::current_user_sid().map_err(|e| format!("current_user_sid: {e}"))?;
        Ok(format!("{sid}//Vaultkeeper//Vaultkeeper"))
    }

    fn open_provider() -> Result<Handle, i32> {
        let mut provider: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: the out-param points at a live local and the provider name is a static string.
        let status =
            unsafe { NCryptOpenStorageProvider(&raw mut provider, MS_NGC_KEY_STORAGE_PROVIDER, 0) };
        println!("NCryptOpenStorageProvider(Passport KSP): {}", hex(status));
        if status != 0 {
            return Err(status);
        }
        Ok(Handle(provider))
    }

    fn open_key(provider: &Handle, name: &[u16]) -> Result<Handle, i32> {
        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: the provider handle is open, `name` is NUL-terminated and the out-param points
        // at a live local.
        let status = unsafe { NCryptOpenKey(provider.raw(), &raw mut key, name.as_ptr(), 0, 0) };
        println!("NCryptOpenKey: {}", hex(status));
        if status != 0 {
            return Err(status);
        }
        Ok(Handle(key))
    }

    fn set_window(handle: usize, label: &str) {
        // SAFETY: both calls take no arguments and only read thread state.
        let (console, foreground) = unsafe { (GetConsoleWindow(), GetForegroundWindow()) };
        let (hwnd, source) = if console.is_null() {
            (foreground, "GetForegroundWindow")
        } else {
            (console, "GetConsoleWindow")
        };
        println!("{label}: owner window {hwnd:p} from {source}");
        if hwnd.is_null() {
            println!("{label}: no window available, skipping NCRYPT_WINDOW_HANDLE_PROPERTY");
            return;
        }
        let bytes = (hwnd as usize).to_ne_bytes();
        let status = set_property(handle, NCRYPT_WINDOW_HANDLE_PROPERTY, &bytes);
        println!(
            "{label}: set NCRYPT_WINDOW_HANDLE_PROPERTY: {}",
            hex(status)
        );
    }

    fn create_key(provider: &Handle, name: &[u16]) -> Result<Handle, i32> {
        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: the provider handle is open, the algorithm and `name` are NUL-terminated and
        // the out-param points at a live local.
        let status = unsafe {
            NCryptCreatePersistedKey(
                provider.raw(),
                &raw mut key,
                BCRYPT_RSA_ALGORITHM,
                name.as_ptr(),
                0,
                0,
            )
        };
        report("NCryptCreatePersistedKey", status)?;
        let key = Handle(key);
        let status = set_property(key.raw(), NCRYPT_LENGTH_PROPERTY, &KEY_BITS.to_ne_bytes());
        println!("set NCRYPT_LENGTH_PROPERTY=2048: {}", hex(status));
        let status = set_property(
            key.raw(),
            NCRYPT_KEY_USAGE_PROPERTY,
            &NCRYPT_ALLOW_DECRYPT_FLAG.to_ne_bytes(),
        );
        println!("set NCRYPT_KEY_USAGE_PROPERTY=decrypt: {}", hex(status));
        set_window(key.raw(), "create");
        println!("finalizing the key (may prompt once)");
        // SAFETY: the key handle is valid and not yet finalized.
        let status = unsafe { NCryptFinalizeKey(key.raw() as NCRYPT_KEY_HANDLE, 0) };
        report("NCryptFinalizeKey", status)?;
        Ok(key)
    }

    fn open_or_create(provider: &Handle, name: &[u16]) -> Result<(Handle, bool), i32> {
        match open_key(provider, name) {
            Ok(key) => Ok((key, false)),
            Err(NTE_BAD_KEYSET | NTE_NO_KEY) => {
                println!("key not found, creating it");
                create_key(provider, name).map(|key| (key, true))
            }
            Err(status) => Err(status),
        }
    }

    fn export_public(key: &Handle) -> Result<Vec<u8>, i32> {
        let mut len = 0_u32;
        // SAFETY: a null output buffer with size 0 asks for the required length only.
        let status = unsafe {
            NCryptExportKey(
                key.raw(),
                0,
                BCRYPT_RSAPUBLIC_BLOB,
                null(),
                null_mut(),
                0,
                &raw mut len,
                0,
            )
        };
        report("NCryptExportKey(size)", status)?;
        let mut blob = vec![0_u8; len as usize];
        // SAFETY: `blob` is `len` bytes long and the out-param points at a live local.
        let status = unsafe {
            NCryptExportKey(
                key.raw(),
                0,
                BCRYPT_RSAPUBLIC_BLOB,
                null(),
                blob.as_mut_ptr(),
                len,
                &raw mut len,
                0,
            )
        };
        report("NCryptExportKey(RSAPUBLICBLOB)", status)?;
        blob.truncate(len as usize);
        Ok(blob)
    }

    fn describe_blob(blob: &[u8]) {
        let header = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>();
        if blob.len() < header {
            println!("public blob: {} bytes, too short for a header", blob.len());
            return;
        }
        let word = |i: usize| {
            u32::from_le_bytes([
                blob[i * 4],
                blob[i * 4 + 1],
                blob[i * 4 + 2],
                blob[i * 4 + 3],
            ])
        };
        println!(
            "public blob: {} bytes, magic {:#010x}, {} bits, exponent {} bytes, modulus {} bytes",
            blob.len(),
            word(0),
            word(1),
            word(2),
            word(3),
        );
    }

    #[derive(Clone, Copy)]
    enum Padding {
        OaepSha256,
        Pkcs1,
    }

    impl Padding {
        fn name(self) -> &'static str {
            match self {
                Self::OaepSha256 => "RSA-OAEP-SHA256",
                Self::Pkcs1 => "PKCS#1 v1.5",
            }
        }

        fn flags(self) -> NCRYPT_FLAGS {
            match self {
                Self::OaepSha256 => NCRYPT_PAD_OAEP_FLAG,
                Self::Pkcs1 => NCRYPT_PAD_PKCS1_FLAG,
            }
        }
    }

    /// Runs `op` with the padding info a padding scheme needs, as the pointer NCrypt expects.
    fn with_padding<T>(padding: Padding, op: impl FnOnce(*const c_void) -> T) -> T {
        match padding {
            Padding::OaepSha256 => {
                let info = BCRYPT_OAEP_PADDING_INFO {
                    pszAlgId: BCRYPT_SHA256_ALGORITHM,
                    pbLabel: null_mut(),
                    cbLabel: 0,
                };
                op((&raw const info).cast())
            }
            Padding::Pkcs1 => op(null()),
        }
    }

    fn encrypt(key: &Handle, padding: Padding, plain: &[u8]) -> Result<Vec<u8>, i32> {
        let call = |out: *mut u8, out_len: u32, written: &mut u32| {
            with_padding(padding, |info| {
                // SAFETY: `plain` is a live slice, `out` is null or `out_len` bytes long, and the
                // padding info outlives the call inside `with_padding`.
                unsafe {
                    NCryptEncrypt(
                        key.raw(),
                        plain.as_ptr(),
                        plain.len() as u32,
                        info,
                        out,
                        out_len,
                        written,
                        padding.flags(),
                    )
                }
            })
        };
        let mut len = 0_u32;
        let status = call(null_mut(), 0, &mut len);
        if status != 0 {
            return Err(status);
        }
        let mut out = vec![0_u8; len as usize];
        let status = call(out.as_mut_ptr(), len, &mut len);
        if status != 0 {
            return Err(status);
        }
        out.truncate(len as usize);
        Ok(out)
    }

    fn prepare_decrypt(key: &Handle) {
        set_window(key.raw(), "decrypt");
        let context: Vec<u8> = wide(PROMPT)
            .into_iter()
            .flat_map(u16::to_ne_bytes)
            .collect();
        let status = set_property(key.raw(), NCRYPT_USE_CONTEXT_PROPERTY, &context);
        println!("set NCRYPT_USE_CONTEXT_PROPERTY: {}", hex(status));
        let status = set_property(
            key.raw(),
            NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY,
            &1_u32.to_ne_bytes(),
        );
        println!(
            "set NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY=1: {}",
            hex(status)
        );
    }

    fn decrypt_once(
        key: &Handle,
        padding: Padding,
        cipher: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, i32> {
        let mut out = Zeroizing::new(vec![0_u8; cipher.len()]);
        let mut written = 0_u32;
        let status = with_padding(padding, |info| {
            // SAFETY: `cipher` is a live slice, `out` is as long as the length passed, and the
            // padding info outlives the call inside `with_padding`.
            unsafe {
                NCryptDecrypt(
                    key.raw(),
                    cipher.as_ptr(),
                    cipher.len() as u32,
                    info,
                    out.as_mut_ptr(),
                    out.len() as u32,
                    &raw mut written,
                    padding.flags(),
                )
            }
        });
        if status != 0 {
            return Err(status);
        }
        out.truncate(written as usize);
        Ok(out)
    }

    fn decrypt(key: &Handle, padding: Padding, cipher: &[u8]) -> Result<Zeroizing<Vec<u8>>, i32> {
        prepare_decrypt(key);
        println!("decrypting: expect one Hello prompt now");
        for attempt in 1..=2 {
            let started = Instant::now();
            let result = decrypt_once(key, padding, cipher);
            let status = result.as_ref().err().copied().unwrap_or(0);
            println!(
                "NCryptDecrypt attempt {attempt}: {} after {:.2?}",
                hex(status),
                started.elapsed()
            );
            match result {
                Err(NTE_FOREGROUND) if attempt == 1 => {
                    println!("0x80098044: retrying once");
                }
                other => return other,
            }
        }
        Err(NTE_FOREGROUND)
    }

    fn roundtrip(key: &Handle) -> Result<(), i32> {
        let blob = export_public(key)?;
        describe_blob(&blob);

        let secret = Zeroizing::new(rand::random::<[u8; 32]>());
        let (padding, cipher) = match encrypt(key, Padding::OaepSha256, secret.as_slice()) {
            Ok(cipher) => (Padding::OaepSha256, cipher),
            Err(status) => {
                println!(
                    "encrypt with {}: {}",
                    Padding::OaepSha256.name(),
                    hex(status)
                );
                let cipher = encrypt(key, Padding::Pkcs1, secret.as_slice()).inspect_err(|s| {
                    println!("encrypt with {}: {}", Padding::Pkcs1.name(), hex(*s));
                })?;
                (Padding::Pkcs1, cipher)
            }
        };
        println!(
            "encrypt worked with {}: {} byte ciphertext",
            padding.name(),
            cipher.len()
        );

        let plain = decrypt(key, padding, &cipher)?;
        if plain.as_slice() == secret.as_slice() {
            println!("plaintext matches the original 32 bytes");
            Ok(())
        } else {
            println!("MISMATCH: decrypted {} bytes that differ", plain.len());
            Err(-1)
        }
    }

    fn delete_key(provider: &Handle, name: &[u16]) -> Result<(), i32> {
        let key = open_key(provider, name)?;
        // SAFETY: the key handle is valid; on success NCryptDeleteKey frees it, so ownership is
        // given up first and the wrapper never frees it again.
        let status = unsafe { NCryptDeleteKey(key.release() as NCRYPT_KEY_HANDLE, 0) };
        report("NCryptDeleteKey", status)
    }

    pub fn run() -> ExitCode {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let strict = args.iter().any(|a| a == "--strict");
        let delete = args.iter().any(|a| a == "--delete");

        if strict {
            vk_platform::hardening::harden_process(vk_platform::hardening::Role::Daemon);
            println!("harden_process(Daemon) applied");
        }

        let name = match key_name() {
            Ok(name) => name,
            Err(message) => {
                eprintln!("{message}");
                return ExitCode::FAILURE;
            }
        };
        println!("key name: {name}");
        let wide_name = wide(&name);

        let Ok(provider) = open_provider() else {
            return ExitCode::FAILURE;
        };

        if delete {
            return outcome(delete_key(&provider, &wide_name));
        }

        let result = open_or_create(&provider, &wide_name).and_then(|(key, created)| {
            println!(
                "key {}",
                if created {
                    "CREATED"
                } else {
                    "already existed"
                }
            );
            roundtrip(&key)
        });
        outcome(result)
    }

    fn outcome(result: Result<(), i32>) -> ExitCode {
        match result {
            Ok(()) => {
                println!("RESULT: ok");
                ExitCode::SUCCESS
            }
            Err(status) => {
                println!("RESULT: failed, last status {}", hex(status));
                ExitCode::FAILURE
            }
        }
    }
}
