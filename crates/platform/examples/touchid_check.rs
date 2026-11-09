//! Manual Touch ID check against the real Secure Enclave.
//!
//! ```text
//! cargo run -p vk-platform --example touchid_check            # enroll, unlock, compare
//! cargo run -p vk-platform --example touchid_check -- --keep  # same, but keep the file
//! cargo run -p vk-platform --example touchid_check -- --reuse # unlock the kept file only
//! cargo run -p vk-platform --example touchid_check -- --auth  # plain Touch ID check
//! ```
//!
//! `--keep`, then add or remove a fingerprint, then `--reuse` must report "invalidated".

// Printing the outcome is the whole point of this example.
#![allow(clippy::print_stdout)]

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use vk_platform::{Error, biometric};
    use zeroize::Zeroizing;

    tracing_subscriber::fmt()
        .with_env_filter("vk_platform=debug")
        .init();
    let mode = std::env::args().nth(1).unwrap_or_default();
    let path = std::env::temp_dir().join("vaultkeeper-touchid-check.bin");
    println!(
        "Secure Enclave + Touch ID available: {}",
        biometric::is_available()
    );

    if mode == "--auth" {
        let outcome = biometric::authenticate("approve a test SSH signature");
        println!("authenticate: {outcome:?}");
        return Ok(());
    }

    let expected = (mode != "--reuse").then(|| {
        let key = Zeroizing::new(rand::random::<[u8; 64]>());
        biometric::enroll(&path, key.as_slice()).map(|()| key)
    });
    let expected = expected.transpose()?;
    if expected.is_some() {
        println!("enrolled into {}", path.display());
    }

    println!("touch the sensor when prompted...");
    match (
        biometric::unlock(&path, "test vaultkeeper Touch ID unlock"),
        expected,
    ) {
        (Ok(key), Some(expected)) if key.as_slice() == expected.as_slice() => println!("MATCH"),
        (Ok(_), Some(_)) => println!("MISMATCH: unwrapped key differs"),
        (Ok(key), None) => println!("unlocked {} bytes", key.len()),
        (Err(Error::BiometricInvalidated), _) => println!("invalidated: enroll again"),
        (Err(Error::BiometricFailed), _) => println!("failed or cancelled"),
        (Err(err), _) => println!("error: {err}"),
    }

    if mode == "--keep" {
        println!("kept {}; run again with --reuse", path.display());
    } else {
        biometric::unenroll(&path)?;
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("Touch ID is macOS only");
}
