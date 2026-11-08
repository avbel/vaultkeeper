use std::num::NonZeroU32;

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

const KDF_TYPE_PBKDF2: u8 = 0;
const KDF_TYPE_ARGON2ID: u8 = 1;

// Minimums stop a hostile server from downgrading the KDF; maximums stop it from making unlock
// hang or exhaust memory. The maximums are Bitwarden server's `KdfConstants` ranges.
const PBKDF2_ITERATIONS: Limits = Limits {
    min: 5_000,
    max: 2_000_000,
    below: "PBKDF2 needs at least 5000 iterations",
    above: "PBKDF2 allows at most 2000000 iterations",
};
const ARGON2_ITERATIONS: Limits = Limits {
    min: 2,
    max: 10,
    below: "Argon2id needs at least 2 iterations",
    above: "Argon2id allows at most 10 iterations",
};
const ARGON2_MEMORY_MIB: Limits = Limits {
    min: 16,
    max: 1024,
    below: "Argon2id needs at least 16 MiB of memory",
    above: "Argon2id allows at most 1024 MiB of memory",
};
const ARGON2_PARALLELISM: Limits = Limits {
    min: 1,
    max: 16,
    below: "Argon2id needs a parallelism of at least 1",
    above: "Argon2id allows a parallelism of at most 16",
};
const KIB_PER_MIB: u32 = 1024;

struct Limits {
    min: u32,
    max: u32,
    below: &'static str,
    above: &'static str,
}

impl Limits {
    fn check(&self, value: NonZeroU32) -> Result<()> {
        if value.get() < self.min {
            Err(Error::KdfTooWeak(self.below))
        } else if value.get() > self.max {
            Err(Error::KdfOutOfRange(self.above))
        } else {
            Ok(())
        }
    }
}

/// KDF settings as returned by prelogin. `KdfType` 0 is PBKDF2-SHA256, 1 is Argon2id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    Pbkdf2 {
        iterations: NonZeroU32,
    },
    Argon2id {
        iterations: NonZeroU32,
        memory_mib: NonZeroU32,
        parallelism: NonZeroU32,
    },
}

impl Kdf {
    /// Builds from the wire representation (`kdf`, `kdfIterations`, `kdfMemory`, `kdfParallelism`).
    ///
    /// Only zero or missing values are rejected here; the limits are enforced by
    /// [`Kdf::validate`] when a key is derived.
    pub fn from_wire(
        kdf_type: u8,
        iterations: u32,
        memory_mib: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<Self> {
        match kdf_type {
            KDF_TYPE_PBKDF2 => Ok(Self::Pbkdf2 {
                iterations: non_zero(Some(iterations), "PBKDF2 iterations are zero")?,
            }),
            KDF_TYPE_ARGON2ID => Ok(Self::Argon2id {
                iterations: non_zero(Some(iterations), "Argon2id iterations are zero")?,
                memory_mib: non_zero(memory_mib, "Argon2id memory is missing or zero")?,
                parallelism: non_zero(parallelism, "Argon2id parallelism is missing or zero")?,
            }),
            other => Err(Error::UnsupportedKdf(other)),
        }
    }

    /// Rejects parameters outside the client limits, so a malicious server can neither downgrade
    /// the KDF ([`Error::KdfTooWeak`]) nor stall or exhaust the client ([`Error::KdfOutOfRange`]):
    /// PBKDF2 5000..=2000000 iterations; Argon2id 2..=10 iterations, 16..=1024 MiB memory,
    /// 1..=16 parallelism.
    pub fn validate(&self) -> Result<()> {
        match *self {
            Self::Pbkdf2 { iterations } => PBKDF2_ITERATIONS.check(iterations),
            Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                ARGON2_ITERATIONS.check(iterations)?;
                ARGON2_MEMORY_MIB.check(memory_mib)?;
                ARGON2_PARALLELISM.check(parallelism)
            }
        }
    }

    /// Validates the parameters, then fills `out` with the derived key.
    pub(crate) fn derive_into(
        &self,
        password: &[u8],
        salt: &[u8],
        out: &mut [u8; 32],
    ) -> Result<()> {
        self.validate()?;
        match *self {
            Self::Pbkdf2 { iterations } => {
                pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations.get(), out);
                Ok(())
            }
            Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                let memory_kib = memory_mib
                    .get()
                    .checked_mul(KIB_PER_MIB)
                    .ok_or(Error::Kdf)?;
                let params = Params::new(
                    memory_kib,
                    iterations.get(),
                    parallelism.get(),
                    Some(out.len()),
                )
                .map_err(|_| Error::Kdf)?;
                // Bitwarden hashes the salt so that short emails still meet Argon2's 8-byte minimum.
                let salt = Sha256::digest(salt);
                Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                    .hash_password_into(password, &salt, out)
                    .map_err(|_| Error::Kdf)
            }
        }
    }
}

fn non_zero(value: Option<u32>, reason: &'static str) -> Result<NonZeroU32> {
    value
        .and_then(NonZeroU32::new)
        .ok_or(Error::KdfTooWeak(reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).expect("test values are non-zero")
    }

    fn argon2(iterations: u32, memory_mib: u32, parallelism: u32) -> Kdf {
        Kdf::Argon2id {
            iterations: nz(iterations),
            memory_mib: nz(memory_mib),
            parallelism: nz(parallelism),
        }
    }

    #[test]
    fn from_wire_builds_pbkdf2() {
        let kdf = Kdf::from_wire(0, 600_000, None, None).expect("valid PBKDF2 settings");
        assert_eq!(
            kdf,
            Kdf::Pbkdf2 {
                iterations: nz(600_000)
            }
        );
    }

    #[test]
    fn from_wire_ignores_argon2_fields_for_pbkdf2() {
        let kdf = Kdf::from_wire(0, 600_000, Some(64), Some(4)).expect("valid PBKDF2 settings");
        assert_eq!(
            kdf,
            Kdf::Pbkdf2 {
                iterations: nz(600_000)
            }
        );
    }

    #[test]
    fn from_wire_builds_argon2id() {
        let kdf = Kdf::from_wire(1, 3, Some(64), Some(4)).expect("valid Argon2id settings");
        assert_eq!(kdf, argon2(3, 64, 4));
    }

    #[test]
    fn from_wire_rejects_zero_iterations() {
        assert!(matches!(
            Kdf::from_wire(0, 0, None, None),
            Err(Error::KdfTooWeak(_))
        ));
        assert!(matches!(
            Kdf::from_wire(1, 0, Some(64), Some(4)),
            Err(Error::KdfTooWeak(_))
        ));
    }

    #[test]
    fn from_wire_rejects_missing_or_zero_argon2_fields() {
        for (memory, parallelism) in [
            (None, Some(4)),
            (Some(64), None),
            (Some(0), Some(4)),
            (Some(64), Some(0)),
        ] {
            let result = Kdf::from_wire(1, 3, memory, parallelism);
            assert!(
                matches!(result, Err(Error::KdfTooWeak(_))),
                "memory {memory:?}, parallelism {parallelism:?} gave {result:?}"
            );
        }
    }

    #[test]
    fn from_wire_rejects_unknown_type() {
        assert!(matches!(
            Kdf::from_wire(2, 600_000, None, None),
            Err(Error::UnsupportedKdf(2))
        ));
    }

    #[test]
    fn validate_accepts_minimums() {
        Kdf::Pbkdf2 {
            iterations: nz(5_000),
        }
        .validate()
        .expect("PBKDF2 minimum is allowed");
        argon2(2, 16, 1)
            .validate()
            .expect("Argon2id minimums are allowed");
    }

    #[test]
    fn validate_rejects_below_minimums() {
        for kdf in [
            Kdf::Pbkdf2 {
                iterations: nz(4_999),
            },
            argon2(1, 16, 1),
            argon2(2, 15, 1),
            argon2(1, 15, 1),
        ] {
            assert!(
                matches!(kdf.validate(), Err(Error::KdfTooWeak(_))),
                "{kdf:?} accepted"
            );
        }
    }

    #[test]
    fn derive_rejects_weak_kdf_before_hashing() {
        let mut out = [0u8; 32];
        let result = Kdf::Pbkdf2 {
            iterations: nz(4_999),
        }
        .derive_into(b"password", b"salt", &mut out);
        assert!(matches!(result, Err(Error::KdfTooWeak(_))));
        assert_eq!(out, [0u8; 32]);
    }

    #[test]
    fn validate_accepts_maximums() {
        Kdf::Pbkdf2 {
            iterations: nz(2_000_000),
        }
        .validate()
        .expect("PBKDF2 maximum is allowed");
        argon2(10, 1024, 16)
            .validate()
            .expect("Argon2id maximums are allowed");
    }

    #[test]
    fn validate_rejects_above_maximums() {
        for kdf in [
            Kdf::Pbkdf2 {
                iterations: nz(2_000_001),
            },
            Kdf::Pbkdf2 {
                iterations: nz(u32::MAX),
            },
            argon2(11, 16, 1),
            argon2(2, 1025, 1),
            argon2(2, 16, 17),
            argon2(u32::MAX, u32::MAX, u32::MAX),
        ] {
            assert!(
                matches!(kdf.validate(), Err(Error::KdfOutOfRange(_))),
                "{kdf:?} accepted"
            );
        }
    }

    #[test]
    fn validate_reports_too_weak_before_too_strong() {
        assert!(matches!(
            argon2(1, 2048, 1).validate(),
            Err(Error::KdfTooWeak(_))
        ));
    }

    #[test]
    fn derive_rejects_out_of_range_kdf_before_hashing() {
        for kdf in [
            Kdf::Pbkdf2 {
                iterations: nz(u32::MAX),
            },
            argon2(2, u32::MAX, 1),
        ] {
            let mut out = [0u8; 32];
            let result = kdf.derive_into(b"password", b"salt", &mut out);
            assert!(matches!(result, Err(Error::KdfOutOfRange(_))), "{kdf:?}");
            assert_eq!(out, [0u8; 32]);
        }
    }
}
