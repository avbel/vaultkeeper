use std::num::NonZeroU32;

use crate::Result;

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
    pub fn from_wire(
        kdf_type: u8,
        iterations: u32,
        memory_mib: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<Self> {
        let _ = (kdf_type, iterations, memory_mib, parallelism);
        todo!("step 2")
    }

    /// Rejects parameters below the client minimums so a malicious server can't downgrade the KDF:
    /// PBKDF2 >= 5000 iterations; Argon2id iterations >= 2, memory >= 16 MiB, parallelism >= 1.
    pub fn validate(&self) -> Result<()> {
        todo!("step 2")
    }
}
