//! The `&'static str` details carried by [`crate::Error`]. Exported as tables so a process that
//! receives an error by its text (the UI, over IPC) can map it back to the same `&'static str`.

pub(crate) const WRONG_PARTS: &str = "wrong number of parts";
pub(crate) const INVALID_TYPE_HEADER: &str = "invalid type header";
pub(crate) const INVALID_BASE64: &str = "invalid base64";
pub(crate) const EMPTY_RSA_CIPHERTEXT: &str = "RSA ciphertext is empty";
pub(crate) const IV_LEN: &str = "IV must be 16 bytes";
pub(crate) const MAC_LEN: &str = "MAC must be 32 bytes";
pub(crate) const CIPHERTEXT_LEN: &str = "ciphertext must be a non-empty multiple of 16 bytes";
pub(crate) const EMPTY_BUFFER: &str = "encrypted buffer is empty";
pub(crate) const SHORT_BUFFER: &str = "encrypted buffer is shorter than its header";

pub(crate) const PBKDF2_ITERATIONS_ZERO: &str = "PBKDF2 iterations are zero";
pub(crate) const ARGON2_ITERATIONS_ZERO: &str = "Argon2id iterations are zero";
pub(crate) const ARGON2_MEMORY_ZERO: &str = "Argon2id memory is missing or zero";
pub(crate) const ARGON2_PARALLELISM_ZERO: &str = "Argon2id parallelism is missing or zero";
pub(crate) const PBKDF2_ITERATIONS_BELOW: &str = "PBKDF2 needs at least 5000 iterations";
pub(crate) const PBKDF2_ITERATIONS_ABOVE: &str = "PBKDF2 allows at most 2000000 iterations";
pub(crate) const ARGON2_ITERATIONS_BELOW: &str = "Argon2id needs at least 2 iterations";
pub(crate) const ARGON2_ITERATIONS_ABOVE: &str = "Argon2id allows at most 10 iterations";
pub(crate) const ARGON2_MEMORY_BELOW: &str = "Argon2id needs at least 16 MiB of memory";
pub(crate) const ARGON2_MEMORY_ABOVE: &str = "Argon2id allows at most 1024 MiB of memory";
pub(crate) const ARGON2_PARALLELISM_BELOW: &str = "Argon2id needs a parallelism of at least 1";
pub(crate) const ARGON2_PARALLELISM_ABOVE: &str = "Argon2id allows a parallelism of at most 16";

/// Every detail of [`crate::Error::MalformedEncString`].
pub const MALFORMED_DETAILS: &[&str] = &[
    WRONG_PARTS,
    INVALID_TYPE_HEADER,
    INVALID_BASE64,
    EMPTY_RSA_CIPHERTEXT,
    IV_LEN,
    MAC_LEN,
    CIPHERTEXT_LEN,
    EMPTY_BUFFER,
    SHORT_BUFFER,
];

/// Every detail of [`crate::Error::KdfTooWeak`] and [`crate::Error::KdfOutOfRange`].
pub const KDF_DETAILS: &[&str] = &[
    PBKDF2_ITERATIONS_ZERO,
    ARGON2_ITERATIONS_ZERO,
    ARGON2_MEMORY_ZERO,
    ARGON2_PARALLELISM_ZERO,
    PBKDF2_ITERATIONS_BELOW,
    PBKDF2_ITERATIONS_ABOVE,
    ARGON2_ITERATIONS_BELOW,
    ARGON2_ITERATIONS_ABOVE,
    ARGON2_MEMORY_BELOW,
    ARGON2_MEMORY_ABOVE,
    ARGON2_PARALLELISM_BELOW,
    ARGON2_PARALLELISM_ABOVE,
];
