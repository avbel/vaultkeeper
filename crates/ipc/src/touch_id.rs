//! Touch ID inside the daemon. The user key is wrapped and unwrapped here, next to the vault that
//! owns it, so it never travels over the socket; the UI only asks for "enrol" or "unlock".

use zeroize::Zeroizing;

use crate::protocol::TouchIdFailure;

/// The daemon's Secure Enclave access. Both methods may block (the unlock shows the system
/// prompt); the server calls them on the blocking pool.
pub trait TouchIdBackend: Send + Sync + 'static {
    /// Seals `user_key` for `account_id`, replacing an earlier enrolment.
    fn enroll(&self, account_id: &str, user_key: &[u8]) -> Result<(), TouchIdFailure>;

    /// Shows the prompt and returns the unsealed user key of `account_id`.
    fn unlock(&self, account_id: &str) -> Result<Zeroizing<Vec<u8>>, TouchIdFailure>;
}
