//! How `webauthn.dll` HRESULTs map to login outcomes. Portable so the mapping is tested on every
//! host; only the Windows backend calls it.

use crate::hooks::HookError;

const ERROR_CANCELLED: i32 = 0x8007_04C7_u32.cast_signed();
const NTE_USER_CANCELLED: i32 = 0x8009_0036_u32.cast_signed();
const ERROR_TIMEOUT: i32 = 0x8007_05B4_u32.cast_signed();
const NTE_NOT_FOUND: i32 = 0x8009_0011_u32.cast_signed();

/// The Windows dialog's own Cancel button and `WebAuthNCancelCurrentOperation` both end the call
/// with one of the cancel codes, so neither shows an error.
pub(super) fn error_for(hresult: i32) -> HookError {
    let text = match hresult {
        ERROR_CANCELLED | NTE_USER_CANCELLED => return HookError::Cancelled,
        ERROR_TIMEOUT => "No registered security key answered in time",
        NTE_NOT_FOUND => "This security key is not registered for this account",
        other => {
            tracing::warn!(
                hresult = format_args!("{other:#010x}"),
                "security key failed"
            );
            "The security key could not be used"
        }
    };
    HookError::Failed(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_cancel_codes_are_a_cancel() {
        assert!(matches!(
            error_for(0x8009_0036_u32.cast_signed()),
            HookError::Cancelled
        ));
        assert!(matches!(
            error_for(0x8007_04C7_u32.cast_signed()),
            HookError::Cancelled
        ));
    }

    #[test]
    fn timeout_and_unknown_codes_have_text() {
        assert!(matches!(
            error_for(0x8007_05B4_u32.cast_signed()),
            HookError::Failed(text) if text.contains("in time")
        ));
        assert!(matches!(error_for(-1), HookError::Failed(_)));
    }
}
