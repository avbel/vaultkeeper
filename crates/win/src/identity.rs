//! Identity of an executable as the Windows filesystem sees it: the volume it lives on plus its
//! 128-bit file id. This replaces the macOS cdhash check (§5.3) — it proves the same file on the
//! same volume, not who signed it, so a rebuild signed with our certificate still differs.
//!
//! The struct stays free of Win32 so callers and tests compile on every target; the Windows half
//! lives in `windows.rs`.

/// Identifies a file by the volume it lives on and its file id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageIdentity {
    pub volume_serial: u64,
    pub file_id: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::ImageIdentity;

    #[test]
    fn equality_covers_both_volume_and_file_id() {
        let identity = ImageIdentity {
            volume_serial: 0x1234_5678_9abc_def0,
            file_id: [7; 16],
        };
        assert_eq!(identity, identity);

        let other_volume = ImageIdentity {
            volume_serial: 0x1234_5678_9abc_def1,
            ..identity
        };
        assert_ne!(identity, other_volume);

        let other_file = ImageIdentity {
            file_id: [8; 16],
            ..identity
        };
        assert_ne!(identity, other_file);
    }
}
