//! Starts the UI process on Windows: hardened, with the daemon's pipe as its only inherited handle
//! (`docs/solutions/windows-support.md` §5.1, §5.2).

use std::{io, path::Path};

use vk_ipc::{UiSink, transport::UiPipe};
use vk_win::{Child, SpawnOptions, sddl};

use super::ui_args_with_pipe;

// The attribute takes `PROCESS_CREATION_MITIGATION_POLICY_*` flags, which windows-sys does not
// export. They mirror `vk_platform::hardening::UI_MITIGATIONS` so the UI is locked down before
// its first instruction instead of after `harden_process` runs.
const STRICT_HANDLE_CHECKS: u64 = 1 << 24;
const PROHIBIT_DYNAMIC_CODE: u64 = 1 << 36;
const IMAGE_LOAD_NO_REMOTE: u64 = 1 << 52;
const IMAGE_LOAD_NO_LOW_LABEL: u64 = 1 << 56;
const IMAGE_LOAD_PREFER_SYSTEM32: u64 = 1 << 60;
const BASE_CREATION_MITIGATIONS: u64 = STRICT_HANDLE_CHECKS
    | IMAGE_LOAD_NO_REMOTE
    | IMAGE_LOAD_NO_LOW_LABEL
    | IMAGE_LOAD_PREFER_SYSTEM32;

// ProhibitDynamicCode can break input methods, file dialogs and screen readers that inject code,
// so it waits for the hardware checklist like the other risky mitigations in vk-platform.
fn creation_mitigations(strict: bool) -> u64 {
    if strict {
        BASE_CREATION_MITIGATIONS | PROHIBIT_DYNAMIC_CODE
    } else {
        BASE_CREATION_MITIGATIONS
    }
}

fn strict_enabled() -> bool {
    std::env::var("VAULTKEEPER_STRICT_MITIGATIONS").is_ok_and(|value| value == "1")
}

/// Creates the channel, spawns the UI with it and gives the server end to the daemon's IPC
/// server. Must run inside the Tokio runtime that serves the pipe.
pub fn spawn(
    exe: &Path,
    first_unlock: bool,
    no_activate: bool,
    sink: &UiSink,
) -> io::Result<Child> {
    let mut pipe = UiPipe::create()?;
    let handle = pipe
        .client_handle()
        .ok_or_else(|| io::Error::other("the UI pipe has no client handle"))?;
    let sid = vk_win::current_user_sid()?;
    let options = SpawnOptions {
        process_sddl: Some(sddl::process(&sid)?),
        thread_sddl: Some(sddl::thread(&sid)?),
        inherit_handles: vec![handle],
        mitigation_policy: creation_mitigations(strict_enabled()),
        creation_flags: 0,
    };
    let args = ui_args_with_pipe(first_unlock, no_activate, handle as usize);
    let child = vk_win::spawn_hardened(exe, &args, &options)?;
    // The child owns its copy now; keeping ours would hold the pipe open after the UI dies.
    pipe.close_client();
    if let Err(error) = sink.offer(pipe.into_stream()) {
        let _ = child.kill();
        return Err(io::Error::other(error));
    }
    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_code_is_prohibited_only_in_strict_mode() {
        assert_eq!(creation_mitigations(false) & PROHIBIT_DYNAMIC_CODE, 0);
        assert_ne!(creation_mitigations(true) & PROHIBIT_DYNAMIC_CODE, 0);
    }
}
