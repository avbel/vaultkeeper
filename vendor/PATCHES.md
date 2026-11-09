# Patches to vendored crates

Baseline for each crate is the upstream commit in `UPSTREAM.txt`. Every deviation is listed here with the reason.

## ssh_agent

The socket-path rows are `#[cfg(unix)]` and purely additive: the upstream entry points and their tests are untouched. The `protocol.rs` row fixes behavior; the `clear` row is an additive public entry point.

| File | Change | Reason |
| --- | --- | --- |
| `src/server/listener/unix.rs` | `UnixListener::bind(PathBuf)` holds the old body of `new()`; `new()` now calls it with `get_socket_path()`. | Lets the caller choose the socket path without mutating the process-wide `BITWARDEN_SSH_AUTH_SOCK`. |
| `src/server/listener/mod.rs` | New `create_listeners_at(PathBuf)`. | Plumbing for the path. |
| `src/server/mod.rs` | New `SSHAgentServer::start_at_socket_path(PathBuf)`. | Plumbing for the path. |
| `src/agent.rs` | New public `BitwardenSSHAgent::start_at(PathBuf)`. | Entry point used by `crates/ssh`. |
| `src/server/protocol.rs` | `detect_namespace` reads the namespace right after the 6-byte `SSHSIG` magic instead of after magic + a `u32` version. Its unit-test helper `make_sshsig_blob` drops the version field, `detect_namespace_truncated_after_version_returns_unsupported` becomes `..._after_magic_...` with the same intent, and `detect_namespace_reads_the_layout_openssh_signs` is new. | Upstream bug, not Unix-specific: the data an agent signs for `ssh-keygen -Y sign` is `SSHSIG`, namespace, reserved, hash algorithm, hash (`sshsig_wrap_sign` in OpenSSH); the version only exists in the armored signature. With the old offset every real `git`/`file` signature was reported as `Unsupported`, so the approval UI never saw the namespace. Observed with OpenSSH 10.5 in `crates/ssh/tests/agent.rs`. |
| `src/agent.rs` | New public `BitwardenSSHAgent::clear()` calling `KeyStore::clear()` (which resets `initialized`), plus the unit test `clear_clears_the_keystore_without_stopping`. | Upstream only clears on `stop()`, and `replace(vec![])` leaves the keystore `initialized`, so after the first key refresh a list request never reaches `request_list_approval`. bw-lite clears on lock / log out / account switch so a locked vault serves no keys and `ssh-add -l` asks the user to unlock. |
