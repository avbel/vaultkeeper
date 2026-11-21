# Linux requirements

Generated from `app/src/os/security_requirements.rs`; `vaultkeeper security requirements` prints the same table. On Ubuntu 26.10, Fedora 45 and Omarchy the stock install meets every line. Any other Arch setup is unsupported and runs only when these checks pass.

| Item | Probe | Class | Missing → | Fix: Ubuntu 26.10 | Fedora 45 | Omarchy (Arch) |
| --- | --- | --- | --- | --- | --- | --- |
| Kernel 6.5 or newer with SO_PEERPIDFD; 6.13 or newer for PIDFD_GET_INFO | `SO_PEERPIDFD` on a socket pair, `PIDFD_GET_INFO` on a pidfd | Refuse | peers cannot be identified; Vaultkeeper will not start | stock kernel | stock kernel | `linux-omarchy`, `linux` or `linux-lts` |
| `XDG_RUNTIME_DIR` on tmpfs, owned by you, mode 0700 | `stat` and `statfs` of the directory | Refuse | nowhere private for the sockets; Vaultkeeper will not start | provided by logind | provided by logind | provided by logind (UWSM) |
| Wayland session (daemon and windows; not the CLI) | `WAYLAND_DISPLAY` is set and its socket connects | Refuse | no windows; X11 is not supported | log in to the "Ubuntu" (Wayland) session | stock | stock (Hyprland) |
| Keys in memory: `memfd_secret`, else keyctl, else mlock | the key store reports the mechanism it obtained | Refuse below mlock | keys could not be held in protected memory | stock | stock | stock; a custom kernel needs `CONFIG_SECRETMEM` |
| Data directory owned by you, not a symbolic link; modes 0700 and 0600 | `stat` through an `O_NOFOLLOW` descriptor | Refuse (owner, link); modes are repaired | Vaultkeeper will not start | `chown -R $USER ~/.local/share/vaultkeeper` | same | same |
