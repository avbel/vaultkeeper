//! What the sandbox may execute.
//!
//! Landlock asks for Execute (with ReadFile) when a file is opened for execution: the binary
//! given to `execve` and the `PT_INTERP` loader the kernel opens for it. Mapping a file is not a
//! Landlock access, so a shared library needs ReadFile alone and `dlopen` works without Execute.
//! The same fact is the limit: a library written into a writable directory can still be mapped
//! (the kernel child test holds both).
//!
//! Every grant is a file, and a rule on a file holds for that inode. An upgrade puts a new file
//! behind the same path, which the sandbox refuses: the daemon watches these files and restarts
//! into a fresh sandbox when one was replaced (`update::upgraded`, through systemd so that the
//! new daemon does not inherit this one's rules). Nothing is spawned by name after the sandbox
//! is applied: `rpm -qf` is asked before it (`install_kind::cached`), as are `notify-send` and
//! `update-desktop-database`, and links open through the portal.

use std::path::{Path, PathBuf};

const PT_INTERP: u32 = 3;
const ELF64_HEADER: usize = 64;
const ELF64_PROGRAM_HEADER: usize = 56;
/// `PATH_MAX`: the kernel refuses a longer loader path.
const MAX_INTERP: u64 = 4096;

/// Everything the sandbox may execute: the vaultkeeper binary (the UI is this binary started
/// again), `tools`, and the loader each of them names, resolved to the file a rule can hold.
///
/// `None` when the install path is not absolute: no rule can be derived from it.
#[must_use]
pub fn exec_paths(install: &Path, tools: &[PathBuf]) -> Option<Vec<PathBuf>> {
    if !install.is_absolute() {
        return None;
    }
    let mut paths = vec![install.to_owned()];
    paths.extend(tools.iter().cloned());
    let binaries = std::iter::once(install).chain(tools.iter().map(PathBuf::as_path));
    for loader in binaries.filter_map(loader) {
        if !paths.contains(&loader) {
            paths.push(loader);
        }
    }
    Some(paths)
}

/// The loader of `binary` under its real name: `/lib64` is a link on most systems, and the
/// upgrade watch compares the file, not the link.
fn loader(binary: &Path) -> Option<PathBuf> {
    interpreter(binary)?.canonicalize().ok()
}

/// The `PT_INTERP` of a 64-bit little-endian ELF file, which is every Linux target Vaultkeeper
/// is built for. `None` for anything else, a static binary included.
#[must_use]
pub fn interpreter(binary: &Path) -> Option<PathBuf> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(binary).ok()?;
    let mut header = [0_u8; ELF64_HEADER];
    file.read_exact(&mut header).ok()?;
    if header.get(..6)? != b"\x7fELF\x02\x01" {
        return None;
    }
    let table = le_u64(&header, 32)?;
    let entry_size = u64::from(le_u16(&header, 54)?);
    let entries = u64::from(le_u16(&header, 56)?);
    for index in 0..entries {
        let at = table.checked_add(index.checked_mul(entry_size)?)?;
        let mut entry = [0_u8; ELF64_PROGRAM_HEADER];
        file.seek(SeekFrom::Start(at)).ok()?;
        file.read_exact(&mut entry).ok()?;
        if le_u32(&entry, 0)? != PT_INTERP {
            continue;
        }
        let size = le_u64(&entry, 32)?;
        if size > MAX_INTERP {
            return None;
        }
        let mut name = vec![0_u8; usize::try_from(size).ok()?];
        file.seek(SeekFrom::Start(le_u64(&entry, 8)?)).ok()?;
        file.read_exact(&mut name).ok()?;
        let end = name.iter().position(|byte| *byte == 0)?;
        name.truncate(end);
        let path = PathBuf::from(String::from_utf8(name).ok()?);
        return path.is_absolute().then_some(path);
    }
    None
}

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64-bit ELF with a `PT_LOAD` and a `PT_INTERP` naming `loader`.
    fn elf(loader: &[u8]) -> Vec<u8> {
        let mut file = vec![0_u8; ELF64_HEADER + 2 * ELF64_PROGRAM_HEADER];
        file[..6].copy_from_slice(b"\x7fELF\x02\x01");
        file[32..40].copy_from_slice(&64_u64.to_le_bytes());
        file[54..56].copy_from_slice(&56_u16.to_le_bytes());
        file[56..58].copy_from_slice(&2_u16.to_le_bytes());
        let load = ELF64_HEADER;
        file[load..load + 4].copy_from_slice(&1_u32.to_le_bytes());
        let interp = ELF64_HEADER + ELF64_PROGRAM_HEADER;
        let offset = file.len() as u64;
        file[interp..interp + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
        file[interp + 8..interp + 16].copy_from_slice(&offset.to_le_bytes());
        file[interp + 32..interp + 40].copy_from_slice(&(loader.len() as u64).to_le_bytes());
        file.extend_from_slice(loader);
        file
    }

    #[test]
    fn the_loader_is_read_from_the_program_headers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("binary");
        std::fs::write(&binary, elf(b"/lib64/ld-linux-x86-64.so.2\0")).expect("write");
        assert_eq!(
            interpreter(&binary),
            Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2"))
        );
        for (name, content) in [
            ("relative", elf(b"ld.so\0")),
            ("unterminated", elf(b"/lib/ld.so")),
            ("script", b"#!/bin/sh\nexit 0\n".to_vec()),
            ("elf32", {
                let mut file = elf(b"/lib/ld.so\0");
                file[4] = 1;
                file
            }),
            ("truncated", elf(b"/lib/ld.so\0")[..100].to_vec()),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, content).expect("write");
            assert_eq!(interpreter(&path), None, "{name}");
        }
        assert_eq!(interpreter(&dir.path().join("missing")), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_binary_its_tools_and_each_loader_are_granted_as_files() {
        let base = tempfile::tempdir().expect("tempdir");
        let base = base.path().canonicalize().expect("canonical");
        for dir in ["bin", "tools", "lib"] {
            std::fs::create_dir(base.join(dir)).expect(dir);
        }
        let loader = base.join("lib/ld.so");
        std::fs::write(&loader, b"").expect("loader");
        std::os::unix::fs::symlink("lib", base.join("lib64")).expect("link");
        let mut name = base
            .join("lib64/ld.so")
            .to_string_lossy()
            .into_owned()
            .into_bytes();
        name.push(0);
        let install = base.join("bin/vaultkeeper");
        let tool = base.join("tools/tool");
        for binary in [&install, &tool] {
            std::fs::write(binary, elf(&name)).expect("binary");
        }
        let script = base.join("tools/script");
        std::fs::write(&script, b"#!/bin/sh\n").expect("script");
        assert_eq!(
            exec_paths(&install, &[tool.clone(), script.clone()]),
            Some(vec![install, tool, script, loader])
        );
        assert_eq!(exec_paths(Path::new("vaultkeeper"), &[]), None);
    }
}
