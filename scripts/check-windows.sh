#!/bin/sh
# Type-checks the Windows build from macOS through cargo-xwin's MSVC-compatible
# clang. Windows-only code never compiles with the host toolchain, so this is
# the local equivalent of the CI `windows` job; tests still run only in CI.
set -e

cd "$(dirname "$0")/.."

if ! command -v cargo-xwin >/dev/null 2>&1; then
    echo "cargo-xwin is missing; install it with: cargo install cargo-xwin --locked" >&2
    exit 1
fi

PATH="/opt/homebrew/opt/llvm/bin:/opt/homebrew/opt/lld/bin:$PATH"
export PATH

# Windows artifacts live outside ./target: the two targets would otherwise keep
# evicting each other's incremental state.
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${VK_XWIN_TARGET_DIR:-$HOME/Library/Caches/vaultkeeper-xwin}}"
export CARGO_TARGET_DIR

# VK_WIN_TARGET=aarch64-pc-windows-msvc checks the ARM64 build.
exec cargo xwin clippy --target "${VK_WIN_TARGET:-x86_64-pc-windows-msvc}" "$@" -- -D warnings
