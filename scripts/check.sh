#!/bin/sh
# Required checks before every commit (also run by .githooks/pre-commit).
set -e
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
