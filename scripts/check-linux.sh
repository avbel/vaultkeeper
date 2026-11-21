#!/bin/sh
# Lints (or, with --test, tests) the Linux build from macOS inside Docker.
# Linux-only code never compiles with the host toolchain, so this is the local
# equivalent of the CI `linux` job. The arm64 image on Apple silicon is fine
# for a check: no code here is x86-specific.
#   scripts/check-linux.sh [--test] [cargo args]
set -e

cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "Docker is missing or not running; start Docker Desktop (or colima) and retry." >&2
    exit 1
fi

MODE=clippy
if [ "$1" = "--test" ]; then
    MODE=test
    shift
fi

BASE=rust:1.99.1-bookworm
IMAGE=vaultkeeper-linux-check:1.99.1

# The apt step costs a minute, so it is baked into a local image once.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -t "$IMAGE" - <<DOCKERFILE
FROM $BASE
RUN apt-get -qq update && apt-get -qq install -y libfontconfig1-dev libxkbcommon-dev \
    libwayland-dev libdbus-1-dev libudev-dev clang libelf-dev zlib1g-dev bpftool \
    && rm -rf /var/lib/apt/lists/*
RUN rustup component add clippy rustfmt
DOCKERFILE
fi

# Named volumes keep the registry and the Linux target dir out of ./target,
# where the two hosts would keep evicting each other's artifacts.
# Docker's default seccomp profile blocks keyctl, memfd_secret and landlock, which the probes and
# the secure_memory tests exercise; a desktop session has them.
# Two jobs by default: parallel test links run the Docker VM out of memory. No debug info: with
# it, and with incremental caches, the target volume grew past 50 GB.
exec docker run --rm --security-opt seccomp=unconfined \
    -v "$PWD":/src -w /src \
    -v vaultkeeper-linux-cargo:/usr/local/cargo/registry \
    -v vaultkeeper-linux-target:/target -e CARGO_TARGET_DIR=/target \
    -e CARGO_PROFILE_DEV_DEBUG=0 -e CARGO_PROFILE_TEST_DEBUG=0 -e CARGO_INCREMENTAL=0 \
    -e CARGO_BUILD_JOBS="${VK_LINUX_JOBS:-2}" \
    "$IMAGE" sh -c '
        mode=$1; shift
        if [ "$mode" = test ]; then
            exec cargo test --locked "$@"
        fi
        exec cargo clippy --locked "$@" -- -D warnings
    ' sh "$MODE" "$@"
