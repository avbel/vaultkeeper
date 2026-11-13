#!/usr/bin/env bash
# Prints the release version. [workspace.package] version in Cargo.toml is its only source: the app, the
# browser extension manifests and the release tag (v<version>) all take it from there.
set -euo pipefail

cd "$(dirname "$0")/.."
awk '/^\[workspace\.package\]/ { inside = 1; next }
     /^\[/ { inside = 0 }
     inside && /^version[[:space:]]*=/ { gsub(/^[^"]*"|".*$/, ""); print; found = 1; exit }
     END { if (!found) { print "no version in [workspace.package] of Cargo.toml" > "/dev/stderr"; exit 1 } }' Cargo.toml
