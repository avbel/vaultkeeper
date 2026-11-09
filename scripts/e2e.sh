#!/usr/bin/env bash
# Runs the end-to-end scenarios against a disposable Vaultwarden + Mailpit: the bwl-vault ones,
# then the app's, which start a real `bw-lite --daemon` process (headless, own data dir and
# keychain item prefix) and drive it over IPC.
#
#   scripts/e2e.sh                 # all scenarios
#   scripts/e2e.sh websocket       # extra args go to both `cargo test` runs (name filter, ...)
#
# VW_PORT / MAILPIT_PORT pick the host ports (defaults 8098 / 8025, or a free port when taken).
# KEEP_E2E_STACK=1 leaves the containers running for debugging.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT/tests/e2e/compose.yaml"
PROJECT="bwl-e2e-$$"

port_is_free() {
    python3 -I -c 'import socket,sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)' "$1"
}

free_port() {
    python3 -I -c 'import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

pick_port() {
    if port_is_free "$1"; then echo "$1"; else free_port; fi
}

export VW_PORT="${VW_PORT:-$(pick_port 8098)}"
export MAILPIT_PORT="${MAILPIT_PORT:-$(pick_port 8025)}"
export VW_ADMIN_TOKEN="${VW_ADMIN_TOKEN:-e2e-admin-token}"

compose() {
    docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" "$@"
}

cleanup() {
    if [[ "${KEEP_E2E_STACK:-0}" == "1" ]]; then
        echo "e2e: leaving stack $PROJECT running (VW on $VW_PORT, Mailpit on $MAILPIT_PORT)"
        return
    fi
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
# A signal handler that only cleans up would let the script carry on (and keep running cargo)
# after Ctrl-C; exiting from it runs the EXIT trap once.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for() {
    local name="$1" url="$2"
    for _ in $(seq 1 90); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "e2e: $name did not become healthy at $url" >&2
    compose logs >&2 || true
    return 1
}

echo "e2e: starting Vaultwarden on $VW_PORT and Mailpit on $MAILPIT_PORT"
compose up --detach --quiet-pull
wait_for vaultwarden "http://localhost:$VW_PORT/alive"
wait_for mailpit "http://localhost:$MAILPIT_PORT/api/v1/info"

cd "$ROOT"
export VW_URL="http://localhost:$VW_PORT"
export MAILPIT_URL="http://localhost:$MAILPIT_PORT"
export VW_ADMIN_TOKEN
cargo test -p bwl-vault --features vw-it "$@"
cargo test -p bw-lite --features vw-it --test e2e_daemon "$@"
