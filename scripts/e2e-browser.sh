#!/usr/bin/env bash
# Runs the real Firefox extension (headless, WebDriver) against a real `vaultkeeper --daemon` and a
# disposable Vaultwarden. Everything stays private: the daemon gets its own data dir and keychain
# prefix (the e2e overrides of the `vw-it` build), Firefox gets its own HOME and profile.
#
#   E2E_DEPS=<dir with node_modules/selenium-webdriver> GECKODRIVER=<path> scripts/e2e-browser.sh
#
# E2E_DEPS: `npm i selenium-webdriver` in any scratch directory (not in the repo).
# GECKODRIVER: a geckodriver binary. WORK: where logs and results.json go.
# VW_PORT picks the Vaultwarden host port (a free one when unset).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT/tests/e2e/compose.yaml"
PROJECT="vk-e2e-browser-$$"
: "${E2E_DEPS:?set E2E_DEPS to a directory containing node_modules/selenium-webdriver}"
: "${GECKODRIVER:?set GECKODRIVER to a geckodriver binary}"
export WORK="${WORK:-$(mktemp -d /tmp/vk-e2e-browser-work.XXXXXX)}"

free_port() {
    python3 -I -c 'import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

export VW_PORT="${VW_PORT:-$(free_port)}"
export MAILPIT_PORT="${MAILPIT_PORT:-$(free_port)}"
export VW_ADMIN_TOKEN="${VW_ADMIN_TOKEN:-e2e-admin-token}"

compose() {
    docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" "$@"
}

cleanup() {
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

compose up --detach --quiet-pull
for _ in $(seq 1 90); do
    curl -fsS "http://localhost:$VW_PORT/alive" >/dev/null 2>&1 && break
    sleep 1
done
curl -fsS "http://localhost:$VW_PORT/alive" >/dev/null

cd "$ROOT"
cargo build -p vaultkeeper --features vw-it --bin vaultkeeper --example e2e_browser_bot
pnpm -C browsers build

export VW_URL="http://localhost:$VW_PORT"
export DAEMON_BIN="$ROOT/target/debug/vaultkeeper"
export BOT_BIN="$ROOT/target/debug/examples/e2e_browser_bot"
export EXT_DIR="$ROOT/browsers/dist/firefox"
node "$ROOT/browsers/e2e/run.mjs"
