#!/bin/sh
# Prints the anonymous and proportional memory of the running daemon and UI process, from
# /proc/<pid>/smaps_rollup, next to the macOS numbers in the checklist (§16). Run it three times:
# tray only, with the Quick Panel shown, and 10 s after closing it. Vaultkeeper's processes are
# non-dumpable, so smaps_rollup (Pss) is readable by root only: run it with sudo for that column.
set -e

if [ "$(uname -s)" != Linux ]; then
    echo "measure-linux.sh reads /proc and runs on Linux only." >&2
    exit 1
fi

kib_to_mb() {
    awk -v kib="$1" 'BEGIN { printf "%.1f", kib / 1024 }'
}

field() {
    awk -v name="$1:" '$1 == name { print $2 }' "/proc/$2/smaps_rollup" 2>/dev/null || echo 0
}

found=0
for pid in $(pgrep -x vaultkeeper); do
    found=1
    if tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q -- '--ui'; then
        role=ui
    else
        role=daemon
    fi
    printf '%-7s pid %-7s RssAnon %6s MB  Pss %6s MB\n' "$role" "$pid" \
        "$(kib_to_mb "$(awk '/^RssAnon:/ { print $2 }' "/proc/$pid/status")")" \
        "$(kib_to_mb "$(field Pss "$pid")")"
done

if [ "$found" = 0 ]; then
    echo "No vaultkeeper process is running." >&2
    exit 1
fi
echo "macOS reference: daemon 13.9 MB, UI with Quick Panel 47.3 MB, UI 10 s after close 41.8 MB"
