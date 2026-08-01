#!/bin/sh
# The daemon must stay silent at level 0 and narrate at -vv / RELIQUARY_DEBUG.
# We don't even need a client connection: the "listening on" banner is a
# debug1 line, so starting the daemon briefly with no connections is enough
# to exercise the gating. stderr is captured.
set -e
BIN="${MESON_BUILD_ROOT:-build}/src/daemon/reliquaryd"
RT="${XDG_RUNTIME_DIR:=/tmp/reliquary-verb-$$}"
mkdir -p "$RT/reliquary"
export XDG_RUNTIME_DIR RELIQUARY_SKIP_SETGID_CHECK=1 RELIQUARY_SKIP_SECCOMP=1
STORE="/tmp/reliquary-verb-store-$$"

run_daemon() {  # $1 = extra args, $2 = extra env; prints captured stderr
	err="/tmp/reliquary-verb-err-$$"
	env $2 "$BIN" --store "$STORE" $1 2>"$err" &
	pid=$!
	sleep 1				# long enough to print the startup banner
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	cat "$err"; rm -f "$err"
}

# Level 0: the "listening on" line is fine, but no debug1: lines.
out0=$(run_daemon "" "")
echo "$out0" | grep -q "^debug1:" && { echo "FAIL: debug1 at level 0"; exit 1; }

# -vv: expect debug1 lifecycle lines (at minimum the listening banner).
out2=$(run_daemon "-vv" "")
echo "$out2" | grep -q "^debug1:" || { echo "FAIL: no debug1 at -vv"; exit 1; }

# RELIQUARY_DEBUG=1 via env alone must also raise the level.
outenv=$(run_daemon "" "RELIQUARY_DEBUG=1")
echo "$outenv" | grep -q "^debug1:" || { echo "FAIL: no debug1 via env"; exit 1; }

echo "ok: verbosity gating via flags and env"
