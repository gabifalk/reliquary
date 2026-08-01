#!/bin/sh
# The daemon must refuse to run when it is not setgid to the reliquary group.
# In the test environment the built binary is NOT setgid, so egid == gid and
# the self-check must abort.

set -e
BIN="${MESON_BUILD_ROOT:-build}/src/daemon/reliquaryd"
XDG_RUNTIME_DIR="$(mktemp -dt reliquary-test-runtime-XXXXXX)"
mkdir -p "$XDG_RUNTIME_DIR"
export XDG_RUNTIME_DIR

cleanup() {
	kill "$pid" 2>/dev/null || true
	wait 2>/dev/null || true
	rm -rf "$XDG_RUNTIME_DIR"
}
trap cleanup EXIT

unset RELIQUARY_SKIP_SETGID_CHECK

if "$BIN" --store /tmp/reliquary-setgid-test-$$ 2>err.log; then
	echo "FAIL: daemon started without setgid"
	cat err.log
	exit 1
fi
grep -qi "setgid" err.log || { echo "FAIL: no setgid error"; cat err.log; exit 1; }
echo "ok: daemon refused to start without setgid"
