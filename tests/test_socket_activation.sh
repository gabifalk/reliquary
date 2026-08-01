#!/bin/sh
# reliquaryd must adopt an inherited socket passed via the systemd socket-
# activation protocol (LISTEN_FDS/LISTEN_PID, fd SD_LISTEN_FDS_START=3)
# instead of creating its own. A Python helper binds a listening socket on
# fd 3 and execs the daemon so that LISTEN_PID matches the daemon's pid.
set -e
BIN="${MESON_BUILD_ROOT:-build}/src/daemon/reliquaryd"
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not found"; exit 77; }

XDG_RUNTIME_DIR="$(mktemp -dt reliquary-sockact-XXXXXX)"
mkdir -p "$XDG_RUNTIME_DIR/reliquary"
export XDG_RUNTIME_DIR RELIQUARY_SKIP_SETGID_CHECK=1 RELIQUARY_SKIP_SECCOMP=1

ACT_SOCK="$XDG_RUNTIME_DIR/reliquary/activation.socket"
OWN_SOCK="$XDG_RUNTIME_DIR/reliquary/socket"
STORE="/tmp/reliquary-sockact-store-$$"
ERR="/tmp/reliquary-sockact-err-$$"

cleanup() {
	kill "$pid" 2>/dev/null || true
	wait 2>/dev/null || true
	rm -rf "$STORE" "$ERR" "$ACT_SOCK" "$XDG_RUNTIME_DIR"
}
trap cleanup EXIT

python3 - "$ACT_SOCK" "$BIN" "$STORE" "$ERR" <<'PY' &
import os, socket, sys
sock_path, binpath, store, errpath = sys.argv[1:5]
try:
    os.unlink(sock_path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
s.listen(16)
# Hand the listening socket to the daemon as fd 3; dup2 clears CLOEXEC so it
# survives exec. Redirect the daemon's stderr to the capture file.
os.dup2(s.fileno(), 3)
os.set_inheritable(3, True)
err = os.open(errpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.dup2(err, 2)
os.environ["LISTEN_FDS"] = "1"
os.environ["LISTEN_PID"] = str(os.getpid())  # preserved across execv
os.execv(binpath, [binpath, "--store", store, "-vv"])
PY
pid=$!

# Wait for the daemon to announce it is serving the inherited socket.
for _ in $(seq 1 50); do
	grep -q "socket-activated" "$ERR" 2>/dev/null && break
	sleep 0.1
done

if ! grep -q "socket-activated" "$ERR" 2>/dev/null; then
	echo "FAIL: daemon did not adopt the inherited LISTEN_FDS socket"
	cat "$ERR" 2>/dev/null
	exit 1
fi

# With an inherited socket it must not have created its own default one.
if [ -S "$OWN_SOCK" ]; then
	echo "FAIL: daemon created its own socket despite activation"
	exit 1
fi

echo "ok: reliquaryd adopts an inherited LISTEN_FDS socket"
