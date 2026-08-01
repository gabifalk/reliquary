#!/bin/sh
# reliquary-scd-proxy is a libexec helper spawned by gpg-agent, never run
# interactively -- but --version/--help must work without a daemon socket
# so a build can be identified in bug reports. Both short-circuit before
# any connect attempt and exit 0.
set -e
BIN="${MESON_BUILD_ROOT:-build}/src/scd/reliquary-scd-proxy"

# --version prints the program name and a version, and exits 0 even with
# no daemon reachable.
out=$("$BIN" --version)
echo "$out" | grep -q "reliquary-scd-proxy" \
	|| { echo "FAIL: --version missing program name: $out"; exit 1; }
echo "$out" | grep -qE '[0-9]+\.[0-9]+\.[0-9]+' \
	|| { echo "FAIL: --version missing version number: $out"; exit 1; }

# --help and -h exit 0 and mention gpg-agent so the reader learns it is a
# backend, not a command to run by hand.
help=$("$BIN" --help)
echo "$help" | grep -qi "gpg-agent" \
	|| { echo "FAIL: --help does not mention gpg-agent: $help"; exit 1; }
"$BIN" -h >/dev/null

echo "ok: scd-proxy --version/--help"
