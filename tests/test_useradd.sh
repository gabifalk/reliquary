#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Integration test for reliquary-setup-user shell script

set -e

SCRIPT="$1"
if [ -z "$SCRIPT" ]; then
    echo "Usage: $0 <path-to-reliquary-setup-user>" >&2
    exit 1
fi

TMPDIR=$(mktemp -d /tmp/test_setup_XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0
TOTAL=0

run_test() {
    TOTAL=$((TOTAL + 1))
    printf "  %s ... " "$1"
}

ok() {
    PASS=$((PASS + 1))
    echo "ok"
}

fail() {
    FAIL=$((FAIL + 1))
    echo "FAIL: $1"
}

USERNAME=$(id -un)
UID_NUM=$(id -u)

# Test 1: create store for current user
run_test "create_for_current_user"
STORE="$TMPDIR/store1"
mkdir -p "$STORE"
# Override STORE_DIR by editing a temp copy of the script
TSCRIPT="$TMPDIR/setup"
sed "s|^STORE_DIR=.*|STORE_DIR=\"$STORE\"|; s|^GROUP=.*|GROUP=\"$(id -gn)\"|" "$SCRIPT" > "$TSCRIPT"
chmod +x "$TSCRIPT"

if "$TSCRIPT" "$USERNAME" >/dev/null 2>&1; then
    if [ -d "$STORE/$UID_NUM" ]; then
        ok
    else
        fail "directory not created"
    fi
else
    fail "script exited non-zero"
fi

# The per-uid dir must be owner-gated (0700) and owned by the user, so no other
# user's reliquaryd can enter it.
run_test "store_dir_owner_gated"
DMODE=$(stat -c '%a' "$STORE/$UID_NUM" 2>/dev/null || echo '?')
DOWNER=$(stat -c '%u' "$STORE/$UID_NUM" 2>/dev/null || echo '?')
if [ "$DMODE" = "700" ] && [ "$DOWNER" = "$UID_NUM" ]; then
    ok
else
    fail "store dir mode=$DMODE owner=$DOWNER, want 700 owned by $UID_NUM"
fi

# Test 2: duplicate creation fails
run_test "create_duplicate_fails"
if "$TSCRIPT" "$USERNAME" >/dev/null 2>&1; then
    fail "should have failed on duplicate"
else
    ok
fi

# Test 3: nonexistent user fails
run_test "nonexistent_user_fails"
if "$TSCRIPT" "nonexistent_user_xyzzy_12345" >/dev/null 2>&1; then
    fail "should have failed on nonexistent user"
else
    ok
fi

# Test 4: --help exits 0
run_test "help_flag"
if "$TSCRIPT" --help >/dev/null 2>&1; then
    ok
else
    fail "--help should exit 0"
fi

# Test 5: no args exits non-zero
run_test "no_args_fails"
if "$TSCRIPT" >/dev/null 2>&1; then
    fail "should have failed with no args"
else
    ok
fi

echo "test_setup:"
echo "$PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
