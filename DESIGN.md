# Reliquary -- Design Document

## Overview

Reliquary is a setgid daemon that provides hardware-security-module semantics in
software.  It holds private key material in files inaccessible to the invoking
user and exposes two standard interfaces for cryptographic operations over a
single Assuan Unix socket:

- A **PKCS#11 module** (thin stub `.so` that translates PKCS#11 calls to
  Assuan commands)
- A **GnuPG scdaemon-compatible interface** (OpenPGP card protocol via Assuan)

The daemon never exports stored private key material.  All private-key
operations happen inside the daemon process; callers receive only the
results.

---

## Motivation

SoftHSM2 is the standard software PKCS#11 token, but it runs as an in-process
library under the caller's UID.  The key files are readable by the user, and the
process memory is accessible via ptrace.  It provides no meaningful isolation.

Reliquary provides the missing privilege boundary in pure software, without
requiring a hardware token, a TPM, or a separate system account.

---

## Security Model

### Secure memory

Decrypted key material -- the per-token master key (MK), the Argon2id KEK
used only transiently to unwrap it, and each unlocked slot's decrypted
private key -- is allocated from libgcrypt's secure memory pool rather than
the regular heap. `crypto_init` (`crypto.c`) initializes the pool
(`GCRYCTL_INIT_SECMEM`, 64 KiB) and resumes secure-memory warnings
(`GCRYCTL_RESUME_SECMEM_WARN`).
`secure_alloc`/`secure_free` (`secmem.c`) wrap `gcry_malloc_secure` and
`gcry_free`, which back the allocation with `mlock`'d pages, and
`secure_free` explicitly zeroes (`explicit_bzero` where available) before
releasing. Secure-pool memory therefore cannot be paged to swap, closing
the one exposure that setgid's `ptrace`/core-dump protections (below) do
not.

### Privilege separation mechanism

The daemon binary is installed **setgid** to a dedicated group (e.g. `reliquary`).
Key storage directories and files are group-owned by `reliquary` with permission
bits that deny access to "other" (the invoking user).  See Key Storage for the
full permission layout.

This is enforced at runtime, not just assumed from installation: at startup
the daemon calls `verify_setgid()` (`main.c`), which requires `getegid()`
to equal the configured group's gid (`RELIQUARY_GROUP`, a build-time
default) and to differ from `getgid()` (the invoking user's real gid). A
plain `meson install` build, or any other way the setgid bit ends up
missing, fails this check; the daemon prints an error and `exit(1)`s rather
than serving with none of the isolation below -- **fail closed**, not a
warning. `RELIQUARY_SKIP_SETGID_CHECK` bypasses the check, with a printed
warning, strictly for dev/test harnesses that need to run an unprivileged,
non-setgid build; it is documented as not for production use. See Daemon
lifecycle for the full startup sequence.

### Kernel enforcement

When a setgid binary executes, the kernel sets `dumpable = 0` on the process.
This has the following concrete consequences, enforced by the kernel
independently of any daemon logic:

| Vector                                     | Status                                   |
|--------------------------------------------|------------------------------------------|
| `ptrace(PTRACE_ATTACH)` from owning UID    | `EPERM`                                  |
| `/proc/<pid>/mem` read from owning UID     | `EPERM`                                  |
| `/proc/<pid>/maps`                         | inaccessible                             |
| `gcore` / core dumps                       | suppressed                               |
| `LD_PRELOAD` / `LD_LIBRARY_PATH` injection | stripped by dynamic linker (`AT_SECURE`) |

The `AT_SECURE` aux vector entry is set by the kernel and causes the dynamic
linker to drop all environment-variable-based injection paths before `main()`
is reached.

### Runtime hardening

At startup, after the setgid self-check, the daemon calls
`prctl(PR_SET_DUMPABLE, 0)` -- an explicit reassertion; setgid execution
already sets `dumpable = 0` -- and `prctl(PR_SET_NO_NEW_PRIVS, 1)`, which
blocks the process (and anything it might exec) from gaining privileges it
does not already have. These are cheap, honest steps. There is no
capability dropping: a normal-user setgid process does not hold any extra
Linux capabilities to drop in the first place, so a "drops unnecessary
capabilities" claim would be vacuous.

**Build-level hardening.** The build (`meson.build`) sets the standard
exploit-mitigation flags explicitly rather than relying on the host
toolchain's defaults: PIE (full ASLR), full RELRO (`-z relro -z now`), a
non-executable stack, `-fstack-protector-strong`, `-fstack-clash-protection`,
control-flow protection (`-fcf-protection=full` on x86 / `-mbranch-protection`
on arm64), and `-Wformat-security`. Optimized (release/packaged) builds also
get `-D_FORTIFY_SOURCE=3`. Unsupported flags are filtered per compiler/arch, so
the set degrades gracefully. These do not stop a bug but raise the cost of
turning one in the daemon's input handling into code execution.

**Seccomp syscall filter.** Once the listening socket exists (so the one
legitimate `socket()`/`bind()` has already run) and before any client is
served, the daemon installs a seccomp-BPF filter via `seccomp_install()`
(`src/daemon/seccomp.c`), hand-rolled as a classic-BPF program with no
libseccomp dependency. The filter is inherited across `fork()`, so it covers
every connection-handling child.

It is a **denylist** (default `ALLOW`), not an allowlist: it targets syscalls
that are never legitimate here after startup, so a libc or libgcrypt update
that reaches for some new benign syscall cannot `SIGSYS` the daemon. Denied:
`execve`/`execveat` (no shell, no new programs), `socket`/`connect` (no
new or outbound sockets -- the listener already exists), `ptrace` and
`process_vm_readv`/`process_vm_writev`, and a set of exploitation and escape
primitives (`userfaultfd`, `bpf`, `open_by_handle_at`, the keyring calls,
kernel-module load/unload, and the namespace/mount calls). A denied call
kills the process (`SECCOMP_RET_KILL_PROCESS`), not returns an error.
Deliberately allowed: `clone`/`clone3` (the parent forks), `openat` (children
open key files -- path-based filtering is out of scope for classic
seccomp-BPF), and `sendmsg`/`recvmsg` (libassuan's I/O over the
already-connected socket).

Supported architectures are x86_64 and aarch64; the filter validates the
`seccomp_data.arch` field against the compiled target (and rejects the x32
ABI on x86_64) so a syscall issued under a different ABI cannot alias a denied
number. On an unsupported architecture or a kernel without seccomp,
`seccomp_install()` returns failure and the daemon **fails closed** -- it
refuses to start, exactly like the setgid self-check. `RELIQUARY_SKIP_SECCOMP`
bypasses the filter with a printed warning, for the same dev/test,
non-setgid harnesses as `RELIQUARY_SKIP_SETGID_CHECK`; not for production.

What the filter buys is **containment of a compromised daemon**, not
prevention of the initial compromise. If a memory-corruption bug in the
daemon's input handling (the Assuan command parsers, or the OpenSSH key
importer decoding attacker-supplied `openssh-key-v1` blobs) yields code
execution, `dumpable = 0` no longer helps -- the attacker is already inside
the address space and can read the decrypted keys directly. The filter then
denies the follow-on moves: spawning a shell or helper (`execve`), opening a
network channel to exfiltrate over (`socket`/`connect`), and the primitives
that turn a bug into a kernel privilege escalation that would escape the UID
boundary entirely. It does **not** stop an attacker who already controls the
client end of the connection (e.g. a local process that sent the malicious
import) from reading a key out of that child's memory and writing it back
over the socket it already holds; and it does not itself restrict filesystem
writes by path -- that is the Landlock layer below.

**Filesystem confinement (Landlock).** After the seccomp filter and before
serving, the daemon calls `landlock_confine()` (`src/daemon/landlock.c`),
another hand-rolled, dependency-free layer that restricts the process to its
own store subtree: read, write, create, delete, and rename **within**
`store_root` (the same `getuid()`-derived path the daemon serves), and no
pathname access anywhere else. Because `store_root` is fixed at startup, this
is applied **once in the parent**, before the accept loop, and inherited
across `fork()` by every child; already-open descriptors (the listening
socket, the client connection) keep working, since Landlock is pathname-based.
The handled rights are masked to the kernel's Landlock ABI (`REFER` needs ABI
2 for `meta.c`'s temp-then-rename, `TRUNCATE` needs ABI 3 for rewriting an
existing file), so an older kernel gets a valid subset rather than a failure.

This closes the path-based exfiltration that seccomp cannot: a compromised
daemon has nowhere user-readable to drop a stolen key, because the only
writable path is the store subtree, which is itself `0700`/`0600` and
unreadable by the user. Unlike the setgid check and the seccomp filter,
Landlock is applied **best effort**: on a kernel without it (pre-5.13, or
Landlock not in the active LSM stack) the daemon logs a warning and continues,
because the owner-gated store directory (see Isolation model) already enforces
per-user isolation through DAC -- Landlock is defense in depth on top of that
boundary, not the boundary itself. `RELIQUARY_SKIP_LANDLOCK` bypasses it for
dev/test, matching the other two escape hatches.

### Isolation model

Isolation is per-user, enforced by the kernel at the socket and the
filesystem, not by any in-daemon table of connections. A daemon instance
belongs to exactly one user -- the account it runs as -- and can reach
exactly one store, that user's:

- Each user reaches the daemon over their own Unix socket at
  `$XDG_RUNTIME_DIR/reliquary/socket` (parent directory and socket both
  mode 0700), so only that UID can connect at all.
- The store path is derived from the daemon's **own** uid (`getuid()`),
  never from a value supplied by the peer:
  `/var/lib/reliquary/<getuid()>/`. The daemon has no code path that even
  names another user's store.
- `SO_PEERCRED` is still read on every connection, now as a guard: the peer
  uid must equal `getuid()`, or the connection is refused. Anyone else who
  reaches the socket -- root traversing into the runtime dir, a
  mis-permissioned socket -- is rejected rather than served the owner's keys.
  If `getsockopt(SO_PEERCRED)` fails, the connection is closed -- fail closed.

Two independent DAC gates back this up, using two different levers because
the daemon and its user share a uid (setgid changes only the gid):

- **User vs. their own daemon** -- the store root `/var/lib/reliquary/`
  (`root:reliquary 0710`) grants the `reliquary` group traverse (`--x`) but
  not read: a daemon can resolve its own known `<uid>/` path, but cannot
  `readdir` the root to enumerate who else has a store (a specific uid's
  existence is still probeable via `stat`, but not the whole list). The
  user is "other" and cannot enter; the daemon enters via its setgid
  `reliquary` egid. The shared group is the lever here, and its being shared
  is fine: this gate governs only entry to the store area, identically for
  every daemon.
- **One user's daemon vs. another's store** -- each per-uid directory
  `/var/lib/reliquary/<uid>/` is `<uid>:reliquary 0700`, owner-gated. The
  only DAC lever distinguishing alice's daemon from bob's (both setgid
  `reliquary`) is the owner: alice's daemon has `euid=alice` and enters her
  own dir as owner, but is "other" to bob's `0700` dir and is denied
  outright. This makes "never another user's keys" a kernel-enforced
  property, not merely a matter of careful path construction.

The peer check and store derivation happen once, at `accept()`/`fork()`
time; there is no per-command re-check, and none is needed -- the socket,
the `getuid()` derivation, and the owner-gated directory each independently
scope a daemon to its one user.

### Threat model

**Protected against:**

- Direct filesystem reads of key material by the invoking user or any process
  running under their UID
- ptrace-based memory extraction from the daemon
- Shared-library injection via `LD_PRELOAD`
- Swap-based extraction of decrypted keys and the master key (secure
  memory is `mlock`'d)
- Accidental exfiltration by backup tools, sync daemons, or scripts that
  vacuum `$HOME`
- `git add -A` accidents
- Escalation of a daemon-side code-execution bug into shell/program execution
  or network exfiltration, and a narrower kernel attack surface for a UID-
  escaping privilege escalation (seccomp syscall denylist; see Runtime
  hardening)
- One user's daemon reaching another user's keys -- denied by the owner-gated
  per-uid store directory (DAC) and the `getuid()`-derived store path (see
  Isolation model)
- Path-based exfiltration or tampering by a compromised daemon writing outside
  its own store -- confined by Landlock where available (best effort; see
  Runtime hardening)

**Not protected against:**

- A kernel vulnerability that specifically bypasses the `dumpable` check
- An attacker with `CAP_SYS_PTRACE` or root
- Side-channel attacks on the cryptographic operations themselves
- Compromise of the daemon binary itself (supply-chain / binary replacement)
- Exfiltration of a key already resident in a compromised daemon child over
  the client connection that child already holds -- the seccomp and Landlock
  layers restrict syscalls and pathnames, not access to the process's own
  memory or a descriptor it already has open

### What this is not

Reliquary does not attempt to provide tamper-evidence, remote attestation, or
protection against a privileged attacker.  It provides a well-defined UID
boundary using standard kernel mechanisms.  If you need stronger guarantees,
use hardware.

---

## Architecture

```
  User process                   reliquary daemon (sgid)
  ------------------             --------------------------------------
  reliquary-pkcs11.so -+
  (PKCS#11 stub)       +-- Unix --> listener (Assuan protocol)
                       |   socket       |
  reliquary-scd-proxy -+                +- PKCS#11 command handler
  (for gpg-agent)                       +- scdaemon command handler
                                        +- session management
                                        +- key store (encrypted at rest)
                                        `- crypto backend (libgcrypt)

  Socket
  ------------------------------
  $XDG_RUNTIME_DIR/reliquary/socket

  Filesystem
  ------------------------------
  /var/lib/reliquary/                    root:reliquary  0710
      <uid>/                             <uid>:reliquary  0700
          <token-label>/                 <uid>:reliquary  0700
              metadata                   <uid>:reliquary  0600
              keywrap, *.key.enc         <uid>:reliquary  0600
```

All clients connect to a single Unix socket speaking the Assuan protocol
(via libassuan).  The daemon dispatches by command name: scdaemon clients
send `SERIALNO`, `PKSIGN`, etc.; PKCS#11 stub clients send `OPEN_SESSION`,
`LOGIN`, `SIGN`, etc.  The daemon's parent process only accepts connections
and `fork()`s a child per connection; each child owns one client's session
state end-to-end, so concurrent clients are isolated by process, not by any
shared in-daemon table.

### Daemon lifecycle

**Startup checks.** The daemon requires `$XDG_RUNTIME_DIR` to be set and
refuses to start without it. It then verifies it is actually running setgid
to the configured group (`RELIQUARY_GROUP`, a build-time default, e.g.
`reliquary`): `getegid()` must equal that group's gid and must differ from
`getgid()` (the invoking user's real gid). If this check fails, the daemon
prints an error and exits(1) instead of serving without the kernel-enforced
isolation described in Security Model -- **fail closed**, not a warning. A
`RELIQUARY_SKIP_SETGID_CHECK` environment variable bypasses the check (with a
printed warning) so dev/test harnesses can run an unprivileged, non-setgid
build; it is not for production use.

**Launch modes.** The daemon supports two ways to obtain its listening
socket:

- **systemd user socket activation** (preferred): the `reliquary.socket`
  user unit binds `$XDG_RUNTIME_DIR/reliquary/socket` and systemd passes the
  already-listening fd to the daemon via `LISTEN_FDS`/`LISTEN_PID` on first
  connection. The daemon recognizes this (`LISTEN_PID` matches its own pid,
  `LISTEN_FDS >= 1`) and uses fd 3 (`SD_LISTEN_FDS_START`) directly, skipping
  its own `bind`/`listen`.
- **Manual start**: run `reliquaryd` directly. It creates, binds (mode 0700),
  and listens on the Unix socket itself at
  `$XDG_RUNTIME_DIR/reliquary/socket`.

Clients never start the daemon themselves: `reliquary-pkcs11.so` and
`reliquary-scd-proxy` only connect to an existing socket and fail if nothing
is listening. Making the daemon available -- via systemd socket activation or
a manual start -- is the caller's or administrator's responsibility.

**Lifetime.** The daemon runs until it is stopped or killed. Under socket
activation, `reliquary.socket` starts it lazily on the first connection.

### Components

**`reliquaryd`** -- the daemon. Runs setgid `reliquary` (self-checked at
startup as above). Listens on a single Unix socket at
`$XDG_RUNTIME_DIR/reliquary/socket`, speaking the Assuan protocol for all
interfaces.

Process model is **fork-per-connection**: the parent `poll()`s the listening
socket and, on each accepted connection, reads the peer uid via `SO_PEERCRED`
and `fork()`s a child to handle that connection to completion; the child
exits when the client disconnects. The parent reaps finished children via a
`SIGCHLD` handler. If `SO_PEERCRED` fails, the daemon closes the connection
immediately rather than falling back to any other identity source -- the
peer-identity check fails closed.

**`reliquary-pkcs11.so`** -- a PKCS#11 module (`CK_FUNCTION_LIST`-compatible) that
contains no crypto logic.  Every PKCS#11 call is serialised into an Assuan
command and forwarded over the Unix socket to the daemon.  Installed
world-readable; not setgid itself.

**`reliquary-scd-proxy`** -- a small wrapper that `gpg-agent` invokes as its
`scdaemon-program`.  Connects to the same daemon socket and speaks the
scdaemon subset of Assuan commands.

**`reliquary-setup-user`** -- root-only admin utility.  Creates the per-uid
directory under `/var/lib/reliquary/`.  Run once per user during provisioning.
Not setgid; requires root.

**`reliquary-tool`** -- user-facing CLI.  Connects to the daemon socket and
sends administrative Assuan commands (`CREATE_TOKEN`, `IMPORT_SLOT`,
`CHANGE_PIN`, etc.).  Not setgid itself -- all privileged filesystem operations
are performed by the daemon.  Not needed at runtime.

### Logging

The daemon is **silent by default**. Verbosity is raised with the `-v` or
`-vv` command-line flag on `reliquaryd`, or by setting the `RELIQUARY_DEBUG=1`
or `RELIQUARY_DEBUG=2` environment variable. The effective debug level is the
maximum of the two (CLI vs. environment), so socket-activated deployments can
raise verbosity via an `Environment=` or `EnvironmentFile=` line in the systemd
service unit without editing the `ExecStart` directive. The shipped user unit
reads an optional `~/.config/reliquary/environment`.

Two debug levels follow the OpenSSH convention:

- **debug1** traces connection lifecycle (accept, fork, peer check), login
  attempts (result only; PIN/passphrase are never logged), crypto operations
  (verb/mechanism/slot/key algorithm and result), and token mutations
  (slot population, PIN change, token visibility toggles). Errors and warnings
  print at all debug levels.
- **debug2** adds payload sizes (data input to sign/decrypt, output signature
  sizes) and protocol detail (Assuan command and status line traces).

Output is written to **stderr** via a single `write(2)` call per line. Under
the systemd user service, stderr flows to the journal; standalone (or with
`stdio-to-file`), it reaches the terminal or a log file. The daemon
deliberately does **not** use syslog: the seccomp filter (see Runtime hardening
above) is a denylist that `KILL_PROCESS`es `socket()` and `connect()` syscalls,
and glibc's `syslog()` function reopens its connection to `/dev/log` on every
call (and again after journald restarts), which would `SIGSYS` the daemon.
Making the syslog path robust would require re-allowing `socket()`/`connect()`,
which reopens the exfiltration channel the filter exists to block. Routing logs
to stderr reaches the same journal without that cost.

**Hard invariant:** the log never contains secret material. No PINs, private-key
bytes, plaintext payloads, ciphertexts, or derived values are logged. Log
call-sites pass only public identifiers (slot indices, mechanism names, token
labels, keygrips) and lengths (payload sizes). This invariant is enforced by
code review and by the `tests/test_secret_safety.c` regression test.

---

## Interfaces

The daemon registers 34 Assuan commands total (`src/daemon/server.c`), split
across a PKCS#11-mapped surface, an OpenPGP-card (scdaemon) surface, and a
handful of admin/write commands shared by both faces (`CREATE_TOKEN`,
`GENKEY`, `IMPORT_SLOT`, `DELETE_TOKEN`, `CLEAR_TOKEN`, `CHANGE_PIN`,
`CONNECT_TOKEN`, `DISCONNECT_TOKEN`, `INIT_STORE`, `STORE_STATUS`), plus `NOP`.
Full per-command wire syntax is in the Wire Protocol section below.

### PKCS#11 (via `reliquary-pkcs11.so`)

Standard PKCS#11 v3.0.  The stub implements `C_GetFunctionList` and forwards
all calls to the daemon.  Session handles are local to the stub and mapped to
daemon-side sessions over the socket.

Supported mechanisms:

- `CKM_RSA_PKCS` -- sign, decrypt
- `CKM_RSA_PKCS_PSS` -- sign (SHA-256 hash/MGF only; any other requested hash
  or MGF is rejected with `CKR_MECHANISM_PARAM_INVALID` rather than silently
  signed under the wrong hash)
- `CKM_RSA_PKCS_OAEP` -- decrypt (SHA-256 only, same rejection policy)
- `CKM_ECDSA` -- sign (NIST P-256/P-384/P-521)
- `CKM_EDDSA` -- sign (Ed25519, PureEdDSA over the raw message)
- `CKM_ECDH1_DERIVE` -- derive (`C_DeriveKey` is implemented in
  `libreliquary.c`, not a stub: it wraps the peer EC point from
  `CK_ECDH1_DERIVE_PARAMS` into the S-expression the daemon's `DERIVE` command
  expects, and materializes the returned shared secret as a session
  `CKO_SECRET_KEY` object)

The module's `C_GetMechanismList` queries the daemon's `GET_MECHANISM_LIST`
rather than returning a hardcoded array, so the daemon is the single source of
truth for the supported-mechanism set.  On the wire, the daemon names these
mechanisms with its own operation-qualified, adapter-neutral tokens (e.g.
`sign.rsa-pss`, `decrypt.rsa-oaep`, `derive.ecdh`) rather than PKCS#11's
numeric `CKM_*` constants; `reliquary-pkcs11.so` and `reliquary-scd-proxy` each
translate between their respective client-facing vocabulary and these tokens
(see Wire Protocol below).

Minimum RSA key size is 2048 bits: both `GENKEY` and key import reject RSA
keys below 2048 bits, and `C_GetMechanismInfo` advertises 2048 bits as the
minimum.

Key generation and import are reachable only through the daemon's
session-authenticated write commands (`GENKEY`, `IMPORT_SLOT`, and, for the
scdaemon face, `WRITEKEY`/keytocard) -- not through the PKCS#11
`C_GenerateKeyPair` or `C_CreateObject` interfaces, which remain unimplemented.
This keeps the PKCS#11 client-facing surface read/sign/decrypt/derive-only,
even though the daemon itself has a write surface used by `reliquary-tool` and
`gpg-agent` keytocard.

Each token's `CK_TOKEN_INFO.serialNumber` is populated from the same
per-token serial the daemon assigns and the scdaemon face exposes via
`SERIALNO` (fetched via `GET_ATTRIBUTE serial` during slot enumeration and
cached in `reliquary-pkcs11.so`'s slot table) -- distinct per token, not a fixed
placeholder, so a `pkcs11:serial=...` URI or serial-based token selection
resolves to the correct token.

### OpenPGP card / scdaemon commands

The daemon presents each token as a **writable, PIN-gated virtual OpenPGP
card** on the same socket as PKCS#11 commands, with keytocard and attribute
writes accepted rather than only ever answering read requests.
`gpg-agent` connects via `reliquary-scd-proxy`:

- `SERIALNO [--demand=<serial>]` -- returns the current token's per-token
  serial number; with `--demand=<serial>` it switches the session to that
  token first (like `SWITCHCARD`), which is how `gpg --card-status` selects
  each card when enumerating multiple tokens
- `LEARN` -- returns `KEYPAIRINFO`/`KEY-FPR`/`KEY-TIME`/`KEY-ATTR` for all
  slots plus capability flags
- `READKEY <keygrip | OPENPGP.N>` -- returns the public key S-expression
- `PKSIGN` -- sign with the signing-slot key (or the key matching a keygrip
  the proxy appends, auto-switching tokens if needed)
- `PKAUTH` -- sign with the authentication-slot key (used for SSH
  authentication through `gpg-agent`)
- `PKDECRYPT` -- decrypt with the encryption-slot key
- `GETATTR <attr>` -- returns card attributes: `SERIALNO`, `DISP-NAME`,
  `KEY-FPR`, `KEY-TIME`, `KEY-ATTR`, `APPTYPE`, `EXTCAP`, `CHV-STATUS`,
  `$SIGNKEYID`/`$ENCRKEYID`/`$AUTHKEYID`
- `SETATTR KEY-FPR <slot> <hex>` / `SETATTR KEY-TIME <slot> <ts>` -- **persisted**
  to the token's metadata (`m.key_fpr_hex[]`/`m.key_time[]` in
  `cmd_scdaemon.c`), so `gpg --card-status`/`gpg --edit-card` fingerprint and
  timestamp updates stick; `SETATTR KEY-ATTR` is accepted as a no-op (the
  algorithm is derived from the stored key itself, not settable)
- `WRITEKEY [--force] <keyid>` -- keytocard: receives a private key via
  `INQUIRE KEYDATA` and writes it into the addressed slot.  PIN-gated: uses
  the session's cached master key if already logged in, otherwise prompts via
  a `NEEDPIN` inquiry and unwraps through the same throttled token-PIN path as
  `LOGIN`
- `KEYINFO [--list] [<keygrip>]` -- enumerates keygrip -> serial/slot
  mappings across *all* tokens in the store, so `gpg-agent` can map a keygrip
  to a card and `SWITCHCARD` to it
- `CHECKPIN` -- verifies the token PIN (via `NEEDPIN` inquiry, throttled
  identically to `LOGIN`) and caches the unwrapped master key in the session
  for a subsequent `WRITEKEY`
- `SWITCHCARD [serial]` -- switch the session to the token with the given
  serial, or report the current token's serial if none is given
- `GETINFO card_list` -- emit a `SERIALNO` status line for every known token

`CONNECT_TOKEN <label>` / `DISCONNECT_TOKEN <label>` toggle a token's
visibility in enumeration (`LIST_TOKENS`, scdaemon auto-open/`GETINFO
card_list`).  These are deliberately **not** PIN- or credential-gated: hiding
a token exposes no key material, and the daemon is already scoped to one
UID's store, so visibility is a convenience toggle rather than an access
control.

Key slot mapping follows the OpenPGP card convention: slot 0 = signing
(`OPENPGP.1`), slot 1 = encryption (`OPENPGP.2`), slot 2 = authentication
(`OPENPGP.3`).  Multiple tokens are presented as separate virtual cards with
distinct serial numbers.

To use Reliquary as the scdaemon backend, add to `~/.gnupg/gpg-agent.conf`:

```
scdaemon-program /usr/libexec/reliquary/reliquary-scd-proxy
```

### SSH key import

`reliquary-tool import-ssh <label> [slot] <keyfile>` imports an existing
OpenSSH private key file directly into a token slot (default: a new token's
`auth` slot, matching `ssh-agent`-via-`gpg-agent` usage).  Decoding
`openssh-key-v1` format -- including passphrase-encrypted keys, which use
bcrypt's KDF over AES -- is done with vendored, byte-identical OpenBSD
sources: `src/bundled/blf.h`/`blowfish.c` (Blowfish cipher) and
`src/bundled/bcrypt_pbkdf.c` (`bcrypt_pbkdf(3)`), built against libgcrypt via
small Reliquary-authored shims (`src/bundled/includes.h`, `crypto_api.h`,
`crypto_shim.c`; see `src/bundled/README`).  The imported key is reachable
afterward through the normal auth-slot path: PKCS#11 `SIGN`/SSH agent
protocol via the module, or the scdaemon `PKAUTH` command for `gpg-agent`
SSH support.

---

## Wire Protocol

All communication uses the **Assuan protocol** (via libassuan) over the single
Unix socket.  Assuan is a text-based, line-oriented command-response protocol
used throughout the GnuPG stack.  Both PKCS#11 stub commands and scdaemon
commands share the same socket, dispatched by command name.  Binary crypto
payloads are **raw** on both faces: the PKCS#11 `SIGN`/`DECRYPT`/`DERIVE`
commands receive their input out-of-band via an `INQUIRE` and return the raw
result, matching the scdaemon face -- which likewise sends and receives raw
binary (public-key S-expressions, signatures, decrypted plaintext) as
`gpg-agent` expects from a real card driver.  Public-key and attribute values
in the PKCS#11 `GET_ATTRIBUTE` replies remain hex-encoded.

### PKCS#11-mapped Assuan commands

- `OPEN_SESSION <token-label>` -- open a session to a token
- `CLOSE_SESSION` -- close the current session
- `LOGIN <pin>` -- unlock the token (equivalent to `C_Login`); throttled by
  the token's PIN retry counter and lockout
- `LOGOUT` -- lock the token and zero key material
- `SIGN <slot> <mechanism>` -- sign with the slot's private key; `mechanism`
  is one of `sign.rsa-pkcs1`, `sign.rsa-pss`, `sign.ecdsa`, `sign.eddsa`; the
  data to sign is sent out-of-band via `INQUIRE VALUE` (raw binary)
- `DECRYPT <slot> <mechanism>` -- decrypt with the slot's private key;
  `mechanism` is one of `decrypt.rsa-pkcs1`, `decrypt.rsa-oaep`,
  `decrypt.rsa-raw`; the ciphertext is sent via `INQUIRE CIPHERTEXT` (raw
  binary)
- `DERIVE <slot> <mechanism>` -- ECDH key derivation (`derive.ecdh` only);
  the peer public key is sent via `INQUIRE PEERKEY` (raw binary)
- `LIST_TOKENS` -- enumerate tokens; one status line per token,
  `S TOKEN <serial> <label> <connected|disconnected>`
- `GET_MECHANISM_LIST` -- list supported mechanisms (authoritative; see
  Interfaces above)
- `GET_ATTRIBUTE <attribute>` -- attribute-only, no object handle: `label`,
  `algorithm`, `algorithm.<slot>`, `public_key`, `public_key.<slot>`,
  `created_at`, `serial`
- `STORE_STATUS` -- fails with not-initialized unless the per-uid store's
  `config` exists
- `INIT_STORE <admin-pin>` -- first-time store initialization; sets the admin
  PIN, fails if already initialized
- `CREATE_TOKEN <label> <pin> <admin-pin>` -- create an empty token (no keys);
  mints the token's master key and PIN-wraps it
- `GENKEY <slot> <algorithm>` -- requires `LOGIN`; generate a key in a slot.
  `algorithm` is one of `rsa2048`, `rsa3072`, `rsa4096`, `nistp256`,
  `nistp384`, `nistp521`, `ed25519`
- `IMPORT_SLOT <slot>` -- requires `LOGIN`; store a caller-supplied private
  key S-expression into a slot (sent out-of-band via `INQUIRE KEYDATA`,
  algorithm auto-detected). A key whose algorithm is not one the daemon
  supports is rejected with `GPG_ERR_NOT_SUPPORTED` before anything is
  written, rather than stored under a substitute algorithm -- the same
  fail-closed detection guards the scdaemon `WRITEKEY`/keytocard path,
  which shares this store routine.
- `DELETE_TOKEN <label> <admin-pin>` -- remove a token entirely
- `CLEAR_TOKEN <label> <admin-pin>` -- wipe a token's key slots, keep the
  token shell
- `CHANGE_PIN <new-pin>` -- requires `LOGIN`; rewraps the master key under the
  new PIN only (slot key files are unchanged, O(1))
- `CONNECT_TOKEN <label>` / `DISCONNECT_TOKEN <label>` -- visibility toggles
  (see Interfaces above); no PIN required

### scdaemon Assuan commands

`SERIALNO`, `LEARN`, `READKEY`, `PKSIGN`, `PKAUTH`, `PKDECRYPT`, `GETATTR`,
`SETATTR`, `WRITEKEY`, `KEYINFO`, `CHECKPIN`, `SWITCHCARD`, `GETINFO`.  See
the Interfaces section above for each command's syntax and semantics.

### Shared commands

`NOP` -- no-op, used for connection liveness checks.

### Authentication

The store served is the daemon's own uid's subtree (`getuid()`); the daemon
reads `SO_PEERCRED` on every connection and refuses any peer whose uid is not
that same owner.  No additional authentication beyond this; PIN entry is
handled via the `LOGIN` command (PKCS#11) or pinentry/`NEEDPIN` inquiries
(scdaemon).

---

## Key Storage

### Directory layout

Each user gets an isolated subtree under `/var/lib/reliquary/`:

```
/var/lib/reliquary/                    root:reliquary  0710
    1000/                              1000:reliquary  0700
        config                         1000:reliquary  0600
        admin-state                    1000:reliquary  0600
        work-signing/                  1000:reliquary  0700
            metadata                   1000:reliquary  0600
            state                      1000:reliquary  0600
            keywrap                    1000:reliquary  0600
            sign.key.enc               1000:reliquary  0600   (if populated)
            encrypt.key.enc            1000:reliquary  0600   (if populated)
            auth.key.enc               1000:reliquary  0600   (if populated)
        personal-encrypt/              1000:reliquary  0700
            ...
    1001/                              1001:reliquary  0700
        ...
```

`config` and `admin-state` live at the per-uid store root, not inside a
token directory -- they hold the admin PIN verifier and its retry counter
respectively (see PIN Handling), which are store-wide, not per-token.
`config` also holds the next-serial counter used to assign each new
token's `serial` field in `metadata`.

Ownership rationale (two gates, two levers -- see Isolation model):

- `/var/lib/reliquary/` is `root:reliquary 0710`.  The reliquary group has
  traverse (`--x`) but not read, so a daemon reaches its own known `<uid>/`
  path yet cannot list the root to enumerate other users' stores; the
  invoking user is not a member of `reliquary`, is "other", and gets no
  access at all.  This gate separates a user from their own daemon.

- The per-uid directory is `<uid>:reliquary 0700`, owned by the user and
  owner-gated.  The user's own daemon (`euid=user`) enters as owner and
  creates token subdirectories inside it; any *other* user's daemon -- also
  setgid `reliquary`, but with a different euid -- is "other" here and is
  denied entry outright.  This gate separates one user's daemon from another's
  store.  The user themselves cannot reach the dir either, being blocked one
  level up by the `0710` store root.

- Token subdirectories are `0700` and files are `0600`, both owned by the
  user and created by the daemon running as `uid=user gid=reliquary`.  The
  daemon sets `umask(0077)` at startup, so these modes hold regardless of the
  umask it inherited.  Group and other get nothing; access is by owner only,
  which is the daemon.

- Independently of these filesystem gates, the daemon derives the served
  store from `getuid()` and refuses any peer whose `SO_PEERCRED` uid is not
  that same owner, so the subtree it serves is fixed to its own user.

The per-uid directory is created by `reliquary-setup-user <username>`, run by
root.  It resolves the username to a UID and creates `/var/lib/reliquary/<uid>/`
owned `<uid>:reliquary` mode `0700`.  This is a one-time operation per user.
All subsequent operations -- creating tokens, rotating PINs -- are performed by
the sgid daemon with no further root involvement.

### Encryption at rest

Keys are stored encrypted, using a per-token **master-key envelope**
(LUKS/age-style) rather than encrypting each key directly under a
PIN-derived key. Each token gets a random 256-bit master key (MK),
generated once at token creation; MK encrypts the token's key slots, and
the PIN only wraps MK. This means:

- Key files at rest (e.g. in a backup) are useless without the PIN
- The daemon does not hold the PIN after session logout; it holds only MK
  and the decrypted per-slot keys, in secure memory, for the duration of
  the session (see Security Model)
- PIN verification is done by attempting to unwrap MK; there is no
  separate PIN hash stored for the token PIN (see PIN Handling for how
  this differs for the admin PIN)
- Rotating the PIN (`CHANGE_PIN`) only has to re-wrap MK, not re-encrypt
  every key slot

File layout per token:

```
keywrap:
  [16 bytes] Argon2id salt
  [12 bytes] AES-256-GCM nonce
  [32 bytes] AES-256-GCM ciphertext (the wrapped master key, MK)
  [16 bytes] AES-256-GCM authentication tag

sign.key.enc / encrypt.key.enc / auth.key.enc   (one file per populated slot)
  [12 bytes] AES-256-GCM nonce
  [N bytes]  AES-256-GCM ciphertext (private key S-expression)
  [16 bytes] AES-256-GCM authentication tag
```

`keywrap` is present from token creation, before any key slot is
populated -- `KEK = Argon2id(PIN, salt)` wraps MK the same way regardless
of whether the token holds keys yet. The slot files use MK directly as the
AES-256-GCM key: there is no per-slot KDF, so slot encryption/decryption
does not repeat the (deliberately expensive) Argon2id step.

`state` holds per-token mutable state that is not really "metadata": the
live PIN retry counter and the scdaemon `CONNECT_TOKEN`/`DISCONNECT_TOKEN`
visibility toggle (see PIN Handling and Wire Protocol). `metadata` (format
version 2) holds the token's serial number, label, creation timestamp, and
the configured `pin-max-retries` as header fields, written once at creation
and never modified afterward. `metadata` also holds per-slot algorithm,
public-key, fingerprint, and key-time fields; unlike the header fields,
these are written whenever a slot is populated (`GENKEY`, `IMPORT_SLOT`, or
`WRITEKEY`) and can be updated afterward by `SETATTR KEY-FPR`/`SETATTR
KEY-TIME` (see Interfaces). None of it is secret (`metadata` carries no PIN
material of any kind, unlike the store-level admin PIN verifier described
in PIN Handling). The public key and any associated certificate are
exposed unencrypted via `metadata` (they are not secret).

---

## PIN Handling

Reliquary uses two distinct PINs:

- The **token PIN** unlocks one specific token for signing/decryption. It
  is solicited via the standard GnuPG pinentry mechanism through the
  Assuan scdaemon interface, or passed by the calling application as the
  `C_Login` PIN over the PKCS#11 interface; either way it is forwarded to
  the daemon over the socket.
- The **admin PIN** authorizes store-management operations (`CREATE_TOKEN`,
  key generation/import, deletion): a separate credential from the token
  PIN, so that day-to-day token use does not also grant the ability to
  mint or delete tokens.

### Token PIN: verify by unwrapping

There is no separate stored hash for the token PIN. Verification is
verify-by-unwrap: the daemon derives a KEK from the candidate PIN via
Argon2id and attempts to AES-256-GCM-decrypt the token's `keywrap` file
(see Key Storage); the AEAD authentication tag on that decryption *is* the
PIN check -- a wrong PIN fails the tag check, a correct PIN yields the
master key MK. Because `keywrap` exists from the moment a token is
created, this works uniformly even for an "empty" token with no key slots
populated yet.

This logic lives in `pin_unwrap_mk()` (`pin.c`), a single throttled helper
used by every daemon path that takes a token PIN: `LOGIN`, `CHECKPIN`, and
`WRITEKEY` (which needs MK to seal a freshly received key into a slot when
the caller is not already logged in). `pin_unwrap_mk` owns both the
lockout check and the retry-counter bookkeeping, so none of these three
paths is an unthrottled brute-force oracle.

The token PIN retry counter lives in the per-token `state` file
(`(state (pin-retries N) (disconnected 0|1))`), not in `metadata`:
`state` changes on every attempt, while `metadata`'s `pin-max-retries`
header field is written once at token creation and never changes -- it is
the only `metadata` field relevant here (the per-slot fields in `metadata`
do change later, via key population and `SETATTR`, but that is orthogonal
to PIN retry bookkeeping).
A wrong PIN decrements `pin-retries`; at 0 the token is locked and even the
correct PIN is then rejected. A correct PIN resets `pin-retries` back to
the token's `pin-max-retries` (default 3).

`CHANGE_PIN` re-wraps MK under the new PIN only (`keywrap_rewrap`) and
resets the retry counter. Because the key slots are encrypted under MK
rather than under a PIN-derived key, they are untouched by a PIN change --
an O(1) re-wrap rather than a rewrite of every populated slot.

### Admin PIN: separate verifier, own lockout

Unlike the token PIN, the admin PIN keeps a stored Argon2id verifier
(`admin-pin-salt`/`admin-pin-hash` in the store's `config` file, written by
`INIT_STORE`) -- a deliberate choice, not an oversight: the admin PIN's
only job is authorizing an online operation, and an offline attacker who
already has the store files gains nothing from cracking it that file
possession did not already grant. `verify_admin_pin` (`cmd_admin.c`)
compares the Argon2id hash of the candidate PIN against the stored hash in
constant time.

The admin PIN has its own retry counter, persisted separately from token
state in `<store>/admin-state` (`(admin-state (retries N))`, default max
3), decremented on mismatch and reset to the max on success; reaching 0
locks out even the correct admin PIN until an admin resets the counter (via
a successful verification before it hits zero -- there is no separate
unlock path). A missing or unparseable `admin-state` file fails open to
the maximum retry count, so a corrupted counter file cannot itself
permanently lock the store; a legitimate 0 written by a prior decrement is
still honored and still locks.

### Session key material

The daemon holds the master key and each unlocked slot's decrypted private
key in secure, `mlock`'d memory (see Security Model) for the duration of a
logged-in session. On `C_Logout`/`LOGOUT` (PKCS#11) or session close, all
of it -- MK and every populated slot key -- is explicitly zeroed before
being freed.

---

## Non-Goals

- **No key escrow or backup mechanism.**  Private keys are never exported.
  (An ECDH-derived shared secret IS returned to the caller as an
  extractable `CKO_SECRET_KEY` session object via `C_DeriveKey` -- that is
  the required ECDH behavior, not private-key export; the stored private
  key itself never leaves the daemon.)  Back up the token's directory
  (`keywrap` and its `*.key.enc` slot files) and remember your PIN.
- **No multi-user sharing.**  One daemon instance per user session.
- **No network interface.**  Unix sockets only; the daemon does not listen on
  TCP.
- **No FIPS compliance claims.**
- **No protection against root.**  Root can always read the key files.
- **No GUI.**  PIN entry delegates to whatever pinentry binary gpg-agent is
  configured to use.

---

## Bootstrapping and Installation

The daemon binary must be installed with the correct ownership before first
use:

```sh
# As root, during package install or initial setup:
groupadd -r reliquary
chown root:reliquary /usr/bin/reliquaryd
chmod 2755 /usr/bin/reliquaryd          # setgid bit
install -d -o root -g reliquary -m 710 /var/lib/reliquary
```

To provision a user:

```sh
# As root:
reliquary-setup-user alice
```

This creates `/var/lib/reliquary/<uid>/` owned `<uid>:reliquary` mode `0700`.
It is a one-time operation per user, analogous to `useradd` itself.  No root
shell is required after this point.  All subsequent token operations (create,
delete, PIN change) are handled by the sgid daemon via `reliquary-tool`.

---

*Last updated: 2026-07-30*
