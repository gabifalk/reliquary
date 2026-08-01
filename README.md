<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Reliquary

**A software HSM with a real privilege boundary.** Reliquary is a setgid
daemon that holds your private keys in files you cannot read, and performs
signing and decryption on your behalf without ever handing the raw key back.
It speaks two standard protocols over one socket, so existing tools use it
unmodified: a **PKCS#11** module and a **GnuPG scdaemon** (OpenPGP card)
interface.

Think of it as a smartcard emulated in software -- the key goes in, results
come out, and the secret material never leaves the daemon.

## Why

The usual software PKCS#11 token, SoftHSM2, runs as an in-process library
under your own UID. Its key files are readable by you, and its memory is
open to `ptrace` -- it provides no isolation from the account that uses it.

Reliquary supplies the missing boundary in pure software, with no hardware
token, TPM, or dedicated system account required:

- The daemon binary is **setgid** to a dedicated `reliquary` group, and key
  files live under a store directory the invoking user cannot traverse.
- Because the process is setgid, the kernel sets `dumpable = 0`, which blocks
  `ptrace(PTRACE_ATTACH)`, `/proc/<pid>/mem` reads, core dumps, and
  `LD_PRELOAD`/`LD_LIBRARY_PATH` injection -- enforced by the kernel, not by
  daemon logic.
- Keys are **encrypted at rest** with AES-256-GCM under a key derived from
  your PIN via Argon2id, so backups of the key files are useless without it.
- The daemon installs a **seccomp syscall denylist** before serving, so that a
  code-execution bug in its own input handling cannot spawn a program
  (`execve`) or open a network socket to exfiltrate over -- containment for the
  case where the boundary above is breached from inside, not a replacement for
  it.

It is *not* a defense against root, a kernel bug that bypasses the `dumpable`
check, or a replaced daemon binary. If you need those guarantees, use
hardware. See [DESIGN.md](DESIGN.md) for the full threat model.

## Features

- **PKCS#11 v3.0** module (`reliquary-pkcs11.so`) -- sign, decrypt, and derive
  for RSA (`PKCS#1 v1.5`, PSS, OAEP), ECDSA, and ECDH.
- **GnuPG scdaemon** interface -- presents tokens as OpenPGP cards to
  `gpg-agent`, including `keytocard` support.
- **Algorithms:** RSA 2048/3072/4096, NIST P-256/P-384/P-521, Ed25519.
- **Per-token key slots** following the OpenPGP convention: `sign`,
  `encrypt`, `auth`.
- **PIN protection** with an Argon2id-derived encryption key and a retry
  counter with lockout.

Keys enter a token through `reliquary-tool` (`genkey` or `import-ssh`) or via
gpg's `keytocard` (the scdaemon `WRITEKEY` path, which requires the PIN). The
PKCS#11 module exposes no key-creation or write interface, so a PKCS#11
application cannot inject or modify keys -- keeping that interface's attack
surface minimal.

## Requirements

- Linux (relies on setgid `dumpable = 0` and `SO_PEERCRED` semantics)
- glibc >= 2.36 (the vendored `bcrypt_pbkdf` uses `arc4random_buf`)
- Meson >= 1.1 and a C11 compiler
- libgcrypt >= 1.10.0
- libassuan >= 2.5.0
- libgpg-error
- Ed25519 over PKCS#11 requires OpenSSH >= 10.1; RSA and ECDSA over PKCS#11
  have no such floor

## Building

```sh
meson setup build
meson compile -C build
meson test -C build      # optional: run the test suite
```

Three options are configurable at setup time (defaults shown):

```sh
meson setup build \
  -Dstore_dir=/var/lib/reliquary \
  -Dgroup=reliquary \
  -Dpkcs11_moduledir=          # empty => <libdir>/pkcs11
```

- `store_dir` -- default token store directory.
- `group` -- system group owning the store directory.
- `pkcs11_moduledir` -- install dir for the PKCS#11 module; empty (the
  default) means `<libdir>/pkcs11`.

## Installing

Reliquary needs a one-time privileged setup: a dedicated group, the setgid
bit on the daemon, and a store directory owned by that group.

```sh
sudo meson install -C build

# As root, during install or first setup:
sudo groupadd -r reliquary
sudo chown root:reliquary /usr/local/bin/reliquaryd
sudo chmod 2755 /usr/local/bin/reliquaryd          # setgid bit
sudo install -d -o root -g reliquary -m 710 /var/lib/reliquary
```

Then provision each user once (analogous to `useradd`):

```sh
sudo reliquary-setup-user alice
```

This creates `/var/lib/reliquary/<uid>/` owned `<uid>:reliquary` mode `0700`
(owner-gated, so only that user's daemon can enter it).
No root shell is needed after this -- all token operations go through the
setgid daemon.

The daemon starts on demand: a `reliquary.socket` systemd **user** unit is
installed, and `reliquary-pkcs11.so` will also auto-spawn `reliquaryd` if the
socket is missing. The socket lives at `$XDG_RUNTIME_DIR/reliquary/socket`,
so `$XDG_RUNTIME_DIR` must be set.

## Usage

All token administration is done with `reliquary-tool`. Initialize the store
once to set an admin PIN, then create tokens and generate keys.

To troubleshoot, run `reliquaryd -vv` (or set `RELIQUARY_DEBUG=2` in
`~/.config/reliquary/environment`) to trace connections, logins, and crypto
operations on stderr / the journal. The log never contains key material or PINs.

```sh
reliquary-tool init                          # set the store admin PIN
reliquary-tool create work                   # create an empty token "work"
reliquary-tool genkey work sign  ed25519     # generate a signing key
reliquary-tool genkey work encrypt rsa3072   # generate an encryption key
reliquary-tool list                          # list tokens
reliquary-tool info work                     # show slots and key details
```

Full command list:

```
init                          Initialize store (set admin PIN)
create <label>                Create a new empty token
delete <label>                Delete a token
clear <label>                 Clear key slots from a token
genkey <label> <slot> <algo>  Generate a key in a slot
import-ssh <label> [slot] <keyfile>
                              Import an OpenSSH private key
list                          List tokens
info <label>                  Show token details
change-pin <label>            Change a token PIN
disconnect <label>            Hide a token from enumeration
connect <label>               Make a token visible again

Slots:      sign, encrypt, auth
Algorithms: rsa2048, rsa3072, rsa4096,
            nistp256, nistp384, nistp521, ed25519
```

### As a PKCS#11 token

Point any PKCS#11 application at the module (`reliquary-pkcs11.so`). This is the
recommended way to use Reliquary keys over SSH -- it covers every algorithm
Reliquary holds. Print a token's public keys for `authorized_keys` with:

```sh
ssh-keygen -D /usr/local/lib/pkcs11/reliquary-pkcs11.so
```

Authenticate either by pointing `ssh` at the module directly or by loading it
into `ssh-agent`:

```
# ~/.ssh/config or command line
ssh -I /usr/local/lib/pkcs11/reliquary-pkcs11.so user@host

# or, via the agent
ssh-add -s /usr/local/lib/pkcs11/reliquary-pkcs11.so
```

Algorithm support depends on your OpenSSH version:

- **RSA** and **ECDSA** (NIST P-256/384/521): any OpenSSH.
- **Ed25519**: OpenSSH **>= 10.1**, where OpenSSH gained PKCS#11 EdDSA support
  (Reliquary exposes it via the PKCS#11 v3.0 `CKM_EDDSA` mechanism). On older
  OpenSSH the module still loads, but its Ed25519 keys are not visible.

Or inspect the module with `pkcs11-tool`:

```sh
pkcs11-tool --module /usr/local/lib/pkcs11/reliquary-pkcs11.so --list-objects
```

### As a GnuPG smartcard

Tell `gpg-agent` to use Reliquary as its scdaemon backend by adding this to
`~/.gnupg/gpg-agent.conf`:

```
scdaemon-program /usr/local/libexec/reliquary/reliquary-scd-proxy
```

Reload the agent (`gpgconf --kill gpg-agent`), and your tokens appear as
OpenPGP cards to `gpg --card-status`, `keytocard`, and friends.

#### SSH authentication via `gpg-agent`

`gpg-agent`'s SSH support can also drive the `auth` slot for SSH logins. Enable
it and register the key with the agent:

```sh
# ~/.gnupg/gpg-agent.conf
scdaemon-program /usr/local/libexec/reliquary/reliquary-scd-proxy
enable-ssh-support

# One-time: let the agent learn the card, then authorize the auth key for SSH
gpgconf --kill gpg-agent
gpg --card-status                                   # writes the key stub
# add the auth key's keygrip (the KEYGRIP field of gpg --card-status, or the
# first field of `gpg-connect-agent 'SCD LEARN' /bye` OPENPGP.3 line) to:
echo <AUTH-KEYGRIP> >> ~/.gnupg/sshcontrol
```

Then `SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)` exposes the key:
`ssh-add -L` lists it and it authenticates like any agent key. (Reliquary
performs the actual `INTERNAL AUTHENTICATE` via the OpenPGP `PKAUTH`
operation.)

This path works for **RSA and ECDSA** auth keys with a released `gpg-agent`.
**Ed25519 does not work over `gpg-agent` SSH with any released `gpg-agent`** --
use the PKCS#11 path above for Ed25519.

> **Why Ed25519 fails here.** EdDSA is PureEdDSA -- the card must sign the raw
> ssh message. Released `gpg-agent` has a bug
> ([dev.gnupg.org/T6250](https://dev.gnupg.org/T6250)): for an Ed25519 key used
> over ssh it wraps the message in a bogus SHA-1 DigestInfo before sending it
> to the card, so the signature is over the wrong data and does not verify.
> Reliquary intentionally signs what it is given rather than papering over
> this, so an Ed25519 auth key would need a `gpg-agent` carrying the T6250 fix,
> which is not in any release. Use the PKCS#11 path (OpenSSH >= 10.1) instead.

## Migrating existing keys

How you move an existing key into Reliquary depends on where it comes from.
Note that a key which has ever lived unencrypted on disk was already
exposable; for a clean privilege boundary, prefer generating fresh keys with
`genkey`. When you do need to migrate, the paths below apply.

### GPG secret subkeys (supported)

Existing GnuPG secret subkeys move in via the standard OpenPGP `keytocard`
flow, exactly as with a hardware card. `keytocard` is **destructive** -- it
replaces the on-disk secret with a stub -- so back up your keyring first:

```sh
cp -a ~/.gnupg ~/.gnupg.bak      # keep a copy of the real secret keys
```

Point `gpg-agent` at Reliquary (see "As a GnuPG smartcard" above), create a
token to hold the key, then move each subkey onto it:

```sh
reliquary-tool create work

gpg --edit-key <key-id>
gpg> key 1            # select the subkey to migrate
gpg> keytocard        # choose the matching slot (sign / encrypt / auth)
gpg> save
```

Repeat `key N` / `keytocard` for each subkey. Afterwards `gpg --card-status`
and `reliquary-tool info work` both show the migrated keys, and the private
material lives only inside the daemon.

### SSH private keys (`import-ssh`)

Import an existing OpenSSH private key (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`,
`~/.ssh/id_ecdsa`) straight into a token with `reliquary-tool import-ssh`. Only
the modern OpenSSH on-disk format (`-----BEGIN OPENSSH PRIVATE KEY-----`) is
supported; Ed25519, RSA, and ECDSA (NIST P-256/384/521) keys all work.

Into an existing token's slot (SSH keys belong in `auth`):

```sh
reliquary-tool create work
reliquary-tool import-ssh work auth ~/.ssh/id_ed25519
```

Or create a new token to hold the key in one step (imports into `auth`):

```sh
reliquary-tool import-ssh work ~/.ssh/id_ed25519
```

Passphrase-protected keys are prompted for. Only the `aes256-ctr` cipher is
supported for encrypted keys; convert any other with `ssh-keygen -o -Z
aes256-ctr -p` first.

How you then *use* the imported key over SSH depends on its type; see the two
Usage sections above. In short: RSA and ECDSA work over PKCS#11 on any OpenSSH
(and over `gpg-agent` SSH); Ed25519 works over PKCS#11 on OpenSSH >= 10.1,
which is the only way to use an Ed25519 key over SSH with released software.

Note that a key which has ever lived unencrypted on disk was already
exposable. For a clean privilege boundary, prefer generating a fresh key
inside the daemon (`genkey`) and rotating your deployed public keys to it.

## Documentation

[DESIGN.md](DESIGN.md) covers the architecture, security model, wire
protocol, key storage layout, and PIN handling in detail.

## Non-goals

Reliquary deliberately does **not** provide key export or escrow (back up
the encrypted key files and remember your PIN), multi-user sharing, any
network interface, FIPS compliance, or protection against root. It provides
one thing well: a UID boundary around private keys using standard kernel
mechanisms.

## License

GPL-2.0-or-later.
