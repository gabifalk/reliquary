# SPDX-License-Identifier: GPL-2.0-or-later

add_test_setup('reliquary', is_default: true,
  env: {'MESON_BUILD_ROOT': meson.project_build_root(),
        'RELIQUARY_SKIP_SETGID_CHECK': '1'},
)

test('hex', executable('test_hex',
  'test_hex.c',
  dependencies: reliquary_core_dep,
))

test('log', executable('test_log',
  'test_log.c',
  dependencies: reliquary_core_dep,
))

test('crypto', executable('test_crypto',
  'test_crypto.c',
  dependencies: reliquary_core_dep,
))

test('secmem', executable('test_secmem',
  'test_secmem.c',
  dependencies: reliquary_core_dep,
))

test('crypto_rsa', executable('test_crypto_rsa',
  'test_crypto_rsa.c',
  dependencies: reliquary_core_dep,
), timeout: 60)

test('crypto_ec', executable('test_crypto_ec',
  'test_crypto_ec.c',
  dependencies: reliquary_core_dep,
))

test('keygrip', executable('test_keygrip',
  'test_keygrip.c',
  '../src/daemon/keygrip.c',
  include_directories: [daemon_inc],
  dependencies: reliquary_core_dep,
))

test('serial', executable('test_serial',
  'test_serial.c',
  dependencies: reliquary_core_dep,
))

test('keywrap', executable('test_keywrap',
  'test_keywrap.c',
  dependencies: reliquary_core_dep,
))

test('keyfile', executable('test_keyfile',
  'test_keyfile.c',
  dependencies: reliquary_core_dep,
))

test('meta', executable('test_meta',
  'test_meta.c',
  dependencies: reliquary_core_dep,
))

test('pin', executable('test_pin',
  'test_pin.c',
  dependencies: reliquary_core_dep,
))

test('tokenstore', executable('test_tokenstore',
  'test_tokenstore.c',
  '../src/daemon/tokenstore.c',
  include_directories: [daemon_inc],
  dependencies: reliquary_core_dep,
))

test('session', executable('test_session',
  'test_session.c',
  '../src/daemon/tokenstore.c',
  '../src/daemon/session.c',
  include_directories: [daemon_inc],
  dependencies: reliquary_core_dep,
))

test('daemon', executable('test_daemon',
  'test_daemon.c',
  daemon_sources,
  include_directories: [daemon_inc],
  dependencies: [reliquary_core_dep, libassuan_dep, gpg_error_dep],
))

test('setgid_check', find_program('test_setgid_check.sh'),
  workdir: meson.project_build_root(),
)

test('socket_activation', find_program('test_socket_activation.sh'),
  workdir: meson.project_build_root(),
)

test('useradd',
  find_program('sh'),
  args: [files('test_useradd.sh'), useradd_script],
)

# Regression test: IMPORT_SLOT derives the OpenPGP v4 fingerprint from the key +
# (created-at ...) so gpg --card-status shows a real fingerprint, not [none].
test('openpgp_fpr',
  find_program('sh'),
  args: [
    files('test_openpgp_fpr.sh'),
    reliquaryd.full_path(),
    files('data/fixture_rsa4096.key'),
  ],
  timeout: 60,
)

# Regression test: on-disk key files must be 0600 and token dirs 0700,
# independent of the caller's umask.
test('store_perms',
  find_program('sh'),
  args: [
    files('test_store_perms.sh'),
    reliquaryd.full_path(),
    reliquary_tool.full_path(),
  ],
  timeout: 60,
)
