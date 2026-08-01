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

test('seccomp', executable('test_seccomp',
  'test_seccomp.c',
  '../src/daemon/seccomp.c',
  include_directories: daemon_inc,
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

test('scd_proxy_version', find_program('test_scd_proxy_version.sh'),
  workdir: meson.project_build_root(),
  env: {'MESON_BUILD_ROOT': meson.project_build_root()},
)

daemon_test_inc = include_directories('../src/daemon')

test('tools', executable('test_tools',
  'test_tools.c',
  daemon_sources,
  include_directories: daemon_test_inc,
  dependencies: [reliquary_core_dep, reliquary_client_dep, libassuan_dep, gpg_error_dep],
))

test_daemon_integration = executable('test_daemon_integration',
  'test_daemon_integration.c',
  include_directories: daemon_test_inc,
  dependencies: [reliquary_core_dep, reliquary_client_dep, libassuan_dep, gpg_error_dep],
)
test('daemon_integration', test_daemon_integration,
  env: [
    'RELIQUARYD_PATH=' + reliquaryd.full_path(),
    'FIXTURE_RSA4096_PATH=' + meson.current_source_dir() / 'data' / 'fixture_rsa4096.key',
  ],
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

test('unblock_tool',
  find_program('sh'),
  args: [
    files('test_unblock.sh'),
    reliquaryd.full_path(),
    reliquary_tool.full_path(),
  ],
  timeout: 60,
)

test('pkcs11', executable('test_pkcs11',
  'test_pkcs11.c',
  '../src/pkcs11/reliquary-pkcs11.c',
  daemon_sources,
  include_directories: [pkcs11_h_inc, daemon_test_inc],
  dependencies: [reliquary_core_dep, reliquary_client_dep, libassuan_dep, gpg_error_dep],
))

test_pkcs11_integration = executable('test_pkcs11_integration',
  'test_pkcs11_integration.c',
  include_directories: pkcs11_h_inc,
  dependencies: [reliquary_client_dep, dependency('dl'), libassuan_dep, gpg_error_dep, libgcrypt_dep],
)
test('pkcs11_integration', test_pkcs11_integration,
  env: [
    'RELIQUARYD_PATH=' + reliquaryd.full_path(),
    'RELIQUARY_PKCS11_PATH=' + reliquary_pkcs11_so.full_path(),
    'RELIQUARY_TOOL_PATH=' + reliquary_tool.full_path(),
  ],
)

test('pkcs11_tool',
  find_program('sh'),
  args: [
    files('test_pkcs11_tool.sh'),
    reliquaryd.full_path(),
    reliquary_pkcs11_so.full_path(),
  ],
  timeout: 60,
)

test('gpg_scd',
  find_program('sh'),
  args: [
    files('test_gpg_scd.sh'),
    reliquaryd.full_path(),
    reliquary_scd_proxy.full_path(),
    files('data/fixture_key.gpg'),
  ],
  timeout: 60,
)

# Regression test for chunked SETDATA (SETDATA --append) reassembly in the
# scd-proxy: rsa4096 card decryption used to fail with "Invalid value".
test('scd_proxy_setdata',
  find_program('sh'),
  args: [
    files('test_scd_proxy_setdata.sh'),
    reliquaryd.full_path(),
    reliquary_scd_proxy.full_path(),
    files('data/fixture_rsa4096.key'),
  ],
  timeout: 60,
)

# Regression test: scd-proxy LEARN must not report a keygrip as a KEY-FPR
# fingerprint when a slot has no fingerprint.
test('scd_proxy_learn',
  find_program('sh'),
  args: [
    files('test_scd_proxy_learn.sh'),
    reliquaryd.full_path(),
    reliquary_scd_proxy.full_path(),
    files('data/fixture_rsa4096.key'),
  ],
  timeout: 60,
)

test('openpgp_fpr_ec',
  find_program('sh'),
  args: [
    files('test_openpgp_fpr_ec.sh'),
    reliquaryd.full_path(),
    reliquary_scd_proxy.full_path(),
  ],
  timeout: 90,
)

keytocard_script = files('test_keytocard.sh')
keytocard_common_args = [
  keytocard_script,
  reliquaryd.full_path(),
  reliquary_scd_proxy.full_path(),
  files('data/fixture_key.gpg'),
]

# 1-of combinations
test('keytocard_sign_only', find_program('sh'),
  args: keytocard_common_args + ['sign_only', 'sign'],
  timeout: 60,
)
test('keytocard_encr_only', find_program('sh'),
  args: keytocard_common_args + ['encr_only', 'encr'],
  timeout: 60,
)
test('keytocard_auth_only', find_program('sh'),
  args: keytocard_common_args + ['auth_only', 'auth'],
  timeout: 60,
)

# 2-of combinations
test('keytocard_sign_encr', find_program('sh'),
  args: keytocard_common_args + ['sign_encr', 'sign', 'encr'],
  timeout: 60,
)
test('keytocard_sign_auth', find_program('sh'),
  args: keytocard_common_args + ['sign_auth', 'sign', 'auth'],
  timeout: 60,
)
test('keytocard_encr_auth', find_program('sh'),
  args: keytocard_common_args + ['encr_auth', 'encr', 'auth'],
  timeout: 60,
)

# 3-of combination
test('keytocard_all_three', find_program('sh'),
  args: keytocard_common_args + ['all_three', 'sign', 'encr', 'auth'],
  timeout: 60,
)

test('bcrypt_pbkdf', executable('test_bcrypt_pbkdf',
  'test_bcrypt_pbkdf.c',
  dependencies: [bcrypt_dep, libgcrypt_dep],
))

test('sshkey', executable('test_sshkey',
  'test_sshkey.c',
  '../src/tool/sshkey.c',
  include_directories: [tool_inc],
  dependencies: [reliquary_core_dep, libgcrypt_dep, bcrypt_dep],
), timeout: 60)

test('ssh_pkcs11',
  find_program('sh'),
  args: [
    files('test_ssh_pkcs11.sh'),
    reliquaryd.full_path(),
    reliquary_pkcs11_so.full_path(),
  ],
  timeout: 60,
)

test('ssh_ed25519_pkcs11',
  find_program('sh'),
  args: [
    files('test_ssh_ed25519_pkcs11.sh'),
    reliquaryd.full_path(),
    reliquary_pkcs11_so.full_path(),
  ],
  timeout: 60,
)

test('import_ssh',
  find_program('sh'),
  args: [
    files('test_import_ssh.sh'),
    reliquaryd.full_path(),
    reliquary_tool.full_path(),
    reliquary_pkcs11_so.full_path(),
  ],
  timeout: 60,
)

test('ssh_gpg_auth',
  find_program('sh'),
  args: [
    files('test_ssh_gpg_auth.sh'),
    reliquaryd.full_path(),
    reliquary_tool.full_path(),
    reliquary_scd_proxy.full_path(),
  ],
  timeout: 60,
)
