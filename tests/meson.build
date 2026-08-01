# SPDX-License-Identifier: GPL-2.0-or-later

add_test_setup('reliquary', is_default: true,
  env: {'MESON_BUILD_ROOT': meson.project_build_root()},
)

test('hex', executable('test_hex',
  'test_hex.c',
  dependencies: reliquary_core_dep,
))

test('log', executable('test_log',
  'test_log.c',
  dependencies: reliquary_core_dep,
))

test('setgid_check', find_program('test_setgid_check.sh'),
  workdir: meson.project_build_root(),
)

test('socket_activation', find_program('test_socket_activation.sh'),
  workdir: meson.project_build_root(),
)
