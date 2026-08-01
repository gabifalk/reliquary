# SPDX-License-Identifier: GPL-2.0-or-later

daemon_sources = files(
  'cmd_admin.c',
  'cmd_session.c',
  'crypto_op.c',
  'keygrip.c',
  'server.c',
  'session.c',
  'tokenstore.c',
)

daemon_inc = include_directories('.')

reliquaryd = executable('reliquaryd',
  'main.c',
  daemon_sources,
  include_directories: daemon_inc,
  c_args: conf_cflags,
  dependencies: [reliquary_core_dep, libassuan_dep],
  install: true,
  install_mode: ['rwxr-sr-x', 'root', get_option('group')],
)
