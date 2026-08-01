# SPDX-License-Identifier: GPL-2.0-or-later

daemon_sources = files('tokenstore.c', 'server.c')
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
