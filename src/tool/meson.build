# SPDX-License-Identifier: GPL-2.0-or-later

tool_inc = include_directories('.')

reliquary_tool = executable('reliquary-tool',
  'reliquary-tool.c',
  'sshkey.c',
  dependencies: [reliquary_core_dep, reliquary_client_dep, bcrypt_dep, libassuan_dep, gpg_error_dep],
  install: true,
)
