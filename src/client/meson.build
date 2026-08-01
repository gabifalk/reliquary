# SPDX-License-Identifier: GPL-2.0-or-later

reliquary_client_inc = include_directories('.')

reliquary_client_deps = [libassuan_dep]

reliquary_client_lib = static_library('reliquary-client',
  'client.c',
  dependencies: reliquary_client_deps,
  include_directories: reliquary_client_inc,
)

reliquary_client_dep = declare_dependency(
  link_with: reliquary_client_lib,
  include_directories: reliquary_client_inc,
  dependencies: reliquary_client_deps,
)
