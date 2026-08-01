# SPDX-License-Identifier: GPL-2.0-or-later

reliquary_core_sources = files('hex.c')

reliquary_core_inc = include_directories('.')

reliquary_core_lib = static_library('reliquary-core',
  reliquary_core_sources,
  include_directories: reliquary_core_inc,
)

reliquary_core_dep = declare_dependency(
  link_with: reliquary_core_lib,
  include_directories: reliquary_core_inc,
)
