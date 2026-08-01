# SPDX-License-Identifier: GPL-2.0-or-later

reliquary_core_sources = files(
  'crypto.c',
  'crypto_ec.c',
  'crypto_rsa.c',
  'hex.c',
  'log.c',
  'secmem.c',
)

reliquary_core_inc = include_directories('.')
reliquary_core_deps = [libgcrypt_dep]

reliquary_core_lib = static_library('reliquary-core',
  reliquary_core_sources,
  include_directories: reliquary_core_inc,
  dependencies: reliquary_core_deps,
)

reliquary_core_dep = declare_dependency(
  link_with: reliquary_core_lib,
  include_directories: reliquary_core_inc,
  dependencies: reliquary_core_deps,
)
