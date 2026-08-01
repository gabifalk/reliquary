# SPDX-License-Identifier: GPL-2.0-or-later

pkcs11_h_inc = include_directories('pkcs11')

bcrypt_inc = include_directories('bcrypt_pbkdf')

bcrypt_lib = static_library('reliquary-bcrypt',
  'bcrypt_pbkdf/blowfish.c',
  'bcrypt_pbkdf/bcrypt_pbkdf.c',
  'bcrypt_pbkdf/crypto_shim.c',
  include_directories: bcrypt_inc,
  c_args: ['-D_DEFAULT_SOURCE', '-DHAVE_BLF_H'],
  dependencies: [libgcrypt_dep],
  override_options: ['warning_level=0'],
)

bcrypt_dep = declare_dependency(
  link_with: bcrypt_lib,
  include_directories: bcrypt_inc,
)
