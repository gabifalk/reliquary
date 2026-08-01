# SPDX-License-Identifier: GPL-2.0-or-later

pkcs11_moduledir = get_option('pkcs11_moduledir')
if pkcs11_moduledir == ''
  pkcs11_moduledir = get_option('libdir') / 'pkcs11'
endif

reliquary_pkcs11_so = shared_module('reliquary-pkcs11',
  'reliquary-pkcs11.c',
  name_prefix: '',
  include_directories: pkcs11_h_inc,
  dependencies: [reliquary_core_dep, reliquary_client_dep],
  install: true,
  install_dir: pkcs11_moduledir,
)
