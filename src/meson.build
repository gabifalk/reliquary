# SPDX-License-Identifier: GPL-2.0-or-later

conf_cflags = [
  '-DDEFAULT_STORE="' + get_option('store_dir') + '"',
  '-DRELIQUARY_GROUP="' + get_option('group') + '"',
  '-DRELIQUARY_VERSION="' + meson.project_version() + '"',
]

subdir('bundled')
subdir('core')
subdir('daemon')
subdir('setup')

subdir('client')
subdir('tool')
subdir('pkcs11')
subdir('scd')
