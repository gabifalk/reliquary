# SPDX-License-Identifier: GPL-2.0-or-later

project('reliquary', 'c',
  version: '0.1.0',
  meson_version: '>=1.1',
  default_options: [
    'c_std=c11',
    'warning_level=2',
  ],
)

cc = meson.get_compiler('c')

libgcrypt_dep = dependency('libgcrypt', version: '>=1.10.0')
libassuan_dep = dependency('libassuan', version: '>=2.5.0')

subdir('src')
subdir('tests')
