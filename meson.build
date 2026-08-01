# SPDX-License-Identifier: GPL-2.0-or-later

project('reliquary', 'c',
  version: '0.1.0',
  meson_version: '>=1.1',
  default_options: [
    'c_std=c11',
    'warning_level=2',
    'b_pie=true',
  ],
)

cc = meson.get_compiler('c')

harden_c = cc.get_supported_arguments(
  '-fstack-protector-strong',
  '-fstack-clash-protection',
  '-fcf-protection=full',
  '-mbranch-protection=standard',
  '-Wformat',
  '-Wformat-security',
  '-Werror=implicit-function-declaration',
)

if get_option('optimization') not in ['0', 'plain']
  harden_c += cc.get_supported_arguments('-D_FORTIFY_SOURCE=3')
endif

harden_link = cc.get_supported_link_arguments(
  '-Wl,-z,relro',
  '-Wl,-z,now',
  '-Wl,-z,noexecstack',
)

add_project_arguments(harden_c, language: 'c')
add_project_link_arguments(harden_link, language: 'c')

libgcrypt_dep = dependency('libgcrypt', version: '>=1.10.0')
libassuan_dep = dependency('libassuan', version: '>=2.5.0')
gpg_error_dep = dependency('gpg-error')

subdir('src')
subdir('man')
subdir('tests')

install_data('units/reliquary.socket', 'units/reliquary.service',
  install_dir: join_paths(get_option('prefix'), 'lib', 'systemd', 'user'),
)
