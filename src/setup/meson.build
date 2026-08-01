# SPDX-License-Identifier: GPL-2.0-or-later

useradd_script = configure_file(
  input: 'reliquary-setup-user.in',
  output: 'reliquary-setup-user',
  configuration: {
    'store_dir': get_option('store_dir'),
    'group': get_option('group'),
  },
  install: true,
  install_dir: get_option('sbindir'),
  install_mode: 'rwxr-xr-x',
)
