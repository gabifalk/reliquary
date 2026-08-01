# SPDX-License-Identifier: GPL-2.0-or-later

reliquary_scd_proxy = executable('reliquary-scd-proxy',
  'reliquary-scd-proxy.c',
  dependencies: [reliquary_core_dep, reliquary_client_dep, gpg_error_dep],
  c_args: conf_cflags,
  install: true,
  install_dir: get_option('libexecdir') / 'reliquary',
)
