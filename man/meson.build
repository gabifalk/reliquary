# SPDX-License-Identifier: GPL-2.0-or-later

man_config = {
  'version': meson.project_version(),
  'store_dir': get_option('store_dir'),
  'group': get_option('group'),
}

foreach page : ['reliquary-tool.1', 'reliquaryd.1', 'reliquary-setup-user.8']
  install_man(configure_file(
    input: page + '.in',
    output: page,
    configuration: man_config,
  ))
endforeach
