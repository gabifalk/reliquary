# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit meson

DESCRIPTION="Setgid daemon providing HSM-like key isolation in software"
HOMEPAGE="https://github.com/gabifalk/reliquary"
SRC_URI="https://github.com//gabifalk/reliquary/archive/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="GPL-2+"
SLOT="0"
KEYWORDS="~amd64 ~arm64"
IUSE="systemd test"
RESTRICT="!test? ( test )"

DEPEND="
	>=dev-libs/libgcrypt-1.10.0:=
	>=dev-libs/libassuan-2.5.0:=
	dev-libs/libgpg-error:=
"
RDEPEND="
	${DEPEND}
	acct-group/reliquary
"
BDEPEND="
	virtual/pkgconfig
"

src_configure() {
	local emesonargs=(
		-Dstore_dir=/var/lib/reliquary
		-Dgroup=reliquary
	)
	meson_src_configure
}

src_install() {
	meson_src_install

	# sgid so the daemon can access /var/lib/reliquary/<uid>/
	fowners root:reliquary /usr/bin/reliquaryd
	fperms 2755 /usr/bin/reliquaryd

	keepdir /var/lib/reliquary
	fowners root:reliquary /var/lib/reliquary
	fperms 0710 /var/lib/reliquary
}

pkg_postinst() {
	if use systemd; then
		elog "Enable per-user with: systemctl --user enable reliquary.socket"
	fi
	elog "Run 'reliquary-setup-user <username>' as root to create a user store."
}
