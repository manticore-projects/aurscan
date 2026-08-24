package rules

import "testing"

// Realistic package shapes that must acquire NO floor.
func TestNewRulesNoFloorOnRealisticPackages(t *testing.T) {
	cases := map[string]map[string]string{
		"plain-autotools": {"PKGBUILD": `pkgname=foo
pkgver=1.2
url="https://example.org/foo"
source=("https://example.org/foo-$pkgver.tar.gz")
sha256sums=('abc')
build(){ cd "$srcdir/foo-$pkgver"; ./configure --prefix=/usr; make; }
package(){ cd "$srcdir/foo-$pkgver"; make DESTDIR="$pkgdir" install; }`},
		"git-vcs": {"PKGBUILD": `pkgname=foo-git
source=("git+https://github.com/u/foo.git")
sha256sums=('SKIP')
pkgver(){ cd "$srcdir/foo"; git describe --tags | sed 's/-/./g'; }
package(){ install -Dm755 foo "$pkgdir/usr/bin/foo"; chmod +x "$pkgdir/usr/bin/foo"; }`},
		"local-source-present": {
			"PKGBUILD":    "pkgname=foo\npkgver=1.0\nsource=(\"https://x.org/a.tar.gz\" \"foo.desktop\" \"$pkgname.patch\")\n",
			"foo.desktop": "[Desktop Entry]\nName=Foo\n",
			"foo.patch":   "--- a\n+++ b\n",
		},
		"install-present-benign": {
			"PKGBUILD": "pkgname=foo\ninstall=foo.install\n",
			"foo.install": `post_install() {
  echo "Enable with: systemctl enable --now foo.service"
  update-desktop-database -q
}
post_upgrade(){ post_install; }
post_remove(){ update-desktop-database -q; }`,
		},
		"systemd-unit-shipped-in-pkgdir": {"PKGBUILD": `pkgname=foo
package(){ install -Dm644 foo.service "$pkgdir/usr/lib/systemd/system/foo.service"; }`},
		"helper-sh-bash-source": {
			"PKGBUILD": "pkgname=foo\n",
			"build.sh": `cd "$(dirname "${BASH_SOURCE[0]}")" && make`,
		},
		"maintainer-release-script": {
			"PKGBUILD":  "pkgname=foo\n",
			"release":   "#!/bin/sh\nmakepkg --printsrcinfo > .SRCINFO\ngit commit -am bump\ngit push origin master\n",
			"update.sh": "#!/bin/bash\ngit push origin master\n",
		},
		"renamed-source": {"PKGBUILD": `pkgname=foo
pkgver=1.0
source=("$pkgname-$pkgver.tar.gz::https://example.org/download/$pkgver")`},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			if f := Floor(Scan(files), false); f != "" {
				t.Errorf("floor=%q, want none. hits: %+v", f, Scan(files))
			}
		})
	}
}

// The distinction WORM-001 rests on: locating yourself is routine, copying
// yourself is a worm. Getting this wrong in either direction is the difference
// between a floor people trust and a floor people mute.
func TestWormSelfLocationVsSelfCopy(t *testing.T) {
	cases := []struct {
		name, file, content string
		want                bool
	}{
		{"dirname-self", "build.sh", `cd "$(dirname "${BASH_SOURCE[0]}")"`, false},
		{"source-sibling", "build.sh", `source "$(dirname "${BASH_SOURCE[0]}")/common.sh"`, false},
		{"readlink-self", "build.sh", `SELF=$(readlink -f "${BASH_SOURCE[0]}")`, false},
		{"cp-self", "x.install", `cp "$BASH_SOURCE" /tmp/copy`, true},
		{"cat-self", "x.install", `cat "${BASH_SOURCE[0]}" > /tmp/copy`, true},
		{"install-self", "x.install", `install -m755 "$BASH_SOURCE" /usr/local/bin/x`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, fired := wormCodes(map[string]string{c.file: c.content})["WORM-001"]
			if fired != c.want {
				t.Errorf("WORM-001 fired=%v, want %v for %q", fired, c.want, c.content)
			}
		})
	}
}

// A worm signature must still fire in a file that is actually EXECUTED. The
// scoping added for maintainer tooling must not blind the scanner to the real
// thing one file over.
func TestWormRulesStillFireInExecutedFiles(t *testing.T) {
	cases := []struct {
		file     string
		wantFire bool
	}{
		{"x.install", true},
		{"PKGBUILD", true},
		{"release", false},
		{"update.sh", false},
		{"ci/deploy.sh", false},
	}
	const body = `git push origin master
git clone ssh://aur@aur.archlinux.org/x.git`
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			got := wormCodes(map[string]string{"PKGBUILD": "pkgname=x\n", c.file: body})
			_, push := got["WORM-003"]
			_, remote := got["WORM-002"]
			if fired := push || remote; fired != c.wantFire {
				t.Errorf("WORM-002/003 fired=%v in %s, want %v", fired, c.file, c.wantFire)
			}
		})
	}
}
