package rules

import "testing"

// Verbatim array shapes from the 158-package corpus run. Every one of these was
// reported as CHK-005 and every one is a correctly signed package.
func TestCorpusChecksumShapes(t *testing.T) {
	cases := []struct {
		name, pkgbuild string
		want           bool
	}{
		{"alhp-keyring", `pkgname=alhp-keyring
source=(https://f.alhp.dev/$pkgname/$pkgname-$pkgver.tar.gz{,.sig})
b2sums=('1d12ae59'
        'SKIP')
validpgpkeys=('00B2519305')`, false},

		{"lib32-libdbusmenu-gtk2", `pkgname=lib32-libdbusmenu-gtk2
source=(https://launchpad.net/${_pkgname}/${pkgver%.?}/${pkgver}/+download/${_pkgname}-${pkgver}.tar.gz{,.asc})
sha512sums=('ee9654ac'
            'SKIP')
validpgpkeys=('45B1103FB9')`, false},

		{"lib32-sdl2_image", `pkgname=lib32-sdl2_image
source=("https://github.com/libsdl-org/SDL_image/releases/download/release-${pkgver}/SDL2_image-${pkgver}.tar.gz"{,.sig})
sha512sums=('c2574d83'
            'SKIP')
validpgpkeys=('09001043')`, false},

		{"xf86-video-vmware", `pkgname=xf86-video-vmware
source=(${url}/releases/individual/driver/${pkgname}-${pkgver}.tar.xz{,.sig})
sha512sums=('7cacde21'
            'SKIP')
validpgpkeys=('3C2C43D9')`, false},

		{"postgresql-jdbc", `pkgname=postgresql-jdbc
source=(LICENSE
        https://repo1.maven.org/maven2/org/postgresql/postgresql/${pkgver}/postgresql-${pkgver}.jar{,.asc})
sha1sums=('98ca35c0'
          'a6e1bd21'
          'SKIP')
validpgpkeys=('86C01449')`, false},

		{"libpng12", `pkgname=libpng12
source=("https://sourceforge.net/projects/libpng/files/libpng-${pkgver}.tar.xz"{,.asc}
        "https://sourceforge.net/projects/libpng-apng/files/libpng12/${pkgver}/libpng-${pkgver}-apng.patch.gz")
validpgpkeys=('8048643B')
sha256sums=('b4635f15'
            'SKIP'
            '281fd5f0')`, false},

		{"openssl-1.1", `pkgname=openssl-1.1
source=(
	"https://www.openssl.org/source/${_pkgname}-${_ver}.tar.gz"{,.asc}
	'ca-dir.patch'
	CVE-2023-5678.patch
)
sha256sums=('cf309895'
            'SKIP'
            '75aa8c2c'
            '2fc41792')`, false},

		// Local files committed to the repo: SKIP is not an integrity gap,
		// nothing is fetched. Both shapes came from the corpus.
		{"jdk19-graalvm-bin", `pkgname=jdk19-graalvm-bin
source=('graalvm-rebuild-libpolyglot.hook')
sha256sums=('SKIP')
source_x86_64=("https://github.com/graalvm/graalvm-ce-builds/releases/download/vm-1/x.tar.gz")
sha256sums_x86_64=('7cd99d80')`, false},

		{"libadwaita-without-adwaita", `pkgname=libadwaita-without-adwaita
source=(
  "https://gitlab.gnome.org/GNOME/libadwaita/-/archive/1/libadwaita-1.tar.gz"
  theming_patch.diff
)
sha256sums=('3e4cf25e' 'SKIP')`, false},

		// Genuine: a remote tarball with no integrity check whatsoever. Both
		// shapes came from the corpus and both are correct findings.
		{"iotop-rs", `pkgname=iotop-rs
url="https://github.com/hisbaan/iotop"
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')`, true},

		// a bare local filename built from variables is still local
		{"local-with-vars", `pkgname=foo
url="https://example.org/foo"
source=("https://example.org/foo-1.tar.gz" ${pkgname}.desktop)
sha256sums=('abc' 'SKIP')`, false},

		{"skeuos-gtk", `pkgname=skeuos-gtk
source=("${pkgname}-${pkgver}.tar.gz::https://github.com/daniruiz/${pkgname}/archive/${pkgver}.tar.gz")
sha256sums=('SKIP')`, true},

		// must still fire: a tarball nothing verifies, no signature in sight
		{"genuine-unverified", `pkgname=x
source=("https://example.org/x-1.0.tar.gz")
sha256sums=('SKIP')`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, h := range Scan(map[string]string{"PKGBUILD": c.pkgbuild}) {
				if h.Code == "CHK-005" {
					got = append(got, h.Snippet)
				}
			}
			if (len(got) > 0) != c.want {
				t.Errorf("CHK-005 fired=%v want %v: %v", len(got) > 0, c.want, got)
			}
		})
	}
}

func TestBraceExpansion(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"https://x/foo.tar.gz{,.sig}", 2},
		{`"https://x/foo.tar.gz"{,.asc}`, 2},
		{"${url}/x-${pkgver}.tar.xz{,.sig}", 2},
		{"${pkgver%.?}/plain.tar.gz", 1},
		{"file{a,b,c}.txt", 3},
		{"nobraces.tar.gz", 1},
	}
	for _, c := range cases {
		got := expandBraces(stripQuotes(c.in))
		if len(got) != c.want {
			t.Errorf("%q -> %v (%d), want %d", c.in, got, len(got), c.want)
		}
	}
}
