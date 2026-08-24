package rules

import "testing"

func codesFor(files map[string]string) map[string]Hit {
	m := map[string]Hit{}
	for _, h := range Scan(files) {
		m[h.Code] = h
	}
	return m
}

// CHK-005 asks "is there a fetched artifact whose integrity nothing verifies?".
// SKIP is correct and universal for a VCS checkout and for a detached
// signature, so neither may fire — including when the source array spans
// several lines, and whichever hash algorithm the package uses.
func TestChecksumPairing(t *testing.T) {
	cases := []struct {
		name, pkgbuild string
		want           bool
	}{
		{"signed-tarball-skip-on-sig", `pkgname=foo
source=("https://example.org/foo-1.0.tar.xz"
        "https://example.org/foo-1.0.tar.xz.asc")
validpgpkeys=('ABCD')
sha256sums=('deadbeef' 'SKIP')`, false},

		{"vcs-single-line", `pkgname=foo-git
source=("git+https://github.com/u/foo.git")
sha256sums=('SKIP')`, false},

		{"vcs-multiline", `pkgname=foo-git
source=(
  "git+https://github.com/u/foo.git"
  "foo.patch"
)
sha256sums=('SKIP' 'abc')`, false},

		{"b2sums-vcs", `pkgname=foo-git
source=("git+https://github.com/u/foo.git")
b2sums=('SKIP')`, false},

		{"arch-suffixed-arrays", `pkgname=foo
source_x86_64=("https://example.org/foo-1.0-x86_64.tar.gz")
sha256sums_x86_64=('abc')
source=("git+https://github.com/u/foo.git")
sha256sums=('SKIP')`, false},

		// the real finding: a downloaded tarball with no integrity check
		{"tarball-skip", `pkgname=foo
source=("https://example.org/foo-1.0.tar.gz")
sha256sums=('SKIP')`, true},

		{"b2sums-tarball-skip", `pkgname=foo
source=("https://example.org/foo-1.0.tar.gz")
b2sums=('SKIP')`, true},

		// second entry unverified while the first is fine
		{"second-entry-skip", `pkgname=foo
source=("https://example.org/foo-1.0.tar.gz"
        "https://elsewhere.example/blob.bin")
sha256sums=('abc' 'SKIP')`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, fired := codesFor(map[string]string{"PKGBUILD": c.pkgbuild})["CHK-005"]
			if fired != c.want {
				t.Errorf("CHK-005 fired=%v, want %v (snippet %q)", fired, c.want, h.Snippet)
			}
		})
	}
}

// SRC-003 asks whether the download host matches the stated upstream. For a
// canonical distribution point or language registry the answer is always no,
// and saying so carries no information — a GNU project's homepage is never
// ftp.gnu.org.
func TestSrc003DistributionHosts(t *testing.T) {
	cases := []struct {
		name, pkgbuild string
		want           bool
	}{
		{"gnu-ftp", `pkgname=x
url="https://www.mathomatic.org/"
source=("https://ftp.gnu.org/gnu/x/x-1.0.tar.bz2")`, false},

		{"gnome-ftp", `pkgname=x
url="https://www.gtk.org/"
source=("https://ftp.gnome.org/pub/GNOME/sources/x/1.0/x-1.0.tar.xz")`, false},

		{"npm-registry", `pkgname=nodejs-x
url="https://x.js.org"
source=("x-1.0.tgz::https://registry.npmjs.org/x/-/x-1.0.tgz")`, false},

		{"pythonhosted", `pkgname=python-x
url="https://x.example.org"
source=("https://files.pythonhosted.org/packages/source/x/x/x-1.0.tar.gz")`, false},

		// still fires where the mismatch IS the signal
		{"unrelated-vps", `pkgname=x
url="https://x.example.org"
source=("https://random-vps.example.net/x-1.0.tar.gz")`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, fired := codesFor(map[string]string{"PKGBUILD": c.pkgbuild})["SRC-003"]
			if fired != c.want {
				t.Errorf("SRC-003 fired=%v, want %v (snippet %q)", fired, c.want, h.Snippet)
			}
		})
	}
}
