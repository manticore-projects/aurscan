package rules

import "testing"

// The jre-jetbrains PKGBUILD: the filename is built from four variables, two
// levels deep.
const jbrPKGBUILD = `pkgname=jre-jetbrains
_major=25
_minor=0
_patch=4.1
_java_version=$_major.$_minor.$_patch
_build=610.67
pkgver="${_java_version}b${_build}"
_zipname="jbr_jcef-$_java_version-linux-x64-b$_build.tar.gz"
source=("https://cache-redirector.jetbrains.com/intellij-jbr/${_zipname}")
b2sums=('2f8d')
`

func TestDownloadedSourceNames(t *testing.T) {
	got := DownloadedSourceNames(jbrPKGBUILD)
	if !got["jbr_jcef-25.0.4.1-linux-x64-b610.67.tar.gz"] || len(got) != 1 {
		t.Errorf("jbr: got %v", got)
	}

	got = DownloadedSourceNames(`pkgname=foo
pkgver=1.2
url=https://example.org/foo
source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz"
        "https://example.org/foo-$pkgver.tar.gz"{,.sig}
        "git+https://example.org/foo.git#tag=v1"
        "https://example.org/bar.zip#frag"
        foo.install
        "https://example.org/${pkgver%.?}/baz.tar.gz")
source_x86_64=("https://example.org/foo-x86_64.bin")
`)
	for _, want := range []string{"foo-1.2.tar.gz", "foo-1.2.tar.gz.sig", "bar.zip", "baz.tar.gz", "foo-x86_64.bin"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	for _, not := range []string{"foo.install", "foo", "foo.git"} {
		if got[not] {
			t.Errorf("%q must not be a download: %v", not, got)
		}
	}
}

func TestIsMakepkgOutput(t *testing.T) {
	for _, n := range []string{
		"jre-jetbrains-25.0.4.1b610.67-2-x86_64.pkg.tar.zst",
		"foo-1-1-any.pkg.tar.zst.sig",
		"foo-1-1.src.tar.gz",
		"foo-1-1-x86_64-build.log",
		"foo-1-1-x86_64-package_foo-bin.log.1",
	} {
		if !IsMakepkgOutput(n) {
			t.Errorf("%q not recognised", n)
		}
	}
	for _, n := range []string{"PKGBUILD", "foo.install", "foo.tar.gz", "build.log.txt", "fix.patch"} {
		if IsMakepkgOutput(n) {
			t.Errorf("%q wrongly recognised", n)
		}
	}
}
