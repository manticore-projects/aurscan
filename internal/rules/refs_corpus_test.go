package rules

import "testing"

// Shapes from the 158-package corpus run. REF-003 carries a floor, so a
// reference the scanner could have resolved but didn't is not a harmless
// info line — it holds the package at SUSPICIOUS.
func TestCorpusReferenceResolution(t *testing.T) {
	cases := []struct {
		name, pkgbuild string
		files          map[string]string
		mustNot        string
	}{
		// jdk19-graalvm-bin: install=$pkgname.install, pkgname built from java_
		{"indirect-pkgname", `java_=19
pkgname=jdk${java_}-graalvm-bin
pkgver=22.3.1
install=$pkgname.install`,
			map[string]string{"jdk19-graalvm-bin.install": "post_install(){ :; }"}, "REF-003"},

		// vdhcoapp-bin: install=$_pkgname.install
		{"underscore-pkgname", `_pkgname=vdhcoapp
pkgname=${_pkgname}-bin
install=$_pkgname.install`,
			map[string]string{"vdhcoapp.install": "post_install(){ :; }"}, "REF-003"},

		// two levels of indirection
		{"two-level", `_base=foo
_name=${_base}-tool
pkgname=${_name}
install=${pkgname}.install`,
			map[string]string{"foo-tool.install": "post_install(){ :; }"}, "REF-003"},

		// a line-continuation backslash is not a source entry
		{"continuation-backslash", `pkgname=foo
source=("https://example.org/a.tar.gz" \
        "https://example.org/b.tar.gz")`,
			nil, "REF-004"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"PKGBUILD": c.pkgbuild}
			for k, v := range c.files {
				files[k] = v
			}
			for _, h := range Scan(files) {
				if h.Code == c.mustNot {
					t.Errorf("%s fired: %q", h.Code, h.Snippet)
				}
			}
		})
	}
}

// A genuinely unresolvable reference must still be reported: silence there
// would mean certifying a scriptlet nobody read.
func TestUnresolvableReferenceStillReported(t *testing.T) {
	cases := []struct{ name, pkgbuild, want string }{
		{"command-substitution", "pkgname=foo\ninstall=$(gen-name).install", "REF-003"},
		{"operator-expansion", "pkgname=foo\npkgver=1.2.3\ninstall=${pkgver%.*}.install", "REF-003"},
		{"resolved-but-absent", "_n=bar\npkgname=${_n}\ninstall=$pkgname.install", "REF-001"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := false
			for _, h := range Scan(map[string]string{"PKGBUILD": c.pkgbuild}) {
				if h.Code == c.want {
					got = true
				}
			}
			if !got {
				t.Errorf("expected %s on %q", c.want, c.pkgbuild)
			}
		})
	}
}

// Improving variable resolution must not turn variable-built URLs into phantom
// missing local files. The scheme is frequently inside $url, so an entry with
// no literal "://" may still be a download.
func TestRemoteSourcesAreNotLocalFiles(t *testing.T) {
	cases := []struct {
		name, pkgbuild string
		want           bool // REF-004 expected
	}{
		{"url-var-with-rename", `pkgname=iotop-rs
pkgver=1.0
url="https://github.com/hisbaan/iotop"
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")`, false},

		{"url-var-plain", `pkgname=foo
pkgver=1.0
url="https://example.org/foo"
source=("$url/releases/foo-$pkgver.tar.gz")`, false},

		{"github-path-built-from-vars", `pkgname=skeuos-gtk
pkgver=1.0
source=("${pkgname}-${pkgver}.tar.gz::https://github.com/daniruiz/${pkgname}/archive/${pkgver}.tar.gz")`, false},

		// a genuine local file that is genuinely absent
		{"missing-local-patch", `pkgname=foo
source=("https://example.org/foo.tar.gz" fix.patch)`, true},

		// present local file, built from a variable
		{"present-local-var", `pkgname=foo
source=("https://example.org/foo.tar.gz" ${pkgname}.desktop)`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"PKGBUILD": c.pkgbuild}
			if c.name == "present-local-var" {
				files["foo.desktop"] = "[Desktop Entry]"
			}
			got := false
			for _, h := range Scan(files) {
				if h.Code == "REF-004" {
					got = true
					t.Logf("  %s", h.Snippet)
				}
			}
			if got != c.want {
				t.Errorf("REF-004 fired=%v, want %v", got, c.want)
			}
		})
	}
}

// The "name::url" rename separator sits outside the quotes as often as inside.
// Truncating at the closing quote discards the URL and turns a download into a
// phantom missing local file. All three shapes come from the corpus.
func TestRenameSeparatorOutsideQuotes(t *testing.T) {
	cases := []string{
		// snyk
		`pkgname=snyk
pkgver=1.0
url='https://github.com/snyk/snyk'
source=("${pkgname}-${pkgver}"::"https://github.com/snyk/snyk/releases/download/v${pkgver}/snyk-linux")`,
		// zoom
		`pkgname=zoom
pkgver=7.1.5
_subver=4332
url="https://zoom.us/"
source=("${pkgname}-${pkgver}.${_subver}_orig_x86_64.pkg.tar.xz"::"https://zoom.us/client/${pkgver}.${_subver}/zoom_x86_64.pkg.tar.xz")`,
		// separator inside the quotes (the form that already worked)
		`pkgname=foo
pkgver=1.0
source=("foo-${pkgver}.tar.gz::https://example.org/foo-${pkgver}.tar.gz")`,
	}
	for i, pb := range cases {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			for _, h := range Scan(map[string]string{"PKGBUILD": pb}) {
				if h.Code == "REF-004" {
					t.Errorf("REF-004 fired on a remote source: %q", h.Snippet)
				}
			}
		})
	}
}

// A $( ) command substitution may contain spaces. Splitting on whitespace
// inside it yields fragments that look like local filenames — `base)` from
// whisper.cpp-model-base — which are then reported as missing sources.
func TestCommandSubstitutionInSourceArray(t *testing.T) {
	pkgbuild := `_model='base'
_pkgbase='whisper.cpp-model'
pkgname="${_pkgbase}-${_model}"
_model_file="ggml-${_model}.bin"
__model_url() {
  echo "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/$1"
}
source=("$_model_file::$(__model_url $_model)")
sha256sums=("$_model_sha256sum")`
	for _, h := range Scan(map[string]string{"PKGBUILD": pkgbuild}) {
		if h.Code == "REF-004" || h.Code == "CHK-005" {
			t.Errorf("%s fired on a command-substitution source: %q", h.Code, h.Snippet)
		}
	}
}

func TestSplitArrayTokens(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{`"a" "b" "c"`, 3},
		{`"$f::$(url $m)"`, 1},
		{`a $(cmd one two) b`, 3},
		{"\"a\"\n\"b\"", 2},
		{`"a b c"`, 1},
		{`url{,.sig}`, 1},
	}
	for _, c := range cases {
		if got := splitArrayTokens(c.in); len(got) != c.want {
			t.Errorf("splitArrayTokens(%q) = %v (%d), want %d", c.in, got, len(got), c.want)
		}
	}
}

// A file the collector skipped is present in the repository, so REF-004 must
// stay quiet about it — reporting it would be the scanner describing its own
// truncation as a property of the package. The pattern rules must also skip it,
// since the marker is not the file's content.
func TestOmittedFileIsNotAMissingSource(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": `pkgname=openssl-1.1
source=("https://example.org/openssl.tar.gz" ca-dir.patch CVE-2024-0727-2.patch)`,
		"ca-dir.patch":          "--- a\n+++ b\n",
		"CVE-2024-0727-2.patch": OmittedContent,
	}
	for _, h := range Scan(files) {
		if h.Code == "REF-004" {
			t.Errorf("REF-004 fired on an omitted (but present) file: %q", h.Snippet)
		}
		if h.File == "CVE-2024-0727-2.patch" {
			t.Errorf("pattern rules must not match against the omission marker: %+v", h)
		}
	}
}

// A genuinely absent file must still be reported.
func TestTrulyMissingSourceStillReported(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": `pkgname=foo
source=("https://example.org/foo.tar.gz" gone.patch)`,
	}
	got := false
	for _, h := range Scan(files) {
		if h.Code == "REF-004" {
			got = true
		}
	}
	if !got {
		t.Error("expected REF-004 for a source file that is not in the repository")
	}
}
