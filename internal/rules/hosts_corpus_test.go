package rules

import "testing"

func hostCodes(pkgbuild string) map[string]Hit {
	m := map[string]Hit{}
	for _, h := range Scan(map[string]string{"PKGBUILD": pkgbuild}) {
		m[h.Code] = h
	}
	return m
}

// Verbatim shapes from the corpus. Each one is a package whose download is
// perfectly attributable, flagged only because a host was missing from the
// allowlist.
func TestCorpusHostAllowlist(t *testing.T) {
	cases := []struct{ name, pkgbuild string }{
		// ttf-roboto-slab: raw.github.com is the same origin as github.com,
		// and the path is pinned to a commit.
		{"raw-github", `pkgname=ttf-roboto-slab
url='https://www.google.com/fonts/specimen/Roboto+Slab'
_commit='1be6141f85b68b48c06ccac50d234302d6e59643'
source=("https://raw.github.com/googlefonts/robotoslab/${_commit}/fonts/ttf/RobotoSlab-Bold.ttf")`},

		// ttf-sourcesanspro: github.com, pinned to a commit. The url= field
		// names an unrelated font — wrong metadata, fine download.
		{"github-raw-path", `pkgname=ttf-sourcesanspro
url="http://www.google.com/fonts/specimen/Open+Sans"
_gitver=f3f3d547cd8c4f7963bcd4dc1965ba564b281ef7
source=(https://github.com/google/fonts/raw/$_gitver/ofl/sourcesanspro/SourceSansPro-Regular.ttf)`},

		{"ffmpeg-forge", `pkgname=x
url="https://ffmpeg.org"
source=("git+https://git.ffmpeg.org/ffmpeg.git")`},

		{"launchpad-code", `pkgname=x
url="https://example.org/x"
source=("bzr+https://code.launchpad.net/~team/x/trunk")`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hostCodes(c.pkgbuild)
			for _, code := range []string{"SRC-001", "SRC-002", "SRC-003"} {
				if h, ok := got[code]; ok {
					t.Errorf("%s fired on an attributable source: %q", code, h.Snippet)
				}
			}
		})
	}
}

// Community asset hosts are NOT allowlisted. The upload path is chosen by
// whoever uploads, so the host establishes nothing about who produced the file
// — which is SRC-002 ("verify provenance"), not a clean bill of health.
func TestCommunityAssetHostsAreGeneric(t *testing.T) {
	// sound-theme-smooth
	got := hostCodes(`pkgname=sound-theme-smooth
url='https://www.pling.com/p/1187979/'
_src_url='https://my.opendesktop.org/s/QrcjmXiTpqQsciE/download/Smooth_v1.2.tar.gz'
source=("${pkgname}-${pkgver}.tar.gz::${_src_url}")`)
	if _, ok := got["SRC-002"]; !ok {
		t.Errorf("expected SRC-002 for an opaque community share link, got %v", got)
	}
	if _, ok := got["SRC-003"]; ok {
		t.Error("SRC-002 and SRC-003 should not both fire on the same entry")
	}
}

// A source whose provenance genuinely cannot be established must keep firing.
// chromium-widevine fetches a proprietary blob from an opaque component-updater
// path; allowlisting www.google.com would wave through every path on that
// domain, so it stays flagged.
func TestUnverifiableSourceStillFlagged(t *testing.T) {
	got := hostCodes(`pkgname=chromium-widevine
url='https://www.widevine.com/'
source=(https://www.google.com/dl/release2/chrome_component/accssjtqfpf5qicscrptql4jyyxa_4.10.2934.0/oimompecagnajdejgnnjijobebaeigek_4.10.2934.0_linux_ph722a3wl2goebkpserszm6bde.crx3)`)
	if _, ok := got["SRC-003"]; !ok {
		t.Errorf("expected SRC-003 for an opaque blob on a non-upstream host, got %v", got)
	}
}

// The allowlist must not become a blanket pass for uncommon hosts.
func TestUncommonHostStillFlagged(t *testing.T) {
	got := hostCodes(`pkgname=x
url="https://x.example.org"
source=("git+https://random-vps.example.net/u/r.git")`)
	if _, ok := got["SRC-001"]; !ok {
		t.Errorf("expected SRC-001 for a VCS source on an uncommon host, got %v", got)
	}
}

// No CHK-006 rule: md5/sha1 in a PKGBUILD is NOT an integrity gap.
//
// The rule that briefly lived here flagged remote sources pinned with md5 or
// sha1, on the reasoning that both are broken. They are broken for COLLISIONS —
// where the attacker chooses both files. The threat a PKGBUILD checksum defends
// against is a mirror or upstream swapping the published tarball, which needs a
// SECOND PREIMAGE against a fixed hash, and neither md5 nor sha1 is broken for
// that. The one scenario collision weakness enables is a maintainer preparing a
// benign/malicious pair in advance — and a maintainer already controls the
// PKGBUILD, build() and the install scriptlet, so it buys them nothing.
//
// It fired on 14 of 158 real packages, all correctly by its own definition and
// none of them a risk. This test pins the absence so it does not come back.
func TestNoBrokenHashRule(t *testing.T) {
	pkgbuild := `pkgname=x
url="https://example.org/x"
source=("https://example.org/x-1.0.tar.gz")
md5sums=('604fad389740b481d16a40d74c3b49fd')`
	for _, h := range Scan(map[string]string{"PKGBUILD": pkgbuild}) {
		if h.Code == "CHK-006" {
			t.Errorf("md5 on a published tarball is not an integrity gap: %+v", h)
		}
	}
}
