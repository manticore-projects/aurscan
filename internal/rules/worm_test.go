package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func wormCodes(files map[string]string) map[string]Hit {
	m := map[string]Hit{}
	for _, h := range Scan(files) {
		m[h.Code] = h
	}
	return m
}

// loadWorm reads the sanitized xsnow-class fixture from testdata.
func loadWorm(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "xsnow-worm")
	files := map[string]string{}
	for _, n := range []string{"PKGBUILD", ".xsnow.install"} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		files[n] = string(b)
	}
	return files
}

// The whole point of the exercise: the payload lives in a dot-prefixed install
// scriptlet, and every stage of it must be caught deterministically, with no
// model involved.
func TestInstallScriptletWormCaught(t *testing.T) {
	got := wormCodes(loadWorm(t))
	want := []string{
		"PERSIST-007", // Tor-fetched binary dropped in /usr/local/bin
		"PERSIST-008", // chmod +x on it
		"PERSIST-009", // systemd unit written through a heredoc redirect
		"PKGMGR-001",  // pacman -S tor from a scriptlet
		"EXFIL-004",   // onion C2
		"EXFIL-005",   // socks5h proxy
		"CRED-004",    // /home/*/.ssh and /root/.ssh enumeration
		"CRED-005",    // ~/.ssh moved aside and symlinked
		"WORM-001",    // cp "$BASH_SOURCE"
		"WORM-002",    // ssh://aur@aur.archlinux.org
		"WORM-003",    // git push
		"HOOK-001",    // work detached into the background
		"REF-002",     // install= names a dot-prefixed file
	}
	for _, c := range want {
		if _, ok := got[c]; !ok {
			t.Errorf("expected %s to fire on the worm fixture", c)
		}
	}
	if f := Floor(Scan(loadWorm(t)), false); f != "MALICIOUS" {
		t.Fatalf("floor = %q, want MALICIOUS", f)
	}
}

// PERSIST-009 exists because the payload of a heredoc-written unit file lives
// in a Redirect, which no command-scoped rule could previously see.
func TestHeredocRedirectTargetIsVisible(t *testing.T) {
	got := wormCodes(map[string]string{"x.install": `post_install() {
  cat <<EOF >/etc/systemd/system/Backdoor.service
[Service]
ExecStart=/usr/local/bin/payload
EOF
}`})
	if _, ok := got["PERSIST-009"]; !ok {
		t.Fatalf("PERSIST-009 did not fire on a heredoc-written systemd unit: %v", got)
	}
}

// A PKGBUILD-only scan of a package whose payload is in install= must report
// that it is incomplete rather than that the package is clean.
func TestPKGBUILDOnlyScanIsIncomplete(t *testing.T) {
	pkgbuild := loadWorm(t)["PKGBUILD"]
	got := wormCodes(map[string]string{"PKGBUILD": pkgbuild})
	if _, ok := got["REF-001"]; !ok {
		t.Fatalf("REF-001 did not fire when the referenced scriptlet was absent: %v", got)
	}
	if f := Floor(Scan(map[string]string{"PKGBUILD": pkgbuild}), false); f == "" {
		t.Fatal("a scan missing the referenced install scriptlet must carry a floor")
	}
}

// install="$pkgname.install" must resolve, and a present scriptlet must not
// raise REF-001.
func TestReferenceResolution(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		wantRef string // "" means no REF-001
	}{
		{"present-literal", map[string]string{
			"PKGBUILD":  "pkgname=foo\ninstall=foo.install\n",
			"foo.tance": "", "foo.install": "post_install(){ echo hi; }",
		}, ""},
		{"present-var", map[string]string{
			"PKGBUILD":    "pkgname=foo\ninstall=\"$pkgname.install\"\n",
			"foo.install": "post_install(){ echo hi; }",
		}, ""},
		{"missing", map[string]string{
			"PKGBUILD": "pkgname=foo\ninstall=foo.install\n",
		}, "REF-001"},
		{"missing-from-srcinfo", map[string]string{
			"PKGBUILD": "pkgname=foo\n",
			".SRCINFO": "pkgbase = foo\n\tinstall = foo.install\n",
		}, "REF-001"},
		{"no-install-at-all", map[string]string{
			"PKGBUILD": "pkgname=foo\nbuild(){ make; }\n",
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := wormCodes(c.files)
			_, fired := got["REF-001"]
			if c.wantRef == "" && fired {
				t.Errorf("REF-001 false positive: %v", got["REF-001"])
			}
			if c.wantRef != "" && !fired {
				t.Errorf("expected REF-001, got %v", got)
			}
		})
	}
}

// The floor must stay narrow: an ordinary critical hit in a PKGBUILD is still
// the model's call unless strict mode is on.
func TestFloorIsNarrowByDefault(t *testing.T) {
	hits := Scan(map[string]string{"PKGBUILD": `package() { sudo make install; }`})
	if len(hits) == 0 {
		t.Fatal("expected PRIV-001 to fire")
	}
	if f := Floor(hits, false); f != "" {
		t.Errorf("default floor = %q, want no floor for a PKGBUILD-only critical", f)
	}
	if f := Floor(hits, true); f != "SUSPICIOUS" {
		t.Errorf("strict floor = %q, want SUSPICIOUS", f)
	}
}

// A clean package must acquire neither hits nor a floor.
func TestCleanPackageHasNoFloor(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": `pkgname=hello
pkgver=1.0
url="https://example.org/hello"
source=("git+https://github.com/upstream/hello.git")
build() { make; }
package() { make DESTDIR="$pkgdir" install; }`,
	}
	if f := Floor(Scan(files), false); f != "" {
		t.Fatalf("floor = %q on a clean package, want none: %v", f, Scan(files))
	}
}

// A legitimate scriptlet that just prints advice must not be dragged in by the
// new install-only rules.
func TestBenignScriptletUnaffected(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": "pkgname=foo\ninstall=foo.install\n",
		"foo.install": `post_install() {
  echo "Run 'systemctl enable --now foo.service' to start foo at boot."
  echo "You may need to add yourself to the foo group: sudo gpasswd -a $USER foo"
}
post_upgrade() { post_install; }`,
	}
	if f := Floor(Scan(files), false); f != "" {
		t.Fatalf("floor = %q on a benign advisory scriptlet, want none: %v", f, Scan(files))
	}
}
