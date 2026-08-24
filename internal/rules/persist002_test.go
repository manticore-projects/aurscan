package rules

import "testing"

func TestPersist002Calibration(t *testing.T) {
	cases := []struct {
		name, file, content string
		want                bool
	}{
		// the 51 real-world false positives
		{"reuse-toml", "REUSE.toml", "path = [\n  \"*.service\",\n  \"*.timer\",\n]", false},
		{"desktop-file", "foo.desktop", "Exec=foo --timer", false},
		{"readme", "README.md", "Enable the foo.timer unit to run it nightly.", false},
		{"patch-hunk", "x.patch", "+++ b/units/foo.timer", false},
		// normal packaging: ship a timer into $pkgdir
		{"install-into-pkgdir", "PKGBUILD", `package(){ install -Dm644 foo.timer "$pkgdir/usr/lib/systemd/system/foo.timer"; }`, false},
		// a shipped unit file is data, not an action
		{"shipped-unit", "foo.timer", "[Timer]\nOnCalendar=daily\n", false},
		// real persistence
		{"enable-in-scriptlet", "x.install", "post_install(){ systemctl enable --now evil.timer; }", true},
		{"write-unit-to-etc", "x.install", "post_install(){ cat <<EOF >/etc/systemd/system/evil.timer\n[Timer]\nOnCalendar=*:0/5\nEOF\n}", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fired := false
			for _, h := range Scan(map[string]string{c.file: c.content}) {
				if h.Code == "PERSIST-002" || h.Code == "PERSIST-010" {
					fired = true
					t.Logf("  %s: %s", h.Code, h.Snippet)
				}
			}
			if fired != c.want {
				t.Errorf("fired=%v, want %v", fired, c.want)
			}
		})
	}
}
