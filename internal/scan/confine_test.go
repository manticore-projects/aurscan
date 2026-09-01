package scan

import "testing"

// The two findings that blocked python-pyhanko and python-pyhanko-certvalidator:
// neither is a statement about the package, and neither may block a build.
func TestIncompleteScanConfinedToScripts(t *testing.T) {
	cases := []struct {
		name       string
		check      Check
		wantID     string
		wantVerdct string
	}{
		{
			"remote sdist tarball",
			Check{ID: "incomplete_scan", Triggered: true, File: "PKGBUILD",
				Evidence: "source=(pyhanko_certvalidator-0.32.0.tar.gz::https://files.pythonhosted.org/...)"},
			"remote_source_unreviewed", "OK",
		},
		{
			"stale built artifact",
			Check{ID: "incomplete_scan", Triggered: true,
				File:     "python-pyhanko-0.36.2-1-any.pkg.tar.zst",
				Evidence: "built package artifact present"},
			"remote_source_unreviewed", "OK",
		},
		{
			"github release zip",
			Check{ID: "incomplete_scan", Triggered: true, File: "PKGBUILD",
				Evidence: "https://github.com/x/y/archive/v1.2.zip"},
			"remote_source_unreviewed", "OK",
		},
		// Must still block: these are scripts the repository itself should hold.
		{
			"install scriptlet",
			Check{ID: "incomplete_scan", Triggered: true, File: "PKGBUILD",
				Evidence: "install=xsnow.install"},
			"incomplete_scan", "SUSPICIOUS",
		},
		{
			"patch file",
			Check{ID: "incomplete_scan", Triggered: true, File: "PKGBUILD",
				Evidence: "source=(fix-build.patch)"},
			"incomplete_scan", "SUSPICIOUS",
		},
		{
			"pacman hook",
			Check{ID: "incomplete_scan", Triggered: true, File: ".SRCINFO",
				Evidence: "source = 99-thing.hook"},
			"incomplete_scan", "SUSPICIOUS",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := confineIncompleteScan([]Check{tc.check})
			if got[0].ID != tc.wantID {
				t.Errorf("id = %q, want %q", got[0].ID, tc.wantID)
			}
			v, _, _, _ := deriveVerdict([]Check{tc.check})
			if v != tc.wantVerdct {
				t.Errorf("verdict = %q, want %q", v, tc.wantVerdct)
			}
		})
	}
}

// A downgraded finding must remain visible, not vanish.
func TestDowngradedFindingStillReported(t *testing.T) {
	v, findings, _, summary := deriveVerdict([]Check{{
		ID: "incomplete_scan", Triggered: true, File: "PKGBUILD",
		Evidence: "pyhanko_certvalidator-0.32.0.tar.gz",
		Note:     "sdist contents unreviewed",
	}})
	if v != "OK" {
		t.Fatalf("verdict = %q, want OK", v)
	}
	if len(findings) != 1 || findings[0].Severity != "info" {
		t.Fatalf("findings = %+v, want one info finding", findings)
	}
	if summary == "No suspicious behaviour found beyond normal makepkg operation." {
		t.Error("info finding was silently dropped from the summary")
	}
}
