package scan

import "testing"

// A sweep of 20 real AUR packages returned 13 MALICIOUS, none of them
// malicious. The cause was not model judgement — the model was judging
// correctly and had no vocabulary for the judgement. arc-client's own note read
// "this is a normal part of building this project, not an attack" while it
// triggered a critical check, because the checklist offered no id for "npm ran,
// and it was legitimate". deriveVerdict cannot read an exculpatory note.
func TestBenignSiblingsExistForEveryOverreachingCritical(t *testing.T) {
	pairs := []struct{ critical, benign string }{
		{"unrelated_pkg_manager_exec", "pkg_manager_build_deps"},
		{"privilege_persistence", "sudoers_for_own_service"},
		{"privilege_persistence", "service_enabled_by_scriptlet"},
	}
	for _, p := range pairs {
		c, ok := checkCatalog[p.critical]
		if !ok || c.Severity != "critical" {
			t.Errorf("%s should be a critical check", p.critical)
		}
		b, ok := checkCatalog[p.benign]
		if !ok {
			t.Errorf("%s is missing — the model has no way to report the benign form of %s",
				p.benign, p.critical)
			continue
		}
		if b.Severity != "warning" {
			t.Errorf("%s severity = %q, want warning: reporting a legitimate form must not block",
				p.benign, b.Severity)
		}
	}
	if d, ok := checkCatalog["packaging_policy_violation"]; !ok || d.Severity != "warning" {
		t.Error("packaging_policy_violation must exist at warning tier — a guideline breach is not an attack")
	}
}

// The benign siblings must not block the build.
func TestBenignSiblingsDoNotBlock(t *testing.T) {
	for _, id := range []string{
		"pkg_manager_build_deps",
		"service_enabled_by_scriptlet",
		"sudoers_for_own_service",
		"packaging_policy_violation",
	} {
		v := VerdictFromChecks([]Check{{ID: id, Triggered: true, File: "PKGBUILD", Evidence: "x"}})
		if v.Verdict == "MALICIOUS" {
			t.Errorf("%s produced MALICIOUS on its own", id)
		}
	}
}

// And the real thing still blocks.
func TestGenuineCriticalStillBlocks(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "unrelated_pkg_manager_exec", Triggered: true, File: "PKGBUILD",
			Evidence: "npm install atomic-lockfile"},
	})
	if v.Verdict != "MALICIOUS" {
		t.Errorf("verdict = %q, want MALICIOUS", v.Verdict)
	}
}

// The prompt must tell the model when to choose a sibling. Without this the
// catalog change alone does nothing — the model never sees checkCatalog.
func TestPromptDocumentsTheSiblings(t *testing.T) {
	for _, want := range []string{
		"pkg_manager_build_deps",
		"service_enabled_by_scriptlet",
		"sudoers_for_own_service",
		"packaging_policy_violation",
		"belongs at\nwarning tier",
	} {
		if !contains(Instructions, want) {
			t.Errorf("the auditor instructions do not mention %q", want)
		}
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
