package pipeline

import (
	"testing"

	"github.com/manticore-projects/aurscan/internal/rules"
	"github.com/manticore-projects/aurscan/internal/scan"
)

// An offline scan must still report what it found in checklist vocabulary.
// FloorChecks covers only the hits that constrain the verdict, so a rules-only
// run had an empty check_ids — precisely the field a sweep filters on, because
// a check id says what a package DOES while a verdict label says what a scanner
// called it.
func TestRulesOnlyPopulatesCheckIDs(t *testing.T) {
	t.Setenv("AURSCAN_RULES_ONLY", "1")
	t.Setenv("AURSCAN_CONFIG_DIR", t.TempDir())
	t.Setenv("AURSCAN_CACHE_DIR", t.TempDir())

	files := scan.Files{"PKGBUILD": "pkgname=x\nbuild(){ curl -sfL https://sh.rustup.rs | sh; }"}
	r := Run("x", files, "")
	if len(r.V.Checks) == 0 {
		t.Fatal("an offline scan must record its findings as checks")
	}
	var found bool
	for _, c := range r.V.Checks {
		if c.ID == "unpinned_upstream_installer" {
			found = true
		}
		if !scan.KnownCheckID(c.ID) {
			t.Errorf("unknown check id %q would be recorded as info and silently dropped", c.ID)
		}
	}
	if !found {
		t.Errorf("expected unpinned_upstream_installer, got %+v", r.V.Checks)
	}
}

// AllChecks records every hit; it must never drive a verdict. Only Floor does.
func TestAllChecksDoesNotEscalate(t *testing.T) {
	t.Setenv("AURSCAN_RULES_ONLY", "1")
	t.Setenv("AURSCAN_CONFIG_DIR", t.TempDir())
	t.Setenv("AURSCAN_CACHE_DIR", t.TempDir())

	// A medium-severity hit only: recorded, but not grounds to block.
	files := scan.Files{"PKGBUILD": "pkgname=x\nsource=(http://example.org/x.tar.gz)\nsha256sums=('abc')"}
	hits := rules.Scan(files)
	if len(rules.AllChecks(hits)) == 0 {
		t.Fatal("expected the hit to be recorded")
	}
	if r := Run("x", files, ""); r.V.Verdict != "OK" {
		t.Errorf("verdict = %q, want OK: recording a finding is not escalating it", r.V.Verdict)
	}
}
