package scan

import "testing"

// The ecosystem-wide false positive: an Electron or Rust package that pins its
// dependency resolution must not be blocked for having run a package manager.
func TestPinnedDepsDoNotBlock(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "pkg_manager_build_deps", Triggered: true, File: "PKGBUILD",
			Evidence: "npm ci --cache \"$srcdir/npm-cache\""},
		{ID: "pkg_manager_deps_pinned", Triggered: true, File: "PKGBUILD",
			Evidence: "npm ci", Note: "DEP-001 dependency fetch pinned to a lockfile (static rule)"},
	})
	if v.Verdict != "OK" {
		t.Fatalf("verdict = %q, want OK", v.Verdict)
	}
	for _, f := range v.Findings {
		if f.Severity == "warning" {
			t.Errorf("pinned fetch still produced a warning finding: %+v", f)
		}
	}
	if len(v.Findings) == 0 {
		t.Error("downgraded findings vanished; the fetch must still be reported")
	}
}

// Without the pinning signal the warning stands. This is the whole point of the
// distinction: an unpinned resolve is decided at build time by the registry.
func TestUnpinnedDepsStillWarn(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "pkg_manager_build_deps", Triggered: true, File: "PKGBUILD",
			Evidence: "npm install"},
	})
	if v.Verdict != "SUSPICIOUS" {
		t.Fatalf("verdict = %q, want SUSPICIOUS", v.Verdict)
	}
}

// Pinning answers "will this resolve change?", not "whose dependencies are
// these?". A lockfile must never launder the Atomic Arch signature.
func TestPinningDoesNotClearUnrelatedExec(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "unrelated_pkg_manager_exec", Triggered: true, File: "PKGBUILD",
			Evidence: "npm install atomic-lockfile"},
		{ID: "pkg_manager_deps_pinned", Triggered: true, File: "PKGBUILD",
			Evidence: "npm ci"},
	})
	if v.Verdict != "MALICIOUS" {
		t.Fatalf("verdict = %q, want MALICIOUS — a lockfile does not make a fetch legitimate", v.Verdict)
	}
}

// The existing sibling invariant must survive: pkg_manager_build_deps is still
// the benign form of unrelated_pkg_manager_exec and still a warning.
func TestBuildDepsRemainsTheWarningSibling(t *testing.T) {
	d, ok := checkCatalog["pkg_manager_build_deps"]
	if !ok || d.Severity != "warning" {
		t.Fatal("pkg_manager_build_deps must stay at warning tier")
	}
	p, ok := checkCatalog["pkg_manager_deps_pinned"]
	if !ok || p.Severity != "info" {
		t.Fatal("pkg_manager_deps_pinned must be info tier")
	}
}
