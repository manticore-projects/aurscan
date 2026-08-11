package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manticore-projects/aurscan/internal/scan"
)

func TestRulesOnlyMalicious(t *testing.T) {
	files := scan.Files{"PKGBUILD": `build() { npm install atomic-lockfile; }`}
	r := RunRulesOnly("evil", files)
	if r.V.Verdict != "MALICIOUS" {
		t.Fatalf("verdict = %q, want MALICIOUS", r.V.Verdict)
	}
	if len(r.V.Findings) == 0 {
		t.Fatal("expected findings from static rules")
	}
}

func TestRulesOnlyClean(t *testing.T) {
	files := scan.Files{"PKGBUILD": `build() { make; }
package() { make DESTDIR="$pkgdir" install; }`}
	r := RunRulesOnly("hello", files)
	if r.V.Verdict != "OK" {
		t.Fatalf("verdict = %q, want OK", r.V.Verdict)
	}
}

// TestDisabledShortCircuits proves AURSCAN_DISABLE=1 skips even a package that
// would trip the static rules: instant SKIPPED verdict, no findings.
func TestDisabledShortCircuits(t *testing.T) {
	t.Setenv("AURSCAN_DISABLE", "1")
	files := scan.Files{"PKGBUILD": `build() { npm install atomic-lockfile; }`}
	r := Run("evil", files, "")
	if r.V.Verdict != "SKIPPED" {
		t.Fatalf("verdict = %q, want SKIPPED", r.V.Verdict)
	}
	if len(r.V.Findings) != 0 {
		t.Fatalf("expected no findings while disabled, got %d", len(r.V.Findings))
	}
	if !strings.Contains(r.V.Summary, "AURSCAN_DISABLE") {
		t.Fatalf("summary = %q, want the AURSCAN_DISABLE note", r.V.Summary)
	}
}

// TestDisabledNeverInvokesBackend proves the kill switch really stops all
// scanning: with AURSCAN_DISABLE=1 the model CLI on PATH is never executed
// (a fake claude would write a marker); without it, the same setup runs and
// the marker appears.
func TestDisabledNeverInvokesBackend(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "backend-was-run")
	script := "#!/bin/sh\n: > '" + marker + "'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("AURSCAN_BACKEND", "")
	t.Setenv("AURSCAN_RULES_ONLY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AURSCAN_OPENAI_URL", "")
	t.Setenv("AURSCAN_CONFIG_DIR", t.TempDir()) // empty: no llmN.conf
	t.Setenv("XDG_CACHE_HOME", t.TempDir())     // fresh verdict cache: no stale hits
	scan.ExtraBackends = nil
	t.Cleanup(func() { scan.ExtraBackends = nil })

	files := scan.Files{"PKGBUILD": `build() { npm install atomic-lockfile; }`}

	t.Setenv("AURSCAN_DISABLE", "1")
	r := Run("evil", files, "")
	if r.V.Verdict != "SKIPPED" {
		t.Fatalf("verdict = %q, want SKIPPED", r.V.Verdict)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("model backend was invoked while scanning is disabled")
	}

	t.Setenv("AURSCAN_DISABLE", "")
	r = Run("evil", files, "")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("sanity: backend marker missing after an enabled run: %v", err)
	}
	if !r.Failed {
		t.Fatalf("sanity: fake backend exits 1, want Failed=true, got verdict %q", r.V.Verdict)
	}
}

// TestScoreIgnoresDisable proves --score runs a real scan even when
// AURSCAN_DISABLE=1: the kill switch governs the build hooks and the plain
// scan gate, not the explicit scoring query.
func TestScoreIgnoresDisable(t *testing.T) {
	t.Setenv("AURSCAN_DISABLE", "1")
	t.Setenv("PATH", t.TempDir()) // no claude/codex
	t.Setenv("AURSCAN_BACKEND", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AURSCAN_OPENAI_URL", "")
	t.Setenv("AURSCAN_CONFIG_DIR", t.TempDir()) // empty: no llmN.conf
	scan.ExtraBackends = nil
	t.Cleanup(func() { scan.ExtraBackends = nil })

	files := scan.Files{"PKGBUILD": `build() { npm install atomic-lockfile; }`}
	r := RunScored("evil", files, "")
	if r.V.Verdict != "MALICIOUS" {
		t.Fatalf("verdict = %q, want MALICIOUS", r.V.Verdict)
	}
	if len(r.V.Findings) == 0 {
		t.Fatal("expected findings: --score must not skip the scan")
	}
}

// TestRunNoBackendNote pins down the unchanged State A: with no backend
// configured at all (no env backend, no llmN.conf), Run returns the static-rules
// verdict carrying the original "no LLM backend configured" note — NOT the
// chain-exhaustion path.
func TestRunNoBackendNote(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no claude/codex
	t.Setenv("AURSCAN_BACKEND", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AURSCAN_OPENAI_URL", "")
	t.Setenv("AURSCAN_RULES_ONLY", "")
	t.Setenv("AURSCAN_CONFIG_DIR", t.TempDir()) // empty: no llmN.conf
	scan.ExtraBackends = nil
	t.Cleanup(func() { scan.ExtraBackends = nil })

	files := scan.Files{"PKGBUILD": `build() { make; }`}
	r := Run("hello", files, "")
	if r.V.Verdict != "OK" {
		t.Fatalf("verdict = %q, want OK", r.V.Verdict)
	}
	if !strings.Contains(r.V.Summary, "no LLM backend configured") {
		t.Fatalf("summary = %q, want the 'no LLM backend configured' note", r.V.Summary)
	}
}
