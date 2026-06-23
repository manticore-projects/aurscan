package pipeline

import (
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
