package pipeline

import (
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
