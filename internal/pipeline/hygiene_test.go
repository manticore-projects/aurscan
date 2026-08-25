package pipeline

import (
	"strings"
	"testing"

	"github.com/manticore-projects/aurscan/internal/rules"
	"github.com/manticore-projects/aurscan/internal/scan"
)

// Build-cache confinement is a hygiene issue, not a security finding: cargo and
// go without a confined CARGO_HOME/GOMODCACHE write to ~/.cargo and ~/go on
// nearly every Rust and Go package in the AUR. It must be reported and must not
// block — 7 of 20 sampled packages were pushed to SUSPICIOUS by this alone.
func TestInformationalHitsDoNotBlock(t *testing.T) {
	t.Setenv("AURSCAN_RULES_ONLY", "1")
	t.Setenv("AURSCAN_CONFIG_DIR", t.TempDir())
	t.Setenv("AURSCAN_CACHE_DIR", t.TempDir())

	files := scan.Files{"PKGBUILD": `pkgname=x
pkgver=1.0
url="https://example.org/x"
source=("git+https://github.com/u/x.git")
build(){ cd x; cargo build --release; }
package(){ install -Dm755 x "$pkgdir/usr/bin/x"; }`}

	hits := rules.Scan(files)
	if len(hits) == 0 {
		t.Fatal("expected BLD-002 to be reported")
	}
	if w := rules.Worst(hits); w == rules.Critical || w == rules.High {
		t.Fatalf("build-cache confinement should stay below High, got %v: %v", w, hits)
	}

	r := Run("x", files, "")
	if r.V.Verdict != "OK" {
		t.Errorf("verdict = %q, want OK — an informational hit must not block", r.V.Verdict)
	}
	if !strings.Contains(r.V.Summary, "informational") {
		t.Errorf("the finding must still be surfaced: %q", r.V.Summary)
	}
}

// A high-severity hit still blocks.
func TestHighSeverityStillBlocks(t *testing.T) {
	t.Setenv("AURSCAN_RULES_ONLY", "1")
	t.Setenv("AURSCAN_CONFIG_DIR", t.TempDir())
	t.Setenv("AURSCAN_CACHE_DIR", t.TempDir())

	files := scan.Files{"PKGBUILD": `pkgname=x
source=("https://example.org/x.tar.gz")
sha256sums=('SKIP')`}
	r := Run("x", files, "")
	if r.V.Verdict == "OK" {
		t.Errorf("an unverified remote source must not pass: %q", r.V.Summary)
	}
}
