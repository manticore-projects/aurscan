package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanArgsDisabledSkipsCollection(t *testing.T) {
	t.Setenv("AURSCAN_DISABLE", "1")

	results := scanArgs([]string{t.TempDir()})
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if got := results[0].V.Verdict; got != "SKIPPED" {
		t.Fatalf("verdict = %q, want SKIPPED", got)
	}
}

func TestScoreModeIgnoresDisable(t *testing.T) {
	t.Setenv("AURSCAN_DISABLE", "1")
	t.Setenv("AURSCAN_RULES_ONLY", "1")

	path := filepath.Join(t.TempDir(), "PKGBUILD")
	if err := os.WriteFile(path, []byte("pkgname=clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := scoreMode([]string{path}); got != 80 {
		t.Fatalf("scoreMode exit = %d, want 80 from a real rules-only scan", got)
	}
}
