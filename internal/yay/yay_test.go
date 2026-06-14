package yay

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPackageRootFindsPKGBUILDParent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(dir, "pkg", "usr", "bin")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := packageRoot(nested); got != dir {
		t.Fatalf("packageRoot(%q) = %q, want %q", nested, got, dir)
	}
}
