package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewPaclistParsesYayOutput(t *testing.T) {
	list, err := newPaclist("aur/orca-git 49.beta.r12-2 -> 49.beta.r13-1\nbrave-bin 1.2.3-1 -> 1.2.4-1\n")
	if err != nil {
		t.Fatal(err)
	}
	if list.Format != paclistFormat {
		t.Fatalf("format = %q, want %q", list.Format, paclistFormat)
	}
	if got, want := len(list.Packages), 2; got != want {
		t.Fatalf("package count = %d, want %d", got, want)
	}
	if got, want := list.Packages[0].Name, "orca-git"; got != want {
		t.Fatalf("first package name = %q, want %q", got, want)
	}
	if got, want := list.Packages[0].Available, "49.beta.r13-1"; got != want {
		t.Fatalf("available version = %q, want %q", got, want)
	}
}

func TestNewPaclistRejectsBadPackageName(t *testing.T) {
	if _, err := newPaclist("bad/name/extra 1 -> 2\n"); err == nil {
		t.Fatal("expected invalid package name error")
	}
}

func TestReadPaclistPackages(t *testing.T) {
	dir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })

	data := []byte(`{
  "format": "aurscan-paclist-v1",
  "generated_at": "2026-06-14T16:30:00Z",
  "host": "example",
  "source": "yay -Qua",
  "packages": [
    {"name": "orca-git", "current": "1", "available": "2", "raw": "orca-git 1 -> 2"},
    {"name": "orca-git", "current": "1", "available": "2", "raw": "orca-git 1 -> 2"},
    {"name": "brave-bin", "current": "3", "available": "4", "raw": "brave-bin 3 -> 4"}
  ]
}`)
	if err := os.WriteFile(filepath.Join(dir, paclistFile), data, 0o644); err != nil {
		t.Fatal(err)
	}
	names, err := readPaclistPackages()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(names), 2; got != want {
		t.Fatalf("package count = %d, want %d", got, want)
	}
	if names[0] != "orca-git" || names[1] != "brave-bin" {
		t.Fatalf("names = %#v, want orca-git/brave-bin", names)
	}
}

func TestReadPaclistPackagesRequiresFile(t *testing.T) {
	dir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })

	if _, err := readPaclistPackages(); err == nil {
		t.Fatal("expected missing paclist error")
	}
}
