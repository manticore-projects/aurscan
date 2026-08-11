package ui

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout redirects os.Stdout for the duration of the test and returns
// a func that closes the pipe and returns everything printed so far.
func captureStdout(t *testing.T) func() string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	t.Cleanup(func() {
		w.Close()
		os.Stdout = old
	})
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	return func() string {
		w.Close()
		return <-done
	}
}

// TestProgressSilentWhenDisabled proves the kill switch silences the
// "scanning ..." announce: with AURSCAN_DISABLE=1 nothing is scanned, so
// nothing is printed.
func TestProgressSilentWhenDisabled(t *testing.T) {
	t.Setenv("AURSCAN_DISABLE", "1")
	got := captureStdout(t)
	Progress("evilpkg", 3)
	if out := got(); out != "" {
		t.Fatalf("Progress printed %q while scanning is disabled", out)
	}
}

// TestProgressPrintsWhenEnabled pins the announce for a real scan.
func TestProgressPrintsWhenEnabled(t *testing.T) {
	t.Setenv("AURSCAN_DISABLE", "")
	got := captureStdout(t)
	Progress("evilpkg", 3)
	if out := got(); !strings.Contains(out, "scanning evilpkg (3 files)") {
		t.Fatalf("Progress output = %q, want the scanning line", out)
	}
}
