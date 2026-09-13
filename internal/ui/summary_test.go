package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/manticore-projects/aurscan/internal/scan"
)

// On an OK verdict the derived count line restates the green badge and counts
// the findings printed two lines below it. With a synopsis present it is pure
// redundancy and is dropped.
func TestDerivedSummaryDroppedOnCleanOKWithSynopsis(t *testing.T) {
	v := scan.Verdict{
		Verdict:    "OK",
		Confidence: 80,
		Summary:    "No suspicious behaviour; 2 informational items noted for context.",
		Synopsis:   "Installs a prebuilt logalize binary from GitHub releases.",
	}
	if showDerivedSummary(v) {
		t.Error("the count line must be suppressed on a clean OK with a synopsis")
	}
}

// Without a synopsis the count line is the only body text there is, so it stays.
func TestDerivedSummaryKeptWhenThereIsNoSynopsis(t *testing.T) {
	v := scan.Verdict{Verdict: "OK", Summary: "No suspicious behaviour found."}
	if !showDerivedSummary(v) {
		t.Error("with no synopsis the count line is the only body text; keep it")
	}
}

// A non-OK verdict's summary carries the imperative ("do not build"), which the
// badge does not. It stays regardless of the synopsis.
func TestDerivedSummaryKeptOnAdverseVerdict(t *testing.T) {
	for _, verdict := range []string{"SUSPICIOUS", "MALICIOUS"} {
		v := scan.Verdict{Verdict: verdict, Summary: "…do not build.", Synopsis: "Builds x."}
		if !showDerivedSummary(v) {
			t.Errorf("%s: the imperative must survive", verdict)
		}
	}
}

// The catalog description is printed once, in the drafted report — never once
// per finding in the terminal.
func TestTerminalPrintsNoteNotCatalogDescription(t *testing.T) {
	findings := []scan.Finding{
		{
			File: "PKGBUILD", Severity: "info", ID: "remote_source_unreviewed",
			Label: "remote source archive not reviewed",
			Note:  "A pre-compiled binary tarball from GitHub releases.",
			Why: "A remote source=() archive's contents were not inspected — checksum-pinned " +
				"but unreviewed, so build hooks inside it (setup.py, build.rs, configure) were " +
				"not seen — A pre-compiled binary tarball from GitHub releases.",
		},
	}
	var buf bytes.Buffer
	printFindings(&buf, findings, 100, false)
	out := buf.String()
	if strings.Contains(out, "checksum-pinned") {
		t.Errorf("the catalog description leaked into terminal output:\n%s", out)
	}
	for _, want := range []string{"remote source archive not reviewed", "PKGBUILD",
		"pre-compiled binary tarball"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

// Legacy and fallback findings carry no split Note. They must still print
// something rather than an empty line.
func TestTerminalFallsBackToWhyWhenNoteIsEmpty(t *testing.T) {
	var buf bytes.Buffer
	printFindings(&buf, []scan.Finding{
		{File: "PKGBUILD", Severity: "warning", Why: "legacy free-text finding"},
	}, 100, false)
	if !strings.Contains(buf.String(), "legacy free-text finding") {
		t.Errorf("a finding with no Note printed nothing useful:\n%s", buf.String())
	}
}
