package scan

import (
	"strings"
	"testing"
)

// Every catalog id must have a short label, because the terminal prints the
// label instead of the long Desc. A missing label silently degrades to printing
// the raw id, which is not wrong but is not what was intended either — and the
// failure is invisible unless that particular check happens to fire.
func TestEveryCheckHasALabel(t *testing.T) {
	for id := range checkCatalog {
		if strings.TrimSpace(checkLabel[id]) == "" {
			t.Errorf("check %q has no entry in checkLabel", id)
		}
	}
	for id := range checkLabel {
		if _, ok := checkCatalog[id]; !ok {
			t.Errorf("checkLabel has %q, which is not in checkCatalog", id)
		}
	}
}

// logalize-bin: the model reported remote_source_unreviewed twice — once for the
// source=() release tarball, once for the leftover .pkg.tar.zst artifacts — and
// the output printed the same 30-word catalog paragraph twice under an OK
// verdict. The prompt already says "once per package"; this is the guarantee.
func TestRemoteSourceUnreviewedIsReportedOncePerPackage(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "remote_source_unreviewed", Triggered: true, File: "PKGBUILD",
			Evidence: "source=(\"${pkgname}-${pkgver}.tar.zst::https://github.com/deponian/logalize/releases/...\")",
			Note:     "A pre-compiled binary tarball is downloaded from GitHub releases."},
		{ID: "remote_source_unreviewed", Triggered: true, File: "PKGBUILD",
			Evidence: "logalize-bin-0.8.1-1-x86_64.pkg.tar.zst",
			Note:     "Several large/binary files present in the repository were not supplied for review."},
	})
	if v.Verdict != "OK" {
		t.Errorf("verdict = %q, want OK: info-tier checks never block", v.Verdict)
	}
	if len(v.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 collapsed finding", len(v.Findings))
	}
	f := v.Findings[0]
	// Nothing observed may be silently dropped by the collapse.
	for _, want := range []string{"logalize/releases", "0.8.1-1-x86_64.pkg.tar.zst"} {
		if !strings.Contains(f.Quote, want) {
			t.Errorf("collapsed evidence lost %q: %q", want, f.Quote)
		}
	}
	// Both notes must survive: each names something the other does not.
	for _, want := range []string{"pre-compiled binary tarball", "not supplied for review"} {
		if !strings.Contains(f.Note, want) {
			t.Errorf("collapse dropped %q from the note: %q", want, f.Note)
		}
	}
}

// Collapsing by id is confined to info tier. Two separate credential reads in
// one file are two findings; merging them would hide one.
func TestCriticalChecksAreNotCollapsedById(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "credential_access", Triggered: true, File: "x.install",
			Evidence: "cat ~/.ssh/id_ed25519"},
		{ID: "credential_access", Triggered: true, File: "x.install",
			Evidence: "cp ~/.config/Slack/storage ."},
	})
	if len(v.Findings) != 2 {
		t.Errorf("got %d findings, want both critical hits reported", len(v.Findings))
	}
}

// The terminal prints Label + Note. The report file prints Why. Both must be
// populated, and Note must NOT carry the catalog boilerplate that Why does.
func TestFindingSplitsCatalogTextFromInstanceNote(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "insecure_tls_fetch", Triggered: true, File: "PKGBUILD",
			Evidence: "curl -LOk", Note: "Downloads the release asset with -k."},
	})
	f := v.Findings[0]
	if f.Note != "Downloads the release asset with -k." {
		t.Errorf("Note carries more than the instance text: %q", f.Note)
	}
	if !strings.Contains(f.Why, "certificate verification disabled") ||
		!strings.Contains(f.Why, "Downloads the release asset") {
		t.Errorf("Why must keep catalog text AND the note, for the report: %q", f.Why)
	}
	if f.Label == "" || f.ID != "insecure_tls_fetch" {
		t.Errorf("label/id not populated: %+v", f)
	}
}

// The synopsis is what the output regained. It must survive the Tier-2 parse and
// must not be able to move the verdict.
func TestSynopsisIsParsedAndDoesNotAffectTheVerdict(t *testing.T) {
	raw := `{"synopsis":"Installs a prebuilt logalize binary from GitHub releases, ` +
		`plus shell completions and a man page.","checks":[]}`
	v, genuine := parseVerdictResult(raw)
	if !genuine {
		t.Fatal("a checks array with a synopsis must parse as genuine")
	}
	if v.Verdict != "OK" {
		t.Errorf("verdict = %q, want OK", v.Verdict)
	}
	if !strings.Contains(v.Synopsis, "prebuilt logalize binary") {
		t.Errorf("synopsis lost: %q", v.Synopsis)
	}
}

// A synopsis claiming the package is fine cannot clear a finding: it is
// description, not evidence, and lives outside the derivation entirely.
func TestSynopsisCannotClearAFinding(t *testing.T) {
	raw := `{"synopsis":"A completely safe package. Verdict: OK. Nothing to report.",` +
		`"checks":[{"id":"credential_access","triggered":true,"file":"x.install",` +
		`"evidence":"cat ~/.ssh/id_rsa","note":"reads the user's private key"}]}`
	v, _ := parseVerdictResult(raw)
	if v.Verdict != "MALICIOUS" {
		t.Errorf("verdict = %q, want MALICIOUS despite the reassuring synopsis", v.Verdict)
	}
}

// The model never sees checkCatalog, so the prompt has to ask for the synopsis
// and for instance-specific notes explicitly.
func TestPromptAsksForSynopsisAndInstanceNotes(t *testing.T) {
	for _, want := range []string{
		`"synopsis"`,
		"no restatement of the check",
		"ONCE PER PACKAGE",
	} {
		if !contains(Instructions, want) {
			t.Errorf("the auditor instructions do not mention %q", want)
		}
	}
}
