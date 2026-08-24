package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manticore-projects/aurscan/internal/rules"
)

// A file the collector skips must be RECORDED, not dropped. Absent and
// "present but not read" are different facts and only one of them is about the
// package: openssl-1.1 ships 41 patches, and under the old behaviour its tail
// vanished and was reported as a missing source.
func TestCollectDirRecordsOmittedFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, n int) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Repeat("x", n)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("PKGBUILD", 100)
	write("small.patch", 100)
	write("huge.patch", maxFileBytes+1)

	files, err := CollectDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["huge.patch"]; !ok {
		t.Fatal("an oversized file must still appear in the set, marked omitted")
	}
	if !rules.IsOmitted(files["huge.patch"]) {
		t.Error("huge.patch should carry the omission marker")
	}
	if rules.IsOmitted(files["small.patch"]) {
		t.Error("small.patch was readable and must carry its content")
	}
}

// A PKGBUILD too large to read is not a usable scan.
func TestCollectDirRejectsOmittedPKGBUILD(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"),
		[]byte(strings.Repeat("x", maxFileBytes+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := CollectDir(dir); err == nil {
		t.Fatal("expected an error when the PKGBUILD itself could not be read")
	}
}

// The manifest must never tell the auditor a truncated set is complete. That
// assertion is what would let a payload in an unread file pass a review that
// claimed to have seen everything.
func TestPromptDoesNotClaimCompletenessWhenTruncated(t *testing.T) {
	files := Files{
		"PKGBUILD":   "pkgname=foo",
		"big.patch":  rules.OmittedContent,
		"good.patch": "--- a\n+++ b\n",
	}
	p := buildPrompt("foo", files, Signals{})

	if !strings.Contains(p, "FILES PRESENT BUT NOT SUPPLIED") {
		t.Error("omitted files must be listed under their own heading")
	}
	if !strings.Contains(p, "incomplete_scan") {
		t.Error("the auditor must be told to trigger incomplete_scan")
	}
	if strings.Contains(p, "Every file in the package is listed above") {
		t.Error("must not claim completeness when files were omitted")
	}
	if strings.Contains(p, rules.OmittedContent) {
		t.Error("the marker itself must never be shown as file content")
	}
	if !strings.Contains(p, "----- FILE: good.patch -----") {
		t.Error("readable files must still be included in full")
	}
	if strings.Contains(p, "----- FILE: big.patch -----") {
		t.Error("an omitted file must not be presented as though it had content")
	}
}

// With nothing omitted the manifest keeps its stronger claim.
func TestPromptClaimsCompletenessWhenIntact(t *testing.T) {
	p := buildPrompt("foo", Files{"PKGBUILD": "pkgname=foo"}, Signals{})
	if !strings.Contains(p, "Every file in the package is listed above") {
		t.Error("a complete set should say so")
	}
	if strings.Contains(p, "FILES PRESENT BUT NOT SUPPLIED") {
		t.Error("no omissions, so no omission section")
	}
}
