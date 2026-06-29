package ui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/manticore-projects/aurscan/internal/scan"
)

// ReportTo is the aurscan aggregation address. Reports are collected here and
// triaged before any upstream disclosure; the Arch aur-general list is not a
// suitable destination for automated LLM-assisted reports.
const ReportTo = "aurscan@manticore-projects.com"

const pkgURLFmt = "https://aur.archlinux.org/packages/%s"

// WriteReport drafts a security report to a temp file and returns its path.
// The report is never sent automatically.
func WriteReport(r scan.Result) string {
	path := filepath.Join(os.TempDir(), "aurscan-report-"+r.Pkg+".txt")
	var sb strings.Builder
	fmt.Fprintf(&sb, "Subject: [SECURITY] Possibly malicious AUR package: %s\n\n", r.Pkg)
	fmt.Fprintf(&sb, "Package : %s\nAUR page: "+pkgURLFmt+"\n", r.Pkg, r.Pkg)
	sb.WriteString("Scanner : aurscan (automated Claude-model PKGBUILD analysis)\n")
	fmt.Fprintf(&sb, "Verdict : %s (confidence %.0f%%)\n\nSummary : %s\n\nFindings:\n",
		r.V.Verdict, r.V.Confidence, r.V.Summary)
	for _, f := range r.V.Findings {
		fmt.Fprintf(&sb, "  - [%s] %s: %s\n      snippet: %s\n", f.Severity, f.File, f.Why, f.Quote)
	}
	sb.WriteString("\nNOTE: This report was produced by an automated LLM-based scanner and\n" +
		"has been reviewed by the submitting user before sending. Please verify\n" +
		"independently.\n")
	os.WriteFile(path, []byte(sb.String()), 0o644)
	return path
}

// offerReport prints reporting instructions and optionally opens a mail client.
func offerReport(r scan.Result, prompt func(string) string) {
	path := WriteReport(r)
	subject := "[SECURITY] Possibly malicious AUR package: " + r.Pkg
	w := TerminalWidth()
	fmt.Println()
	fmt.Println(Bold("Report drafted: ") + path)
	fmt.Println("  1. " + WrapLine("Review it, then email it to "+Bold(ReportTo), w-5, "     "))
	fmt.Println("  2. " + WrapLine("Also file a deletion request on the AUR web page:", w-5, "     "))
	fmt.Println("     " + WrapLine(fmt.Sprintf(pkgURLFmt+"  ->  'Submit Request' -> 'Deletion'", r.Pkg), w-5, "     "))
	if _, err := exec.LookPath("xdg-email"); err == nil && prompt != nil {
		if strings.ToLower(strings.TrimSpace(prompt("  Open your mail client now? [y/N] "))) == "y" {
			body, _ := os.ReadFile(path)
			_ = exec.Command("xdg-email", "--subject", subject, "--body", string(body), ReportTo).Start()
		}
	}
}
