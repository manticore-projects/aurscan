package ui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/manticore-projects/aurscan/internal/scan"
)

// MailingList is where the July 2025 CHAOS RAT cleanup was coordinated.
const MailingList = "aur-general@lists.archlinux.org"

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
	fmt.Println()
	fmt.Println(Bold("Report drafted: ") + path)
	fmt.Printf("  1. Review it, then email it to %s\n", Bold(MailingList))
	fmt.Println("  2. Also file a deletion request on the AUR web page:")
	fmt.Printf("     "+pkgURLFmt+"  ->  'Submit Request' -> 'Deletion'\n", r.Pkg)
	if _, err := exec.LookPath("xdg-email"); err == nil && prompt != nil {
		if strings.ToLower(strings.TrimSpace(prompt("  Open your mail client now? [y/N] "))) == "y" {
			body, _ := os.ReadFile(path)
			_ = exec.Command("xdg-email", "--subject", subject, "--body", string(body), MailingList).Start()
		}
	}
}
