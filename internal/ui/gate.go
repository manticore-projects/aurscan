package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/manticore-projects/aurscan/internal/scan"
)

// Progress prints the "scanning ..." line before a model call.
func Progress(pkg string, nfiles int) {
	fmt.Println(Dim(fmt.Sprintf("  scanning %s (%d files) ...", pkg, nfiles)))
}

func sevColor(sev, s string) string {
	switch sev {
	case "critical":
		return Red(s)
	case "warning":
		return Yellow(s)
	}
	return Dim(s)
}

func printVerdict(r scan.Result) {
	badge := map[string]string{
		"OK": Green("  OK  "), "SUSPICIOUS": Yellow(" SUSP "), "MALICIOUS": Red(" MAL! "),
	}[r.V.Verdict]
	fmt.Printf("[%s] %s  %s\n", badge, Bold(r.Pkg),
		Dim(fmt.Sprintf("confidence %.0f%%", r.V.Confidence)))
	if r.V.Summary != "" {
		fmt.Printf("         %s\n", r.V.Summary)
	}
	for _, f := range r.V.Findings {
		fmt.Printf("         %s %s: %s\n", sevColor(f.Severity, "["+f.Severity+"]"), f.File, f.Why)
		if f.Quote != "" {
			q := f.Quote
			if len(q) > 120 {
				q = q[:120]
			}
			fmt.Println(Dim("             > " + q))
		}
	}
}

// WorstExit maps the worst verdict across results to an exit code
// (0 OK, 1 SUSPICIOUS, 2 MALICIOUS).
func WorstExit(results []scan.Result) int {
	w := 0
	for _, r := range results {
		if scan.Rank[r.V.Verdict] > w {
			w = scan.Rank[r.V.Verdict]
		}
	}
	return w
}

// Gate prints every verdict, the accumulated session usage/cost, and — if any
// package is non-OK — blocks. On a TTY it offers abort / report / override;
// off a TTY (scripts, the editor hook in a non-interactive yay) it always
// blocks. Returns true only if it is safe/approved to proceed.
func Gate(results []scan.Result) bool {
	worst := "OK"
	var session scan.Usage
	calls := 0
	fmt.Println()
	for _, r := range results {
		printVerdict(r)
		if r.Usage.In > 0 || r.Usage.Out > 0 || r.Usage.HaveCost {
			fmt.Println(Dim("         ↳ " + r.Usage.String()))
			session.Add(r.Usage)
			calls++
		}
		if scan.Rank[r.V.Verdict] > scan.Rank[worst] {
			worst = r.V.Verdict
		}
	}

	fmt.Println()
	if calls > 0 {
		fmt.Println(Dim(fmt.Sprintf("scanner usage: %d call(s) · %s", calls, session.String())))
	}

	if worst == "OK" {
		fmt.Println(Green("All scanned packages look clean.") +
			Dim("  (heuristic scan — not a guarantee)"))
		return true
	}

	var flagged []scan.Result
	for _, r := range results {
		if r.V.Verdict != "OK" {
			flagged = append(flagged, r)
		}
	}
	fmt.Printf("%s%d package(s) flagged %s.\n", Red(Bold("!! Installation blocked: ")),
		len(flagged), worst)

	if !IsTTY(os.Stdin) {
		return false
	}
	in := bufio.NewReader(os.Stdin)
	ask := func(p string) string {
		fmt.Print(p)
		line, _ := in.ReadString('\n')
		return line
	}
	for {
		switch strings.TrimSpace(strings.ToLower(ask(
			"  [A]bort (default) / [r]eport to mailing list & abort / [c]ontinue anyway: "))) {
		case "", "a":
			return false
		case "r":
			for _, r := range flagged {
				offerReport(r, ask)
			}
			return false
		case "c":
			if strings.TrimSpace(ask(Red("  Type the word INSTALL to override the scanner: "))) == "INSTALL" {
				return true
			}
			return false
		}
	}
}
