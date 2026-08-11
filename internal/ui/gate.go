package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/manticore-projects/aurscan/internal/pipeline"
	"github.com/manticore-projects/aurscan/internal/scan"
)

// Progress prints the "scanning ..." line before a model call. It is silent
// while scanning is disabled (AURSCAN_DISABLE=1): nothing is scanned, so
// nothing is announced.
func Progress(pkg string, nfiles int) {
	if pipeline.Disabled() {
		return
	}
	fmt.Println(Dim(fmt.Sprintf("  scanning %s (%d files) ...", pkg, nfiles)))
}

func SevColor(sev, s string) string {
	switch sev {
	case "critical":
		return Red(s)
	case "warning":
		return Yellow(s)
	case "info":
		return White(s)
	}
	return Dim(s)
}

func VerdictBadge(verdict string) string {
	switch verdict {
	case "OK":
		return Green("  OK  ")
	case "SUSPICIOUS":
		return Yellow(" SUSP ")
	case "MALICIOUS":
		return Red(" MAL! ")
	case "SKIPPED":
		return Dim("SKIPPED")
	default:
		return verdict
	}
}

func printVerdict(r scan.Result) {
	badge := VerdictBadge(r.V.Verdict)
	if r.V.Verdict == "SKIPPED" {
		fmt.Printf("[%s] %s - %s\n", badge, Bold(r.Pkg), r.V.Summary)
		return
	}
	meta := fmt.Sprintf("confidence %.0f%%", r.V.Confidence)
	if r.Cached {
		meta += ", cached"
	}
	fmt.Printf("[%s] %s  %s\n", badge, Bold(r.Pkg), Dim(meta))
	w := TerminalWidth()
	if r.V.Summary != "" {
		fmt.Printf("  %s\n", WrapLine(r.V.Summary, w-len(IndentBody), IndentBody))
	}
	for _, f := range r.V.Findings {
		prefixLen := FindingPrefixLen(f.Severity, f.File)
		fmt.Printf("  %s %s: %s\n", SevColor(f.Severity, "["+f.Severity+"]"), f.File,
			WrapLine(f.Why, w-prefixLen, IndentBody))
		if f.Quote != "" {
			wrapped := WrapLine("> "+f.Quote, w-len(IndentQuote), IndentQuote)
			lines := strings.Split(wrapped, "\n")
			lines[0] = IndentBody + lines[0]
			for _, line := range lines {
				fmt.Println(Dim(line))
			}
		}
	}
}

// allSkipped reports whether every result is SKIPPED (AURSCAN_DISABLE=1).
func allSkipped(results []scan.Result) bool {
	skipped := false
	for _, r := range results {
		if r.V.Verdict != "SKIPPED" {
			return false
		}
		skipped = true
	}
	return skipped
}

// cleanLine is the message printed when the gate lets a build through.
func cleanLine(results []scan.Result) string {
	if allSkipped(results) {
		return Dim("Scanning disabled — all packages skipped.")
	}
	return Green("All scanned packages look clean.") +
		Dim("  (heuristic scan — not a guarantee)")
}

// autoPass reports whether results may proceed without any prompt. Only OK and
// explicit SKIPPED results auto-pass. In strict mode (the unattended build-hook
// path) a fallback-produced OK does not auto-pass either: the primary scanner
// was unavailable, so a degraded clean verdict still requires confirmation.
func autoPass(results []scan.Result, strict bool) bool {
	for _, r := range results {
		if r.V.Verdict != "OK" && r.V.Verdict != "SKIPPED" {
			return false
		}
		if strict && r.Fallback {
			return false
		}
	}
	return true
}

// flaggedSet is the set of results that block an auto-pass: every verdict other
// than OK or explicit SKIPPED, plus (in strict mode) any fallback-produced OK.
func flaggedSet(results []scan.Result, strict bool) []scan.Result {
	var out []scan.Result
	for _, r := range results {
		if (r.V.Verdict != "OK" && r.V.Verdict != "SKIPPED") || (strict && r.Fallback) {
			out = append(out, r)
		}
	}
	return out
}

// blockLine describes why a build was blocked, distinguishing a genuine adverse
// verdict from a degraded (fallback-only) clean scan.
func blockLine(results []scan.Result, strict bool) string {
	worst := "OK"
	for _, r := range results {
		if scan.Rank[r.V.Verdict] > scan.Rank[worst] {
			worst = r.V.Verdict
		}
	}
	n := len(flaggedSet(results, strict))
	if worst == "OK" {
		return fmt.Sprintf("%d package(s) approved only by a fallback backend "+
			"(primary scanner unavailable).", n)
	}
	return fmt.Sprintf("%d package(s) flagged %s.", n, worst)
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

// summarize prints every verdict plus the session usage line and returns the
// worst verdict string. Shared by Gate (interactive) and Decide (hook).
func summarize(results []scan.Result) string {
	worst := "OK"
	var session scan.Usage
	calls := 0
	w := TerminalWidth()
	fmt.Println()
	for _, r := range results {
		printVerdict(r)
		if r.Usage.In > 0 || r.Usage.Out > 0 || r.Usage.HaveCost {
			fmt.Println(Dim(IndentBody + WrapLine("↳ "+r.Usage.String(), w-len(IndentUsage), IndentUsage)))
			session.Add(r.Usage)
			calls++
		}
		if scan.Rank[r.V.Verdict] > scan.Rank[worst] {
			worst = r.V.Verdict
		}
	}

	fmt.Println()
	if calls > 0 {
		fmt.Println(Dim(WrapLine(
			fmt.Sprintf("scanner usage: %d call(s) · %s", calls, session.String()),
			w, "")))
	}
	return worst
}

// Decide prints verdicts and usage, then returns whether it is safe to proceed
// WITHOUT any interactive prompt. Used by the paru PreBuildCommand hook, whose
// stdio may not be a usable TTY: adverse verdicts block (fail-closed); explicit
// SKIPPED is the user-requested pass-through exception.
func Decide(results []scan.Result, strict bool) bool {
	summarize(results)
	w := TerminalWidth()
	if autoPass(results, strict) {
		fmt.Println(cleanLine(results))
		return true
	}
	fmt.Printf("%s%s\n", Red(Bold("!! aurscan blocked this build: ")),
		WrapLine(blockLine(results, strict), w-prefixBlockDecide, IndentBlock))
	return false
}

// Gate prints every verdict, the accumulated session usage/cost, and — if any
// package has an adverse verdict — blocks. On a TTY it offers abort / report / override;
// off a TTY (scripts, the editor hook in a non-interactive yay) it always
// blocks. Returns true only if it is safe/approved to proceed.
// GateVia is Gate's interactive core operating over an explicit reader/writer
// rather than os.Stdin/os.Stdout. The paru PreBuildCommand hook uses it with
// /dev/tty so the user can still decide interactively even though paru runs the
// hook with redirected stdio. Returns true only if the user approves the build.
func GateVia(results []scan.Result, in io.Reader, out io.Writer, strict bool) bool {
	w := TerminalWidth()
	for _, r := range results {
		if r.V.Verdict == "SKIPPED" {
			fmt.Fprintf(out, "[%s] %s - %s\n", VerdictBadge(r.V.Verdict), r.Pkg, r.V.Summary)
			continue
		}
		fmt.Fprintf(out, "[%s] %s (confidence %.0f%%)\n",
			VerdictBadge(r.V.Verdict), r.Pkg, r.V.Confidence)
		if r.V.Summary != "" {
			fmt.Fprintf(out, "  %s\n", WrapLine(r.V.Summary, w-len(IndentBody), IndentBody))
		}
		for _, f := range r.V.Findings {
			prefixLen := FindingPrefixLen(f.Severity, f.File)
			fmt.Fprintf(out, "  %s %s: %s\n", SevColor(f.Severity, "["+f.Severity+"]"), f.File,
				WrapLine(f.Why, w-prefixLen, IndentBody))
		}
	}
	if autoPass(results, strict) {
		return true
	}
	fmt.Fprintf(out, "%s%s\n", "!! Build blocked: ",
		WrapLine(blockLine(results, strict), w-prefixBlockGateVia, IndentBlock))

	br := bufio.NewReader(in)
	tty, _ := in.(*os.File) // for input flushing when reading from /dev/tty
	ask := func(p string) string {
		DrainInput(tty) // discard keystrokes buffered before this prompt
		fmt.Fprint(out, p)
		line, _ := br.ReadString('\n')
		return strings.TrimSpace(line)
	}
	prompt := White("  Type INSTALL to override the scanner, or [q]uit to exit: ")
	for {
		switch resp := ask(prompt); {
		case strings.EqualFold(resp, "INSTALL"):
			return true
		case strings.EqualFold(resp, "q"), strings.EqualFold(resp, "quit"):
			return false
		}
		prompt = Red("  (mis-spelled) type INSTALL to override, or [q]uit to exit: ")
	}
}

func Gate(results []scan.Result, strict bool) bool {
	summarize(results)

	w := TerminalWidth()
	if autoPass(results, strict) {
		fmt.Println(cleanLine(results))
		return true
	}

	flagged := flaggedSet(results, strict)
	fmt.Printf("%s%s\n", Red(Bold("!! Installation blocked: ")),
		WrapLine(blockLine(results, strict), w-prefixBlockGate, IndentBlock))

	if !IsTTY(os.Stdin) {
		return false
	}
	in := bufio.NewReader(os.Stdin)
	ask := func(p string) string {
		DrainInput(os.Stdin) // discard keystrokes buffered before this prompt
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
				if r.V.Verdict != "OK" { // never "report" a clean (fallback) verdict
					offerReport(r, ask)
				}
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
