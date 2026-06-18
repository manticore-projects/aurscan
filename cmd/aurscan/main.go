// Command aurscan is a Claude-powered pre-build malware scanner for AUR
// packages. It scans PKGBUILDs, .install scriptlets and helper scripts with a
// Claude model BEFORE makepkg runs, and fails closed on any error.
//
// Invocation modes (by binary name / subcommand):
//
//	aurscan <pkgname|./dir> [...]   scan AUR package(s) / local build dir(s)
//	aurscan --update-check          scan pending AUR updates (yay -Qua)
//	aurscan --gen-file              write pending AUR updates to aurscan.paclist
//	aurscan --scan-file             scan packages listed in ./aurscan.paclist
//	aurscan --edit-hook <files...>  $EDITOR-replacement gate for yay
//	syay <yay args...>              transparent yay wrapper (symlink)
//	aurscan-edit <files...>         edit-hook (symlink; what syay points yay at)
//
// See README.md for auth, environment variables and exit codes.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/manticore-projects/aurscan/internal/aur"
	"github.com/manticore-projects/aurscan/internal/config"
	"github.com/manticore-projects/aurscan/internal/pipeline"
	"github.com/manticore-projects/aurscan/internal/scan"
	"github.com/manticore-projects/aurscan/internal/ui"
	"github.com/manticore-projects/aurscan/internal/version"
	"github.com/manticore-projects/aurscan/internal/yay"
)

const usage = `usage:
  aurscan <pkgname|./dir> [...]    scan AUR package(s) / local build dir(s)
  aurscan --update-check           scan pending AUR updates (yay -Qua)
  aurscan --gen-file               write pending AUR updates to ./aurscan.paclist
  aurscan --scan-file              scan packages listed in ./aurscan.paclist
  aurscan --rules-only <...>       static rules only, no LLM call (free, offline)
  aurscan --score <file|dir|->     print 0-100 trust score; exit=score, 255=fail
  aurscan --edit-hook <files...>   gate mode (yay invokes this as its editor)
  aurscan --prebuild <dir>         gate mode (paru PreBuildCommand / yay v13 hook)
  aurscan --install-paru-hook      enable scanning in paru.conf (no wrapper)
  aurscan --install-yay-hook       enable scanning in yay v13 init.lua (no wrapper)
  aurscan --debug ...              trace LLM request/response to stderr
  aurscan --version                print version and exit
  syay <yay args...>               transparent yay wrapper (symlink)
  sparu <paru args...>             transparent paru wrapper (symlink)`

func main() {
	config.LoadEnvFile()
	scan.ExtraInstructions = config.ExtraInstructions()
	scan.ExtraBackends = scan.BackendsFromConfig(config.LLMConfigs())
	argv0 := os.Args[0]
	args := os.Args[1:]

	// --debug may appear anywhere; strip it and enable tracing (issue #17).
	args = stripDebug(args)

	// --version works regardless of invocation name (syay --version too).
	if len(args) > 0 && (args[0] == "--version" || args[0] == "-v" || args[0] == "version") {
		fmt.Println(version.String())
		return
	}

	// Dispatch by how we were invoked.
	if filepath.Base(argv0) == "syay" {
		yay.Wrapper(args)
		return
	}
	if filepath.Base(argv0) == "sparu" {
		yay.ParuWrapper(args)
		return
	}
	if yay.IsEditHook(argv0) {
		yay.EditHook(args)
		return
	}
	if len(args) > 0 && args[0] == "--edit-hook" {
		yay.EditHook(args[1:])
		return
	}
	if len(args) > 0 && args[0] == "--prebuild" {
		yay.PrebuildHook(args[1:])
		return
	}
	if len(args) > 0 && args[0] == "--install-paru-hook" {
		path, err := yay.InstallParuHook()
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Red("error: ")+err.Error())
			os.Exit(3)
		}
		fmt.Println("aurscan paru hook installed in " + path)
		fmt.Println("Plain `paru` will now scan AUR packages before building.")
		if p, found := yay.DetectWrapperAlias("paru", "sparu"); found {
			fmt.Println(ui.Red("note: ") + "an `alias paru=sparu` looks set in " + p + ".")
			fmt.Println("      With the native PreBuildCommand hook it is redundant; you can remove it.")
		}
		return
	}
	if len(args) > 0 && args[0] == "--uninstall-paru-hook" {
		path, changed, err := yay.UninstallParuHook()
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Red("error: ")+err.Error())
			os.Exit(3)
		}
		if changed {
			fmt.Println("Removed aurscan hook from " + path)
		} else {
			fmt.Println("No aurscan hook found in paru.conf")
		}
		return
	}
	if len(args) > 0 && args[0] == "--install-yay-hook" {
		path, major, err := yay.InstallYayHook()
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Red("error: ")+err.Error())
			os.Exit(3)
		}
		fmt.Println("aurscan yay hook installed in " + path)
		if major >= 13 {
			fmt.Println("Plain `yay` (v" + fmt.Sprint(major) + ") will now scan AUR packages after download, before build.")
			if p, found := yay.DetectWrapperAlias("yay", "syay"); found {
				fmt.Println(ui.Red("note: ") + "an `alias yay=syay` looks set in " + p + ".")
				fmt.Println("      With the native v13 hook it is redundant — and on v13 it only adds a forced edit prompt.")
				fmt.Println("      Remove it — fish: `functions -e yay; funcsave yay`  ·  bash/zsh: delete the alias line.")
			}
		} else {
			fmt.Println(ui.Red("note: ") + "yay v13+ is required for Lua hooks; this hook stays dormant on older yay.")
			fmt.Println("      For yay < 13, use the `syay` wrapper instead (see README).")
		}
		return
	}
	if len(args) > 0 && args[0] == "--uninstall-yay-hook" {
		path, changed, err := yay.UninstallYayHook()
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Red("error: ")+err.Error())
			os.Exit(3)
		}
		if changed {
			fmt.Println("Removed aurscan hook from " + path)
		} else {
			fmt.Println("No aurscan hook found in init.lua")
		}
		return
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Println(usage)
		return
	}

	if len(args) > 0 && args[0] == "--score" {
		os.Exit(scoreMode(args[1:]))
	}

	if len(args) > 0 && args[0] == "--rules-only" {
		os.Setenv("AURSCAN_RULES_ONLY", "1")
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Println(usage)
		return
	}
	var results []scan.Result
	switch args[0] {
	case "--update-check":
		results = updateCheck()
	case "--gen-file":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, ui.Red("error: ")+"--gen-file does not accept arguments")
			os.Exit(3)
		}
		n, err := writePaclistFromYay()
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Red("error: ")+err.Error())
			os.Exit(3)
		}
		fmt.Printf("%s wrote %d pending AUR update(s) to %s\n", ui.Green("OK:"), n, paclistFile)
		return
	case "--scan-file":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, ui.Red("error: ")+"--scan-file does not accept arguments")
			os.Exit(3)
		}
		names, err := readPaclistPackages()
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Red("error: ")+err.Error())
			os.Exit(3)
		}
		if len(names) == 0 {
			fmt.Println(ui.Green("No pending AUR updates in ") + paclistFile + ".")
			return
		}
		results = aur.ScanRecursive(names, ui.Progress)
	default:
		results = scanArgs(args)
	}
	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, ui.Red("error: ")+"nothing scanned")
		os.Exit(3)
	}
	if ui.Gate(results, false) {
		os.Exit(0)
	}
	os.Exit(maxInt(1, ui.WorstExit(results)))
}

func updateCheck() []scan.Result {
	out, err := runAllowExit1("yay", "-Qua")
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Red("error: ")+"yay -Qua failed: "+err.Error())
		os.Exit(3)
	}
	var pending []string
	for _, line := range splitLines(out) {
		if f := fields(line); len(f) > 0 {
			pending = append(pending, f[0])
		}
	}
	if len(pending) == 0 {
		fmt.Println(ui.Green("No pending AUR updates."))
		os.Exit(0)
	}
	return aur.ScanRecursive(pending, ui.Progress)
}

func scanArgs(args []string) []scan.Result {
	var results []scan.Result
	var names []string
	for _, a := range args {
		if fi, err := os.Stat(a); err == nil && fi.IsDir() {
			abs, _ := filepath.Abs(a)
			name := filepath.Base(abs)
			files, err := scan.CollectDir(a)
			if err != nil {
				results = append(results, scan.Result{
					Pkg: name,
					V:   scan.Verdict{Verdict: "SUSPICIOUS", Summary: err.Error() + " (fail-closed)"},
				})
				continue
			}
			ui.Progress(name, len(files))
			results = append(results, pipeline.Run(name, files, ""))
		} else {
			names = append(names, a)
		}
	}
	if len(names) > 0 {
		results = append(results, aur.ScanRecursive(names, ui.Progress)...)
	}
	return results
}

// printResultStderr writes a concise verdict + findings to stderr so it does
// not pollute the score on stdout in --score mode.
func printResultStderr(r scan.Result) {
	fmt.Fprintf(os.Stderr, "%s  %s (confidence %.0f%%)\n",
		r.V.Verdict, r.Pkg, r.V.Confidence)
	if r.V.Summary != "" {
		fmt.Fprintf(os.Stderr, "  %s\n", r.V.Summary)
	}
	for _, f := range r.V.Findings {
		fmt.Fprintf(os.Stderr, "  [%s] %s: %s\n", f.Severity, f.File, f.Why)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// stripDebug removes --debug from anywhere in args and enables scan tracing.
func stripDebug(args []string) []string {
	out := args[:0:0]
	for _, a := range args {
		if a == "--debug" {
			scan.Debug = true
			continue
		}
		out = append(out, a)
	}
	return out
}

// collectOne resolves a single scan target for script integration (issue #18):
// "-" reads a PKGBUILD from stdin, a regular file is read directly, a directory
// is collected as usual. Returns the display name and files.
func collectOne(target string) (string, scan.Files, error) {
	switch {
	case target == "-":
		f, err := scan.CollectStdin(os.Stdin)
		return "(stdin)", f, err
	default:
		fi, err := os.Stat(target)
		if err != nil {
			return target, nil, err
		}
		if fi.IsDir() {
			abs, _ := filepath.Abs(target)
			f, err := scan.CollectDir(target)
			return filepath.Base(abs), f, err
		}
		f, err := scan.CollectFile(target)
		return filepath.Base(target), f, err
	}
}

// scoreMode scans exactly one target and maps the result to an exit code for
// scripting (issue #18): the 0-100 trust score on success, or 255 ("-1") if the
// scan could not be completed. The trust score is also printed to stdout; the
// human-readable verdict goes to stderr so `score=$(aurscan --score -)` is clean.
func scoreMode(rest []string) int {
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, ui.Red("error: ")+"--score takes exactly one target (a PKGBUILD file, a dir, or - for stdin)")
		return 255
	}
	name, files, err := collectOne(rest[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Red("error: ")+err.Error())
		return 255
	}
	res := pipeline.Run(name, files, "")
	// Show the verdict + findings on stderr (does not pollute the score stdout).
	printResultStderr(res)
	if res.Failed {
		fmt.Fprintln(os.Stderr, ui.Red("scan failed — exit 255"))
		return 255
	}
	score := scan.TrustScore(res.V)
	fmt.Println(score) // machine-readable: just the number on stdout
	return score
}
