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
  aurscan --edit-hook <files...>   gate mode (yay invokes this as its editor)
  aurscan --version                print version and exit
  syay <yay args...>               transparent yay wrapper (symlink)`

func main() {
	scan.ExtraInstructions = config.ExtraInstructions()
	argv0 := os.Args[0]
	args := os.Args[1:]

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
	if yay.IsEditHook(argv0) {
		yay.EditHook(args)
		return
	}
	if len(args) > 0 && args[0] == "--edit-hook" {
		yay.EditHook(args[1:])
		return
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Println(usage)
		return
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
	if ui.Gate(results) {
		os.Exit(0)
	}
	os.Exit(maxInt(1, ui.WorstExit(results)))
}

func updateCheck() []scan.Result {
	out, err := run("yay", "-Qua")
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

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
