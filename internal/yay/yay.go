package yay

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/manticore-projects/aurscan/internal/pipeline"
	"github.com/manticore-projects/aurscan/internal/scan"
	"github.com/manticore-projects/aurscan/internal/ui"
)

// envForceEdit, when set, makes the binary behave as the edit-hook regardless
// of its argv[0] name (so the injected --editor works even if the
// aurscan-edit symlink is missing).
const envForceEdit = "AURSCAN_EDIT_HOOK"

// Wrapper is the `syay` entrypoint. It guarantees yay's editor-gate is pointed
// at aurscan-edit, then hands off to the real yay via exec. Because yay invokes
// the editor on every AUR PKGBUILD it is about to build — after download,
// before build, regardless of how the package was chosen (bare `yay <term>`
// search-install, `-S name`, or `-Syu`) and including AUR dependencies — this
// is the one interception point that always sees the real, selected package.
func Wrapper(argv []string) {
	yayPath, err := exec.LookPath("yay")
	if err != nil {
		die("real `yay` binary not found in PATH")
	}
	self, _ := os.Executable()
	if rp, _ := filepath.EvalSymlinks(yayPath); rp == self {
		die("`yay` in PATH resolves to aurscan itself — fix your PATH/symlinks")
	}

	env := os.Environ()
	if userSetEditor(argv) {
		// Respect an explicit --editor; chain to it after a clean scan instead.
		fmt.Fprintln(os.Stderr, ui.Yellow(
			"aurscan: --editor given on the command line; scanner will run first, "+
				"then chain to your editor."))
		argv = injectEditor(stripEditor(argv), self)
	} else {
		argv = injectEditor(argv, self)
	}
	env = append(env, envForceEdit+"=1")

	if err := syscall.Exec(yayPath, append([]string{yayPath}, argv...), env); err != nil {
		die("exec yay failed: " + err.Error())
	}
}

func userSetEditor(argv []string) bool {
	for _, a := range argv {
		if a == "--editor" || strings.HasPrefix(a, "--editor=") {
			return true
		}
	}
	return false
}

func stripEditor(argv []string) []string {
	var out []string
	skip := false
	for _, a := range argv {
		if skip {
			skip = false
			continue
		}
		if a == "--editor" {
			skip = true
			continue
		}
		if strings.HasPrefix(a, "--editor=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// injectEditor points yay's edit step at this binary and forces the edit
// prompt on, so the gate cannot be skipped.
func injectEditor(argv []string, self string) []string {
	editor := self
	if dir := filepath.Dir(self); dir != "" {
		if cand := filepath.Join(dir, "aurscan-edit"); fileExists(cand) {
			editor = cand
		}
	}
	return append(argv, "--editor", editor, "--editmenu", "--answeredit", "All")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// IsEditHook reports whether this process was invoked as yay's editor.
func IsEditHook(argv0 string) bool {
	return filepath.Base(argv0) == "aurscan-edit" || os.Getenv(envForceEdit) == "1"
}

// EditHook is the $EDITOR-replacement gate. yay calls it with one or more
// PKGBUILD (and .install) paths. It scans each package directory; on a non-OK
// verdict it exits non-zero, which makes yay abort the build. On a clean
// verdict it optionally chains to the user's real editor ($VISUAL/$EDITOR) so
// manual review still happens.
func EditHook(paths []string) {
	dirs := map[string]bool{}
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			dirs[packageRoot(filepath.Dir(p))] = true
		} else if err == nil && fi.IsDir() {
			dirs[packageRoot(p)] = true
		}
	}
	if len(dirs) == 0 {
		die("edit-hook: no files passed by yay")
	}

	var results []scan.Result
	for d := range dirs {
		name := filepath.Base(d)
		files, err := scan.CollectDir(d)
		if err != nil {
			results = append(results, scan.Result{
				Pkg: name,
				V:   scan.Verdict{Verdict: "SUSPICIOUS", Summary: err.Error() + " (fail-closed)"},
			})
			continue
		}
		ui.Progress(name, len(files))
		results = append(results, pipeline.Run(name, files, ""))
	}

	if !ui.Gate(results) {
		fmt.Fprintln(os.Stderr, ui.Red(":: aurscan blocked this build."))
		os.Exit(maxInt(1, ui.WorstExit(results)))
	}
	chainToUserEditor(paths)
	os.Exit(0)
}

func packageRoot(dir string) string {
	for {
		if fileExists(filepath.Join(dir, "PKGBUILD")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir
		}
		dir = parent
	}
}

// chainToUserEditor opens the user's real editor on the files after a clean
// scan, so the manual-review step yay normally provides is preserved.
func chainToUserEditor(paths []string) {
	ed := os.Getenv("VISUAL")
	if ed == "" {
		ed = os.Getenv("EDITOR")
	}
	if ed == "" {
		return
	}
	self, _ := os.Executable()
	if rp, _ := filepath.EvalSymlinks(ed); rp == self || filepath.Base(ed) == "aurscan-edit" {
		return // never recurse into ourselves
	}
	c := exec.Command(ed, paths...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	_ = c.Run()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, ui.Red("error: ")+msg)
	os.Exit(3)
}
