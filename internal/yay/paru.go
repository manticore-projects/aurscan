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

// paru exposes the scanner through paru's native PreBuildCommand hook, which
// runs once per package in the PKGBUILD directory, after download and before
// build — regardless of whether the package came from -S, a bare interactive
// search, or -Syu, and including AUR dependencies. This is cleaner than yay's
// editor trick, but PreBuildCommand is a config-file setting (paru has no
// equivalent CLI flag), so we either inject an ephemeral config (the sparu
// wrapper) or write it into paru.conf once (--install-paru-hook).

const hookMarker = "# added by aurscan"

// systemParuConf is the system-wide paru config we Include when creating a
// fresh user config, so its settings are not shadowed. Overridable in tests.
var systemParuConf = "/etc/paru.conf"

func prebuildLine() string {
	self, _ := os.Executable()
	if self == "" {
		self = "aurscan"
	}
	// cwd is the PKGBUILD dir when paru runs this, so "." scans the package.
	return fmt.Sprintf("PreBuildCommand = %s --prebuild .", self)
}

// realParuConf returns the path of the paru.conf paru would normally load,
// or "" if none exists.
func realParuConf() string {
	if p := os.Getenv("PARU_CONF"); p != "" {
		return p
	}
	var cands []string
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		cands = append(cands, filepath.Join(xdg, "paru", "paru.conf"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		cands = append(cands, filepath.Join(home, ".config", "paru", "paru.conf"))
	}
	cands = append(cands, "/etc/paru.conf")
	for _, c := range cands {
		if fileExists(c) {
			return c
		}
	}
	return ""
}

// ParuWrapper is the `sparu` entrypoint. It writes a throwaway paru.conf that
// Includes the user's real config and then sets the PreBuildCommand in a fresh
// [bin] section (so it wins regardless of where the included file ends), points
// paru at it via PARU_CONF, and execs the real paru. The user's own config is
// never modified.
func ParuWrapper(argv []string) {
	paruPath, err := exec.LookPath("paru")
	if err != nil {
		die("real `paru` binary not found in PATH")
	}
	self, _ := os.Executable()
	if rp, _ := filepath.EvalSymlinks(paruPath); rp == self {
		die("`paru` in PATH resolves to aurscan itself — fix your PATH/symlinks")
	}

	var b strings.Builder
	b.WriteString("[options]\n")
	if real := realParuConf(); real != "" {
		fmt.Fprintf(&b, "Include = %s\n", real)
	}
	b.WriteString("[bin]\n")
	b.WriteString(prebuildLine() + "\n")

	tmp, err := os.CreateTemp("", "aurscan-paru-*.conf")
	if err != nil {
		die("could not create temp paru config: " + err.Error())
	}
	tmp.WriteString(b.String())
	tmp.Close()

	env := append(os.Environ(), "PARU_CONF="+tmp.Name())
	// Best-effort cleanup: paru replaces this process, so schedule removal by
	// leaving it in TMPDIR (the OS clears it); we cannot defer past Exec.
	if err := syscall.Exec(paruPath, append([]string{paruPath}, argv...), env); err != nil {
		os.Remove(tmp.Name())
		die("exec paru failed: " + err.Error())
	}
}

// userParuConf returns the per-user paru.conf path we install the hook into
// (XDG_CONFIG_HOME/paru/paru.conf, else ~/.config/paru/paru.conf). This is
// always writable without root and is the file paru prefers over /etc.
func userParuConf() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "paru", "paru.conf")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "paru", "paru.conf")
	}
	return ""
}

// InstallParuHook enables scanning by adding the PreBuildCommand to paru's
// config, without a wrapper. It always targets the user config
// (~/.config/paru/paru.conf or $XDG_CONFIG_HOME/paru/paru.conf) so it never
// needs root. Crucially, paru reads only the FIRST config it finds: if a
// system /etc/paru.conf exists and we are creating a new user config, we
// `Include` the system file first so the user's existing settings are not
// silently shadowed (issue #3, rynti). Idempotent: a second run is a no-op.
// Returns the path written.
func InstallParuHook() (string, error) {
	userConf := userParuConf()
	if userConf == "" {
		return "", fmt.Errorf("cannot determine user config dir")
	}

	// Already installed?
	if data, err := os.ReadFile(userConf); err == nil && strings.Contains(string(data), hookMarker) {
		return userConf, nil
	}

	if fileExists(userConf) {
		// Append in place; the user's settings are preserved untouched.
		f, err := os.OpenFile(userConf, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return "", err
		}
		defer f.Close()
		fmt.Fprintf(f, "\n[bin]\n%s\n%s\n", hookMarker, prebuildLine())
		return userConf, nil
	}

	// No user config yet. Create one, but if a system config exists, Include it
	// first so paru still honours those settings (it reads only one file).
	if err := os.MkdirAll(filepath.Dir(userConf), 0o755); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(hookMarker + "\n")
	if fileExists(systemParuConf) {
		fmt.Fprintf(&b, "[options]\nInclude = %s\n", systemParuConf)
	}
	b.WriteString("[bin]\n" + prebuildLine() + "\n")
	if err := os.WriteFile(userConf, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return userConf, nil
}

// UninstallParuHook removes aurscan's lines from paru.conf. Returns true if it
// changed anything.
func UninstallParuHook() (string, bool, error) {
	path := userParuConf()
	if path == "" {
		return "", false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return path, false, err
	}
	lines := strings.Split(string(data), "\n")
	var out []string
	changed := false
	for _, ln := range lines {
		if strings.Contains(ln, hookMarker) ||
			strings.Contains(ln, "--prebuild .") {
			changed = true
			continue
		}
		out = append(out, ln)
	}
	if !changed {
		return path, false, nil
	}
	return path, true, os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o644)
}

// PrebuildHook is the `aurscan --prebuild <dir>` entrypoint paru invokes via
// PreBuildCommand. It scans the directory and, on a non-OK verdict, lets the
// user decide interactively. Because paru runs PreBuildCommand with redirected
// stdio, the prompt is done over /dev/tty (the controlling terminal) rather
// than stdin/stdout — this is what makes the interactive build decision work
// under paru (issue #3). With no controlling terminal (CI, non-interactive),
// it fails closed: any non-OK verdict aborts the build via a non-zero exit.
func PrebuildHook(args []string) {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	abs, _ := filepath.Abs(dir)
	name := filepath.Base(abs)
	files, err := scan.CollectDir(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Red("aurscan: ")+err.Error()+" (fail-closed)")
		os.Exit(2)
	}
	ui.Progress(name, len(files))
	res := pipeline.Run(name, files, "")
	results := []scan.Result{res}

	if res.V.Verdict == "OK" {
		ui.Decide(results) // prints the clean line
		os.Exit(0)
	}

	// Non-OK: try to prompt on the controlling terminal.
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		if ui.GateVia(results, tty, tty) {
			fmt.Fprintln(tty, "Proceeding at your request — be careful.")
			os.Exit(0)
		}
		fmt.Fprintln(tty, "Build aborted by aurscan.")
		os.Exit(maxInt(1, ui.WorstExit(results)))
	}

	// No controlling terminal: fail closed.
	ui.Decide(results)
	os.Exit(maxInt(1, ui.WorstExit(results)))
}
