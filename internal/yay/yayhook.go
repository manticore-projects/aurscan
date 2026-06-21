package yay

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// yay v13 introduced Lua hooks. aurscan registers an AURPostDownload hook,
// which runs after `makepkg --verifysource` (PKGBUILD repo + downloaded sources
// present) and before any build or install. The hook shells out to
// `aurscan --prebuild <dir>` and aborts the install on a non-zero exit, reusing
// the exact same gate (including the /dev/tty prompt) as the paru PreBuildCommand
// integration. AURPostDownload is preferred over AURPreInstall because it lets
// the scanner see the fetched sources, not just the build script.

const (
	yayHookBegin = "-- >>> aurscan begin (managed block; do not edit by hand)"
	yayHookEnd   = "-- <<< aurscan end"
	minYayMajor  = 13
)

// userYayInitLua is the init.lua path yay loads (XDG first, then ~/.config).
func userYayInitLua() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "yay", "init.lua")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "yay", "init.lua")
	}
	return ""
}

// yayVersionCmd is overridable in tests.
var yayVersionCmd = func() (string, error) {
	out, err := exec.Command("yay", "--version").Output()
	return string(out), err
}

var reYayVer = regexp.MustCompile(`v?(\d+)\.\d+`)

// yayMajor returns yay's major version, or 0 if it cannot be determined.
func yayMajor() int {
	out, err := yayVersionCmd()
	if err != nil {
		return 0
	}
	m := reYayVer.FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// DetectWrapperAlias reports, read-only, whether the user appears to have an
// alias/function mapping `helper` to aurscan's `wrapper` (e.g. yay->syay) in a
// common shell config. It never edits anything; it exists only so the install
// commands can hint that an old wrapper alias is now redundant. Returns the
// first matching file and true, or "" and false.
func DetectWrapperAlias(helper, wrapper string) (string, bool) {
	home, _ := os.UserHomeDir()
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" && home != "" {
		cfg = filepath.Join(home, ".config")
	}
	var cands []string
	if cfg != "" {
		cands = append(cands,
			filepath.Join(cfg, "fish", "functions", helper+".fish"), // funcsave yay
			filepath.Join(cfg, "fish", "config.fish"),
		)
	}
	if home != "" {
		cands = append(cands,
			filepath.Join(home, ".bashrc"),
			filepath.Join(home, ".zshrc"),
			filepath.Join(home, ".bash_aliases"),
			filepath.Join(home, ".aliases"),
		)
	}
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(wrapper) + `\b`)
	for _, p := range cands {
		if data, err := os.ReadFile(p); err == nil && re.Match(data) {
			return p, true
		}
	}
	return "", false
}

// yayHookLua renders the managed Lua block. self is the absolute aurscan path.
func yayHookLua(self string) string {
	// self comes from os.Executable() and is shell-safe; the build dir is
	// quoted at runtime by shq() to survive any unusual characters.
	return yayHookBegin + "\n" +
		"-- aurscan: scan each AUR package (PKGBUILD + downloaded sources) before install.\n" +
		"yay.create_autocmd(\"AURPostDownload\", {\n" +
		"  desc = \"aurscan pre-build malware scan\",\n" +
		"  callback = function(event)\n" +
		"    local function shq(s) return \"'\" .. tostring(s):gsub(\"'\", \"'\\\\''\") .. \"'\" end\n" +
		"    local cmd = " + strconv.Quote(self) + " .. \" --prebuild \" .. shq(event.data.dir)\n" +
		"    if os.execute(cmd) ~= 0 then\n" +
		"      yay.abort(event.match .. \": blocked by aurscan\")\n" +
		"    end\n" +
		"  end,\n" +
		"})\n" +
		yayHookEnd
}

// InstallYayHook writes the AURPostDownload hook into the user's init.lua,
// preserving any existing content. Idempotent. Returns the path written and the
// detected yay major version (0 if yay is absent/old, in which case the caller
// should warn that syay is the right integration for pre-v13 yay).
func InstallYayHook() (string, int, error) {
	path := userYayInitLua()
	if path == "" {
		return "", 0, fmt.Errorf("cannot determine user config dir")
	}
	major := yayMajor()

	self, _ := os.Executable()
	if self == "" {
		self = "aurscan"
	}
	block := yayHookLua(self)

	existing := ""
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	}
	if strings.Contains(existing, yayHookBegin) {
		// Replace the managed block in place (keeps user content, updates path).
		existing = stripYayBlock(existing)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", major, err
	}
	var b strings.Builder
	b.WriteString(strings.TrimRight(existing, "\n"))
	if b.Len() > 0 {
		b.WriteString("\n\n")
	}
	b.WriteString(block)
	b.WriteString("\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", major, err
	}
	return path, major, nil
}

// UninstallYayHook removes the managed block. Returns path, whether it changed.
func UninstallYayHook() (string, bool, error) {
	path := userYayInitLua()
	if path == "" {
		return "", false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return path, false, nil // nothing to remove
	}
	s := string(data)
	if !strings.Contains(s, yayHookBegin) {
		return path, false, nil
	}
	out := strings.TrimRight(stripYayBlock(s), "\n") + "\n"
	if strings.TrimSpace(out) == "" {
		// File now empty: remove it so yay falls back to no init.lua.
		if err := os.Remove(path); err != nil {
			return path, false, err
		}
		return path, true, nil
	}
	return path, true, os.WriteFile(path, []byte(out), 0o644)
}

// stripYayBlock removes the managed block (inclusive of its markers).
func stripYayBlock(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	inBlock := false
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if t == yayHookBegin {
			inBlock = true
			continue
		}
		if t == yayHookEnd {
			inBlock = false
			continue
		}
		if !inBlock {
			out = append(out, ln)
		}
	}
	return strings.Join(out, "\n")
}
