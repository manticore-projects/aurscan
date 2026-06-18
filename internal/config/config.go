// Package config resolves aurscan's runtime configuration from environment
// variables and optional files under the user's config directory, so behaviour
// can be tuned without recompiling.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Dir returns aurscan's config directory, honoring AURSCAN_CONFIG_DIR, then
// XDG_CONFIG_HOME/aurscan, then ~/.config/aurscan.
func Dir() string {
	if d := os.Getenv("AURSCAN_CONFIG_DIR"); d != "" {
		return d
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "aurscan")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "aurscan")
	}
	return ""
}

// LoadEnvFile reads KEY=VALUE pairs from <config dir>/env and injects them
// into the process environment. A variable is only set when it is not already
// present in the environment, so explicit env vars always win. Lines starting
// with '#' and blank lines are ignored. Call this once at program startup,
// before reading any other configuration.
func LoadEnvFile() {
	d := Dir()
	if d == "" {
		return
	}
	b, err := os.ReadFile(filepath.Join(d, "env"))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "" || os.Getenv(k) != "" {
			continue
		}
		os.Setenv(k, strings.TrimSpace(v))
	}
}

// ExtraInstructions loads the user's additional auditor guidance, if any.
// Resolution order: AURSCAN_INSTRUCTIONS (a file path), then
// <config dir>/instructions.md. Returns "" when none is present.
//
// The returned text is appended to the built-in instructions, never replaces
// them — so a user can sharpen the auditor (e.g. weight maintainer reputation
// or unexplained changes more heavily) without weakening the core rules or
// the prompt-injection hardening.
func ExtraInstructions() string {
	if p := os.Getenv("AURSCAN_INSTRUCTIONS"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			return string(b)
		}
	}
	if d := Dir(); d != "" {
		if b, err := os.ReadFile(filepath.Join(d, "instructions.md")); err == nil {
			return string(b)
		}
	}
	return ""
}

// llmConfRe matches the priority-ordered backend config files
// (~/.config/aurscan/llm1.conf, llm2.conf, …). The anchored capture group lets
// us sort numerically (so llm2 precedes llm10) and rejects llm.conf, llmfoo.conf
// and llm1.conf.bak.
var llmConfRe = regexp.MustCompile(`^llm(\d+)\.conf$`)

// llmConfKeys is the allowlist of recognised keys in an llmN.conf file. Anything
// else is ignored, so future keys can be added without breaking older binaries.
var llmConfKeys = map[string]bool{
	"backend": true, "model": true, "url": true, "fallback": true, "api_key": true,
}

// LLMConfigs loads the priority-ordered backend config files under the config
// directory and returns one key→value map per file, in numeric filename order
// (llm1.conf, llm2.conf, …, llm10.conf). Each file describes ONE fallback
// backend; the scan package turns these maps into a backend chain.
//
// The format is a flat, literal "key = value": comments (# or ; at the first
// non-space character) and blank lines are skipped, the value runs verbatim to
// end of line (no quote- or inline-comment stripping), and only the first '='
// splits the line so '=' may appear in a value. An unreadable file is skipped
// rather than fatal, and a missing config directory yields nil.
func LLMConfigs() []map[string]string {
	dir := Dir()
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	type confFile struct {
		n    int
		name string
	}
	var files []confFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := llmConfRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		files = append(files, confFile{n: n, name: e.Name()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].n < files[j].n })

	var out []map[string]string
	for _, f := range files {
		path := filepath.Join(dir, f.name)
		b, err := os.ReadFile(path)
		if err != nil {
			continue // skip a single unreadable file, do not abort
		}
		m := parseLLMConf(string(b))
		if len(m) == 0 {
			continue
		}
		if m["api_key"] != "" {
			warnIfSecretReadable(path)
		}
		out = append(out, m)
	}
	return out
}

func parseLLMConf(body string) map[string]string {
	m := map[string]string{}
	for i, line := range strings.Split(body, "\n") {
		if i == 0 {
			line = strings.TrimPrefix(line, "\ufeff") // strip a leading UTF-8 BOM (TrimSpace won't)
		}
		line = strings.TrimSpace(line) // also drops a trailing \r from CRLF
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=") // split on the FIRST '=' only
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		if !llmConfKeys[key] || val == "" {
			continue
		}
		m[key] = val // last assignment of a key within a file wins
	}
	return m
}

// warnIfSecretReadable warns when an llmN.conf holding an api_key is readable by
// group or other, since secrets are better kept in environment variables.
func warnIfSecretReadable(path string) {
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr,
			"WARNING: %s is group/other-readable and contains api_key; run 'chmod 600 %s' "+
				"(env vars are the recommended place for secrets)\n", path, path)
	}
}
