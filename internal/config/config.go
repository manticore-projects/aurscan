// Package config resolves aurscan's runtime configuration from environment
// variables and optional files under the user's config directory, so behaviour
// can be tuned without recompiling.
package config

import (
	"os"
	"path/filepath"
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
