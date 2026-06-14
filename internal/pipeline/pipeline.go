// Package pipeline ties the stages together: cheap deterministic static rules
// first, then (if an LLM backend is available) a model pass informed by the
// rule hits and any reputation signals. If no backend is configured, the
// static rules alone produce a fail-closed verdict, so aurscan still protects
// users who run fully offline with no model at all.
package pipeline

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/manticore-projects/aurscan/internal/rules"
	"github.com/manticore-projects/aurscan/internal/scan"
)

// Run scans one package. rep is optional pre-formatted reputation text.
func Run(pkg string, files scan.Files, rep string) scan.Result {
	hits := rules.Scan(files)

	// Forced rules-only mode (AURSCAN_RULES_ONLY=1): skip the model entirely.
	if AllowRulesOnly() {
		return rulesOnlyVerdict(pkg, hits, "static rules only (AURSCAN_RULES_ONLY)")
	}

	sig := scan.Signals{StaticFindings: formatHits(hits), Reputation: rep}

	// If an LLM backend is configured, use it (informed by the static hits).
	if _, err := scan.PickBackend(); err == nil {
		return scan.Scan(pkg, files, sig)
	}
	// No backend: fall back to a deterministic rules-only verdict.
	return rulesOnlyVerdict(pkg, hits, "no LLM backend configured — static rules only")
}

// AllowRulesOnly reports whether the user has opted into running without an LLM
// (AURSCAN_RULES_ONLY=1) — useful to force the cheap path even when a backend
// exists, e.g. in tight CI loops.
func AllowRulesOnly() bool { return os.Getenv("AURSCAN_RULES_ONLY") == "1" }

// RunRulesOnly scans using only the static catalog (no model call, no cost).
func RunRulesOnly(pkg string, files scan.Files) scan.Result {
	return rulesOnlyVerdict(pkg, rules.Scan(files), "static rules only (AURSCAN_RULES_ONLY)")
}

func formatHits(hits []rules.Hit) string {
	if len(hits) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, h := range hits {
		fmt.Fprintf(&sb, "[%s] %s (%s) in %s: %s\n",
			h.Code, h.Name, h.Severity, h.File, h.Snippet)
	}
	return sb.String()
}

func rulesOnlyVerdict(pkg string, hits []rules.Hit, note string) scan.Result {
	v := scan.Verdict{Confidence: 60}
	switch rules.Worst(hits) {
	case rules.Critical:
		v.Verdict = "MALICIOUS"
		v.Summary = "Static rules matched critical patterns (" + note + ")."
	case rules.High:
		v.Verdict = "SUSPICIOUS"
		v.Summary = "Static rules matched high-severity patterns (" + note + ")."
	case "":
		v.Verdict = "OK"
		v.Confidence = 40
		v.Summary = "No static-rule matches (" + note + "). Note: without an LLM this is a weak signal."
	default:
		v.Verdict = "SUSPICIOUS"
		v.Summary = "Static rules matched (" + note + ")."
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Code < hits[j].Code })
	for _, h := range hits {
		v.Findings = append(v.Findings, scan.Finding{
			File: h.File, Severity: string(h.Severity),
			Quote: h.Snippet, Why: h.Code + " " + h.Name,
		})
	}
	return scan.Result{Pkg: pkg, V: v}
}
