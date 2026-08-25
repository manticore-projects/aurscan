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

	// If an LLM backend is configured, use it (informed by the static hits) —
	// but never let its judgement fall below the deterministic floor.
	if _, err := scan.PickBackend(); err == nil {
		return applyFloor(scan.Scan(pkg, files, sig), hits)
	}
	// No backend: fall back to a deterministic rules-only verdict.
	return rulesOnlyVerdict(pkg, hits, "no LLM backend configured — static rules only")
}

// StrictFloor reports whether the user asked for the widest floor
// (AURSCAN_STRICT_FLOOR=1): any critical static hit anywhere then prevents an
// OK verdict, not only those in an install scriptlet. Off by default because a
// few critical codes (PRIV-001 in particular) do occur in legitimate PKGBUILDs,
// and dismissing those is exactly what the model is for.
func StrictFloor() bool { return os.Getenv("AURSCAN_STRICT_FLOOR") == "1" }

// applyFloor folds the deterministic static-rule findings into the model's
// result as first-class checks.
//
// A rule hit is a fact; a model verdict is a judgement. A fluent judgement must
// not be able to erase a fact — that is how a scanner reports 97% confidence on
// a package whose payload it never read. But the fix must not undo Tier 2
// either: patching the Verdict afterwards would reintroduce a second summary
// generator and findings that bypassed the catalog. So the hits are converted
// to checks (rules.FloorChecks) and the whole thing is re-derived by the same
// deriveVerdict that handles the model's answers.
//
// The result is that scan.MergeStaticChecks, not this function, decides the
// verdict — and it can only ever raise it, because deriveVerdict is monotone in
// the set of triggered checks.
func applyFloor(res scan.Result, hits []rules.Hit) scan.Result {
	// A failed scan is already fail-closed; leave its diagnostics intact.
	if res.Failed {
		return res
	}
	static := staticChecks(hits, StrictFloor())
	if len(static) == 0 {
		return res
	}
	res.V = scan.MergeStaticChecks(res.V, static)
	return res
}

// staticChecks converts floor-triggering rule hits into auditor checks. An id
// the catalog does not know would be recorded as "info" by deriveVerdict — no
// verdict impact — which would silently defeat the floor, so an unknown id is
// mapped to the sanctioned catch-all instead.
func staticChecks(hits []rules.Hit, strict bool) []scan.Check {
	fcs := rules.FloorChecks(hits, strict)
	if len(fcs) == 0 {
		return nil
	}
	out := make([]scan.Check, 0, len(fcs))
	for _, fc := range fcs {
		id := fc.ID
		if !scan.KnownCheckID(id) {
			dbgFallback(id)
			id = "other_critical"
		}
		out = append(out, scan.Check{
			ID:        id,
			Triggered: true,
			File:      fc.File,
			Evidence:  fc.Evidence,
			Note:      fc.Note,
		})
	}
	return out
}

// dbgFallback reports a rules->checklist mapping that no longer resolves. This
// is a programming error rather than a scan finding: TestFloorCheckIDsAreKnown
// is meant to catch it before it ships.
func dbgFallback(id string) {
	fmt.Fprintf(os.Stderr, "WARNING: static-rule check id %q is not in the auditor checklist; "+
		"recording as other_critical\n", id)
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
	// Verdict policy without a model.
	//
	// This used to map ANY critical hit to MALICIOUS via rules.Worst(). That is
	// too strong for a mode with no model to weigh anything: a scan of 120 real
	// AUR packages that ship install scriptlets returned 32 MALICIOUS, none of
	// them malicious — an intrusion-detection config naming /etc/shadow, a
	// package shipping its own .service file, a scriptlet enabling the unit it
	// just installed. A gate that condemns a quarter of what it sees is a gate
	// people switch off.
	//
	// The non-overridable set (rules.Floor) is the honest bar: those codes have
	// no plausible benign form, and they are the same ones the model is not
	// allowed to clear when a model IS present. Everything else a critical rule
	// finds is real but needs judgement, so it lands on SUSPICIOUS and says so.
	v := scan.Verdict{Confidence: 60}
	switch {
	case rules.Floor(hits, StrictFloor()) == "MALICIOUS":
		v.Verdict = "MALICIOUS"
		v.Summary = "Static rules matched non-overridable patterns (" + note + ")."
	case rules.Worst(hits) == rules.Critical || rules.Worst(hits) == rules.High:
		v.Verdict = "SUSPICIOUS"
		v.Summary = "Static rules matched (" + note + "). Without a model these need review, not a verdict."
	case len(hits) > 0:
		// Medium/info hits — build-cache confinement, HTTP source URLs, a
		// missing local source file — are worth showing and are not grounds to
		// stop a build. BLD-001/BLD-002 alone apply to nearly every Rust and Go
		// package in the AUR; blocking on them trains people to pass --force.
		v.Verdict = "OK"
		v.Confidence = 40
		v.Summary = fmt.Sprintf("No high-severity static matches (%s); %d informational item(s) noted. "+
			"Note: without an LLM this is a weak signal.", note, len(hits))
	default:
		v.Verdict = "OK"
		v.Confidence = 40
		v.Summary = "No static-rule matches (" + note + "). Note: without an LLM this is a weak signal."
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
