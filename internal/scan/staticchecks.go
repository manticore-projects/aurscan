package scan

// Folding deterministic static-rule findings into the Tier-2 checklist.
//
// The problem this solves is the one that produced a 97%-confidence OK on a
// package whose payload the scanner never read: a model verdict is a judgement,
// a rule hit is a fact, and a fluent judgement must not be able to erase a fact.
//
// The naive fix is to patch the Verdict afterwards — raise the label, append a
// note to the summary, append rows to the findings. That works, but it undoes
// what checks.go exists for: the summary would then come from two generators,
// the confidence from none of them, and the findings would include rows that
// never passed through the catalog. So instead the static hits are expressed as
// CHECKS and run through the same deriveVerdict as the model's own answers.
// One derivation, one summary, one confidence, byte-identical across runs.
//
// The model may still escalate — a check it triggers counts exactly as much as
// one a rule triggered. It simply has no mechanism for clearing one.

import "sort"

// VerdictFromChecks derives a complete Verdict from a checklist. It is the
// single place a Verdict is constructed from checks, used both for the model's
// own answers and for static-rule findings.
func VerdictFromChecks(checks []Check) Verdict {
	verdict, findings, confidence, summary := deriveVerdict(checks)
	return Verdict{
		Verdict:    verdict,
		Confidence: confidence,
		Summary:    summary,
		Findings:   findings,
		Checks:     checks,
	}
}

// MergeStaticChecks folds static-rule checks into a verdict.
//
// For a Tier-2 result (the model answered a checklist) the two sets are merged
// and everything is re-derived, so a static hit is indistinguishable from a
// model-reported one in the output.
//
// For a legacy result (the model returned a verdict string and no checklist)
// there is nothing to merge into, so the static checks are derived on their own
// and the worse of the two verdicts wins. The legacy path cannot be made
// deterministic — that is the point of Tier 2 — but it must still not fail open.
func MergeStaticChecks(v Verdict, static []Check) Verdict {
	if len(static) == 0 {
		return v
	}
	if v.Checks != nil {
		combined := dedupeChecks(append(append([]Check{}, v.Checks...), static...))
		return VerdictFromChecks(combined)
	}

	sv := VerdictFromChecks(dedupeChecks(static))
	out := v
	out.Checks = sv.Checks
	out.Findings = append(out.Findings, sv.Findings...)
	if Rank[sv.Verdict] > Rank[out.Verdict] {
		out.Verdict = sv.Verdict
		out.Confidence = sv.Confidence
		out.Summary = sv.Summary
	}
	return out
}

// dedupeChecks drops exact duplicates by (id, file, evidence). Without it a
// behaviour both the model and a rule reported would be counted twice, which
// would move the derived confidence for no reason — the same class of
// run-to-run wobble Tier 2 removed.
func dedupeChecks(in []Check) []Check {
	seen := map[[3]string]bool{}
	var out []Check
	for _, c := range in {
		k := [3]string{c.ID, c.File, c.Evidence}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	// Stable ordering so the derived output does not depend on whether the
	// model or the rules reported a behaviour first.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Evidence < out[j].Evidence
	})
	return out
}

// KnownCheckID reports whether id is in the auditor's checklist catalog. The
// pipeline uses it to assert that every static-rule mapping resolves to a real
// check, so a renamed catalog entry fails a test rather than silently demoting
// a critical finding to "unrecognised id" (which deriveVerdict records as info,
// i.e. no verdict impact at all).
func KnownCheckID(id string) bool {
	_, ok := checkCatalog[id]
	return ok
}

// CheckIsCritical reports whether a catalog id carries critical severity.
func CheckIsCritical(id string) bool {
	def, ok := checkCatalog[id]
	return ok && def.Severity == "critical"
}
