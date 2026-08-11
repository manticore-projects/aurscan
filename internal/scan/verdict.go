package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	maxFileBytes  = 64 * 1024
	maxTotalBytes = 240 * 1024
)

// Finding is one issue the auditor reported.
type Finding struct {
	File     string `json:"file"`
	Severity string `json:"severity"` // info | warning | critical
	Quote    string `json:"quote"`
	Why      string `json:"why"`
}

// Verdict is the auditor's structured result for one package. With the Tier-2
// checklist (discussion #56) the model supplies Checks; Verdict, Confidence,
// Summary and Findings are then DERIVED deterministically in Go (see
// deriveVerdict). Legacy models that emit Verdict/Findings directly are still
// accepted. Checks is retained on the result for transparency/debugging.
type Verdict struct {
	Verdict    string    `json:"verdict"` // OK | SUSPICIOUS | MALICIOUS
	Confidence float64   `json:"confidence"`
	Summary    string    `json:"summary"`
	Findings   []Finding `json:"findings"`
	Checks     []Check   `json:"checks,omitempty"`
}

// Rank orders verdicts so callers can compute the worst across packages.
var Rank = map[string]int{"OK": 0, "SUSPICIOUS": 1, "MALICIOUS": 2, "SKIPPED": 0}

// Result pairs a package name with its verdict and the usage it cost.
// Failed is true when the scan could not be completed (backend/comms error or
// unparseable output) rather than reflecting a genuine model judgement; callers
// that map results to exit codes use it to distinguish failure from a low score.
type Result struct {
	Pkg    string
	V      Verdict
	Usage  Usage
	Failed bool
	// Fallback is true when the winning genuine verdict came from a non-primary
	// backend in the chain (an earlier backend failed and we fell through). A
	// fallback verdict is a *degraded* scan: the primary scanner was unavailable,
	// so the unattended build-hook path treats a fallback-produced OK as needing
	// confirmation rather than an automatic pass.
	Fallback bool
	// Model is the resolved model id that produced this verdict (discussion #56),
	// recorded so runs are comparable across time and machines and so a cross-
	// backend difference is explainable rather than mysterious. May be empty for
	// CLI backends that do not expose/pin a model.
	Model string
	// Cached is true when the verdict was replayed from the verdict cache rather
	// than freshly produced by a backend. A cached result cost nothing this run,
	// so its Usage is zero.
	Cached bool
}

func failClosed(why string) Verdict {
	return Verdict{Verdict: "SUSPICIOUS", Summary: why + " (fail-closed)"}
}

// Files maps a relative filename to its text content.
type Files map[string]string

// Signals carries optional non-file context for a scan: static-rule pre-filter
// hits (rendered as text) and AUR reputation facts (votes, popularity, recent
// maintainer change). Empty fields are simply omitted from the prompt.
type Signals struct {
	StaticFindings string // pre-formatted static-rule hits
	Reputation     string // pre-formatted reputation facts
}

// ExtraInstructions, if set by the caller, is appended to the built-in
// auditor instructions (never replaces them). Wired from the config package.
var ExtraInstructions string

// Scan audits a set of package files, optionally informed by static-rule hits
// and reputation signals. Any backend error or unparseable model output yields
// a SUSPICIOUS verdict — the scanner never fails open.
func Scan(pkg string, files Files, sig Signals) Result {
	instr := Instructions
	if ExtraInstructions != "" {
		instr += "\n\n===== ADDITIONAL USER INSTRUCTIONS =====\n" + ExtraInstructions
	}
	prompt := buildPrompt(pkg, files, sig)

	chain := Backends()
	if len(chain) == 0 {
		// Defensive: pipeline.Run gates on PickBackend() before calling Scan.
		return Result{Pkg: pkg, V: failClosed("no LLM backend configured"), Failed: true}
	}
	dbg("scan %s: chain (%d backends): %v", pkg, len(chain), chain) // safe: Backend.String() redacts api_key

	// Verdict cache (discussion #56): key on the primary backend's model plus
	// the exact instructions+prompt, so an identical re-scan replays the stored
	// verdict instead of re-sampling the model. --refresh (CacheBypass) skips
	// the read but still refreshes the entry below.
	primaryModel := chain[0].ModelID()
	key := cacheKey(instr, prompt, primaryModel)
	if !CacheBypass {
		if v, model, ok := cacheLoad(key); ok {
			return Result{Pkg: pkg, V: v, Model: model, Cached: true}
		}
	}

	// last holds the most recent attempt's fail-closed verdict, returned if the
	// whole chain is exhausted. For a single-backend chain this reproduces the
	// previous behaviour exactly (same verdict, summary and Failed flag).
	var last Result
	for i, be := range chain {
		raw, u, err := CallBackend(be, instr, prompt)
		if err != nil {
			if i < len(chain)-1 {
				fmt.Fprintf(os.Stderr, "WARNING: backend %s failed; trying next\n", backendLabel(be))
			}
			dbg("scan %s: backend %s error: %v", pkg, be.Kind, err)
			last = Result{Pkg: pkg, V: failClosed("Scan failed: " + err.Error()), Failed: true}
			continue
		}
		dbg("scan %s: raw model text (%d bytes):\n%s", pkg, len(raw), raw)
		v, genuine := parseVerdictResult(raw)
		if !genuine {
			if i < len(chain)-1 {
				fmt.Fprintf(os.Stderr, "WARNING: backend %s failed; trying next\n", backendLabel(be))
			}
			dbg("scan %s: backend %s returned non-genuine output; trying next", pkg, be.Kind)
			last = Result{Pkg: pkg, V: v, Usage: u, Failed: true}
			continue
		}
		res := finishResult(pkg, v, u, i > 0, be)
		res.Model = be.ModelID()
		// Only cache a genuine PRIMARY verdict. A fallback verdict is a degraded
		// scan and must not be replayed as if the primary scanner had run.
		if i == 0 {
			cacheStore(key, res.Model, v)
		}
		return res
	}
	return last
}

// finishResult builds the winning Result, marking a fallback (non-primary)
// verdict and annotating its summary so the degraded scan is visible in every
// output path.
func finishResult(pkg string, v Verdict, u Usage, fallback bool, be Backend) Result {
	if fallback {
		note := "[verdict from fallback backend " + backendLabel(be) +
			"; earlier backend(s) in the chain failed]"
		if s := strings.TrimSpace(v.Summary); s != "" {
			v.Summary = s + " " + note
		} else {
			v.Summary = note
		}
	}
	return Result{Pkg: pkg, V: v, Usage: u, Fallback: fallback}
}

func buildPrompt(pkg string, files Files, sig Signals) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Package under review: %s\n", pkg)
	if sig.Reputation != "" {
		sb.WriteString("\n----- AUR REPUTATION SIGNALS (trusted metadata) -----\n")
		sb.WriteString(sig.Reputation)
		sb.WriteString("\n")
	}
	if sig.StaticFindings != "" {
		sb.WriteString("\n----- STATIC PRE-SCAN HITS (trusted, from local rules) -----\n")
		sb.WriteString(sig.StaticFindings)
		sb.WriteString("\nConfirm, dismiss as false positives, or extend these with your own analysis.\n")
	}
	sb.WriteString("\n===== BEGIN UNTRUSTED PACKAGE FILES =====\n")
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&sb, "\n----- FILE: %s -----\n%s", n, files[n])
	}
	sb.WriteString("\n===== END UNTRUSTED PACKAGE FILES =====\n")
	return sb.String()
}

var jsonBlobRe = regexp.MustCompile(`(?s)\{.*\}`)

// parseVerdictResult extracts the verdict and reports whether it is GENUINE: a
// real JSON object that produced a usable result. Two shapes are accepted:
//
//   - Tier 2 (preferred, discussion #56): a "checks" array of booleans. The
//     verdict, per-finding severities, confidence and summary are all DERIVED in
//     Go from which checks fired (deriveVerdict), so two runs answering the same
//     booleans yield byte-identical results and the OK/SUSPICIOUS boundary is
//     deterministic rather than a sampled label.
//   - Legacy: a top-level "verdict" string with model-assigned findings. Still
//     accepted so a model that ignores the checklist instructions keeps working,
//     just without the Tier-2 reproducibility guarantee.
//
// The non-genuine cases (no JSON, malformed JSON, neither a checks array nor a
// known verdict string) return false so the chain in Scan falls through to the
// next backend rather than stopping on a backend that produced no usable result.
func parseVerdictResult(raw string) (Verdict, bool) {
	blob := jsonBlobRe.FindString(raw)
	if blob == "" {
		dbg("parseVerdict: no JSON object found in model output (issue #17)")
		return failClosed("Scanner returned no parseable result"), false
	}
	dbgBlock("parseVerdict: extracted JSON blob", blob)
	// Checks is a pointer so we can tell an empty checklist ({"checks":[]},
	// a genuine clean OK) from an absent one (legacy shape or no result).
	var parsed struct {
		Verdict    string    `json:"verdict"`
		Confidence float64   `json:"confidence"`
		Summary    string    `json:"summary"`
		Findings   []Finding `json:"findings"`
		Checks     *[]Check  `json:"checks"`
	}
	if err := json.Unmarshal([]byte(blob), &parsed); err != nil {
		dbg("parseVerdict: json.Unmarshal failed: %v (issue #17)", err)
		return failClosed("Scanner returned malformed JSON"), false
	}

	// Tier 2: a checklist is authoritative. Derive everything deterministically
	// and ignore any model-supplied verdict/confidence/summary/findings.
	if parsed.Checks != nil {
		checks := *parsed.Checks
		verdict, findings, confidence, summary := deriveVerdict(checks)
		dbg("parseVerdict: derived %s from %d checks (confidence %.0f)", verdict, len(checks), confidence)
		return Verdict{
			Verdict:    verdict,
			Confidence: confidence,
			Summary:    summary,
			Findings:   findings,
			Checks:     checks,
		}, true
	}

	// Legacy shape: trust the model's own verdict string.
	if _, ok := Rank[parsed.Verdict]; !ok {
		dbg("parseVerdict: no checks and unknown verdict %q, downgrading to SUSPICIOUS", parsed.Verdict)
		return Verdict{Verdict: "SUSPICIOUS", Confidence: parsed.Confidence, Summary: parsed.Summary}, false
	}
	dbg("parseVerdict: legacy verdict %q (no checklist)", parsed.Verdict)
	return Verdict{
		Verdict:    parsed.Verdict,
		Confidence: parsed.Confidence,
		Summary:    parsed.Summary,
		Findings:   parsed.Findings,
	}, true
}

// parseVerdict is a thin wrapper kept for callers that only need the verdict.
func parseVerdict(raw string) Verdict {
	v, _ := parseVerdictResult(raw)
	return v
}

func isTexty(b []byte) bool {
	n := len(b)
	if n > 4096 {
		n = 4096
	}
	for _, c := range b[:n] {
		if c == 0 {
			return false
		}
	}
	return true
}

// CollectDir reads the scannable text files of a local build directory.
// It skips .git, src and pkg subdirectories, binaries, and oversized files,
// and requires a PKGBUILD to be present.
func CollectDir(dir string) (Files, error) {
	files := Files{}
	total := 0
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			if p != dir && isSkippedBuildDir(filepath.Base(p)) {
				return filepath.SkipDir
			}
			return err
		}
		if info.IsDir() {
			if isSkippedBuildDir(info.Name()) {
				if p != dir {
					return filepath.SkipDir
				}
			}
			if p != dir && isGitCheckoutDir(p) {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Size() > maxFileBytes || total > maxTotalBytes {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil || !isTexty(data) {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		files[rel] = string(data)
		total += len(data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, ok := files["PKGBUILD"]; !ok {
		return nil, fmt.Errorf("no PKGBUILD found in %s", dir)
	}
	return files, nil
}

// CollectFile reads a single PKGBUILD file directly (issue #18). The content is
// keyed as "PKGBUILD" so the auditor and static rules treat it as one.
func CollectFile(path string) (Files, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		data = data[:maxFileBytes]
	}
	if !isTexty(data) {
		return nil, fmt.Errorf("%s is not a text file", path)
	}
	return Files{"PKGBUILD": string(data)}, nil
}

// CollectStdin reads a PKGBUILD from r (stdin) for scripting (issue #18).
func CollectStdin(r io.Reader) (Files, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxFileBytes))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("no PKGBUILD content on stdin")
	}
	if !isTexty(data) {
		return nil, fmt.Errorf("stdin is not text")
	}
	return Files{"PKGBUILD": string(data)}, nil
}

// TrustScore maps a verdict to a 0-100 trust score for script integration
// (issue #18). The bands encode the verdict and the within-band position
// reflects confidence: MALICIOUS 0-33, SUSPICIOUS 34-66, OK 67-100. Higher is
// safer. Operational failures are represented separately (exit 255), not here.
func TrustScore(v Verdict) int {
	c := v.Confidence
	if c < 0 {
		c = 0
	}
	if c > 100 {
		c = 100
	}
	round := func(f float64) int { return int(f + 0.5) }
	switch v.Verdict {
	case "OK":
		return 67 + round(c*33.0/100.0)
	case "SUSPICIOUS":
		return 34 + round((100.0-c)*32.0/100.0)
	case "MALICIOUS":
		return round((100.0 - c) * 33.0 / 100.0)
	case "SKIPPED":
		return 0 // no trust judgement; exit 0 so disabled runs pass cleanly
	default:
		return 0
	}
}

func isSkippedBuildDir(name string) bool {
	switch name {
	case ".git", "src", "pkg":
		return true
	}
	return false
}

func isGitCheckoutDir(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return true
	}
	for _, name := range []string{"HEAD", "config", "objects", "refs"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return false
		}
	}
	return true
}
