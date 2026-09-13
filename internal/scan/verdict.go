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

	"github.com/manticore-projects/aurscan/internal/rules"
)

const (
	maxFileBytes = 64 * 1024
	// maxTotalBytes was 240 KB, which truncated ordinary patch-heavy packages:
	// openssl-1.1 ships 41 patches totalling 382 KB, so its tail was silently
	// dropped. Model context is no longer the binding constraint it was when
	// this was chosen.
	maxTotalBytes = 512 * 1024
)

// Finding is one issue the auditor reported.
//
// Why is the full composed text (canonical catalog description + the auditor's
// note). It is what the drafted report and any JSON consumer see, and it is kept
// whole so a report a maintainer receives still explains what the check means.
//
// Label and Note are the split form the terminal uses. Printing Why on every
// finding repeated the same 30-word catalog description once per hit — twice for
// the same check in a two-source package — which buried the one sentence that
// was actually about this package. The terminal prints "Label: Note" instead.
type Finding struct {
	File     string `json:"file"`
	Severity string `json:"severity"` // info | warning | critical
	Quote    string `json:"quote"`
	Why      string `json:"why"`
	// ID is the catalog check id, kept so output can be grepped and scripted.
	ID string `json:"id,omitempty"`
	// Label is the short human name of the check (catalog-fixed, deterministic).
	Label string `json:"label,omitempty"`
	// Note is the auditor's sentence about THIS instance, with no catalog
	// boilerplate prepended.
	Note string `json:"note,omitempty"`
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
	// Synopsis is the auditor's plain description of what the package DOES —
	// where it gets its sources, what it builds, what it installs. It is not a
	// judgement and it is deliberately outside the derivation: nothing in it can
	// change the verdict, the confidence or the severities.
	//
	// Tier 2 replaced the model's free-text summary with a count line
	// ("No suspicious behaviour; 2 informational items noted"), which fixed the
	// run-to-run drift but also removed the only place the output said what the
	// package was. The count line duplicates the findings printed directly under
	// it; the description does not exist anywhere else. Both facts argue for
	// carrying a descriptive field separately rather than reviving the old one.
	Synopsis string `json:"synopsis,omitempty"`
}

// Rank orders verdicts so callers can compute the worst across packages.
var Rank = map[string]int{"OK": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}

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
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	// Trusted manifest, computed here rather than read from the package. It is
	// the only way the auditor can tell "this package has no install scriptlet"
	// apart from "I was not given the install scriptlet" — a distinction the
	// PKGBUILD alone cannot express, because the only link between a PKGBUILD
	// and its scriptlet is a filename string in install=.
	var supplied, omitted []string
	for _, n := range names {
		if rules.IsOmitted(files[n]) {
			omitted = append(omitted, n)
		} else {
			supplied = append(supplied, n)
		}
	}
	fmt.Fprintf(&sb, "\n----- FILES SUPPLIED TO YOU (trusted, %d) -----\n", len(supplied))
	for _, n := range supplied {
		fmt.Fprintf(&sb, "  %s\n", n)
	}
	if len(omitted) > 0 {
		// Never claim a truncated set is complete. A package whose payload sits
		// in a file the collector skipped would otherwise be reviewed by a model
		// that had been told it had seen everything.
		fmt.Fprintf(&sb, "\n----- FILES PRESENT BUT NOT SUPPLIED (trusted, %d) -----\n", len(omitted))
		for _, n := range omitted {
			fmt.Fprintf(&sb, "  %s\n", n)
		}
		sb.WriteString("These files exist in the package but were too large, too numerous or\n" +
			"not text, so they were NOT reviewed. Your review is INCOMPLETE: trigger\n" +
			"incomplete_scan and do not certify behaviour that could live in them.\n")
	} else {
		sb.WriteString("Every file in the package is listed above. Any file referenced by the\n" +
			"package but absent from this list was NOT reviewed.\n")
	}

	sb.WriteString("\n===== BEGIN UNTRUSTED PACKAGE FILES =====\n")
	for _, n := range supplied {
		fmt.Fprintf(&sb, "\n----- FILE: %s -----\n%s", n, files[n])
	}
	sb.WriteString("\n===== END UNTRUSTED PACKAGE FILES =====\n")
	return sb.String()
}

var jsonBlobRe = regexp.MustCompile(`(?s)\{.*\}`)

// jsonFenceRe finds a ```json … ``` fenced block, which models emit even when
// told not to.
var jsonFenceRe = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*?\\})\\s*```")

// extractJSONObject pulls the model's JSON object out of a reply that may also
// contain prose.
//
// The old approach was a greedy `\{.*\}` over the whole reply, and it failed
// whenever the prose itself contained a brace — which it does constantly, since
// the model quotes shell back at us:
//
//	… `--cache "${srcdir}/npm-cache"` — cache goes into $srcdir …
//	```json
//	{"checks": []}
//	```
//
// The first `{` there belongs to ${srcdir}, so the match ran from mid-sentence
// to the last brace in the file and produced garbage. The model's answer was
// perfectly valid; the extractor could not find it. Two of twenty packages in a
// sample failed this way, and every one of them was a clean verdict thrown
// away — a fail-closed SUSPICIOUS on a package the model had cleared.
//
// Strategy, in order: a fenced ```json block; then a balanced-brace scan
// anchored at each `{` from the END of the reply backwards, since the answer
// comes last; then the old greedy match as a final fallback.
func extractJSONObject(raw string) string {
	if m := jsonFenceRe.FindStringSubmatch(raw); m != nil {
		if json.Valid([]byte(m[1])) {
			return m[1]
		}
	}
	// Scan forward, and require the candidate to LOOK like a verdict. Both
	// halves matter: scanning backwards finds the innermost object first, and a
	// single check entry — {"id":…,"triggered":true} — is perfectly valid JSON
	// on its own, so "first valid object" would silently return one finding as
	// though it were the whole reply.
	var longest string
	for i := strings.IndexByte(raw, '{'); i >= 0; {
		obj := balancedObject(raw[i:])
		if obj != "" && json.Valid([]byte(obj)) {
			var probe map[string]json.RawMessage
			if json.Unmarshal([]byte(obj), &probe) == nil {
				if _, ok := probe["checks"]; ok {
					return obj
				}
				if _, ok := probe["verdict"]; ok {
					return obj
				}
			}
			if len(obj) > len(longest) {
				longest = obj
			}
		}
		next := strings.IndexByte(raw[i+1:], '{')
		if next < 0 {
			break
		}
		i += 1 + next
	}
	if longest != "" {
		return longest
	}
	return jsonBlobRe.FindString(raw)
}

// balancedObject returns the substring of s from its leading '{' to the brace
// that closes it, or "" if the braces never balance. String literals are
// tracked so a brace inside a quoted snippet does not affect the depth.
func balancedObject(s string) string {
	if len(s) == 0 || s[0] != '{' {
		return ""
	}
	depth, inStr, esc := 0, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			esc = false
		case c == '\\' && inStr:
			esc = true
		case c == '"':
			inStr = !inStr
		case inStr:
			// nothing
		case c == '{':
			depth++
		case c == '}':
			if depth--; depth == 0 {
				return s[:i+1]
			}
		}
	}
	return ""
}

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
	blob := extractJSONObject(raw)
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
		Synopsis   string    `json:"synopsis"`
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
			Synopsis:   strings.TrimSpace(parsed.Synopsis),
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
		Synopsis:   strings.TrimSpace(parsed.Synopsis),
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
		rel, _ := filepath.Rel(dir, p)
		if info.Size() > maxFileBytes || total > maxTotalBytes {
			// Record the omission instead of dropping the name: absent and
			// "present but not read" are different facts, and only one of them
			// is about the package.
			files[rel] = rules.OmittedContent
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil || !isTexty(data) {
			files[rel] = rules.OmittedContent
			return nil
		}
		files[rel] = string(data)
		total += len(data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if c, ok := files["PKGBUILD"]; !ok || rules.IsOmitted(c) {
		return nil, fmt.Errorf("no readable PKGBUILD found in %s", dir)
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
