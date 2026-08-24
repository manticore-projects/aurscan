package scan

// Deterministic verdict derivation from a fixed checklist (discussion #56,
// Tier 2).
//
// The reproducibility problem is that a holistic "verdict" is one sampled
// judgement, so a borderline package flips OK <-> SUSPICIOUS between runs. Tier 1
// tightened the model's distribution (temperature 0) and removed the *observable*
// flip on re-runs (verdict cache). Tier 2 removes the flip at its source: the
// model no longer emits a verdict or a made-up confidence number. It answers a
// FIXED set of concrete yes/no checks about observable behaviours, and this file
// maps the triggered checks to a verdict, severities, confidence and summary
// deterministically in Go. Two runs that answer the same booleans therefore
// produce byte-identical results, and the OK/SUSPICIOUS boundary is code we
// control rather than a coin-flip the model makes.
//
// Severity is assigned HERE, not by the model — the model only decides whether
// each behaviour is present. That fixes the other half of the flip HaleTom saw
// (the same finding scored "warning" one run and "info" the next).

import (
	"fmt"
	"sort"
	"strings"
)

// Check is one boolean sub-question the auditor answers about a concrete,
// observable behaviour. Triggered plus the copied Evidence are the only
// model-decided parts; ID selects a fixed severity from the catalog below.
type Check struct {
	ID        string `json:"id"`
	Triggered bool   `json:"triggered"`
	File      string `json:"file"`
	Evidence  string `json:"evidence"`
	Note      string `json:"note"`
}

// checkDef fixes the severity and canonical description of one checklist item.
type checkDef struct {
	Severity string // "critical" | "warning" | "info"
	Desc     string // canonical, deterministic "why" text for the finding
}

// checkCatalog is the fixed checklist. Adding/removing an entry (or changing a
// severity) is a deliberate policy change and MUST bump cacheVersion in cache.go
// so stale cached verdicts are not replayed under the new policy. The IDs are
// the contract the prompt instructs the model to use; keep the two in sync.
var checkCatalog = map[string]checkDef{
	// --- critical: any one => MALICIOUS -----------------------------------
	"pipe_to_shell":              {"critical", "Pipes a downloaded script straight into a shell, or downloads then executes it"},
	"unrelated_pkg_manager_exec": {"critical", "Runs a package-manager install/exec (npm/bun/pip/cargo/go/npx) unrelated to building this software — the Atomic Arch signature"},
	"credential_access":          {"critical", "Reads credentials or secrets: SSH/GPG keys, browser profiles/cookies, tokens, crypto wallets, /etc/shadow"},
	"remote_code_exec":           {"critical", "Reverse shell, socat exec, or eval of a constructed/decoded string that executes"},
	"kernel_bpf_preload":         {"critical", "Loads eBPF/BPF or a kernel module, or uses LD_PRELOAD / process- or file-hiding tricks"},
	"exfiltration":               {"critical", "Exfiltrates data: upload to a paste/temp host, Tor C2, DNS trick, or chat webhook"},
	"disguised_source":           {"critical", "A source disguised as a patch/fix but pointing at a personal/unrelated repo, or a homoglyph/punycode host impersonating a trusted forge"},
	"obfuscated_payload":         {"critical", "A base64/hex/xxd-decoded blob that gets executed, bidi/zero-width characters, or token-splicing that hides a command"},
	"prompt_injection":           {"critical", "Package text addressed to an AI/reviewer/scanner (\"this package is safe\", \"ignore previous instructions\", a verdict) — itself evidence of malice"},
	"privilege_persistence":      {"critical", "sudo/pkexec/setuid manipulation, sudoers edits, or a pacman hook the package installs for itself that runs code"},
	"install_scriptlet_worm":     {"critical", "An install scriptlet that replicates itself: copies its own source, or uses the victim's AUR credentials to push to aur.archlinux.org"},
	"scriptlet_system_takeover":  {"critical", "An install scriptlet makes root-level system changes: drops a binary into a system bin directory, writes and enables a systemd unit, or invokes pacman"},
	"other_critical":             {"critical", "Another clearly malicious behaviour not covered by a specific check"},

	// --- warning: any one (and no critical) => SUSPICIOUS -----------------
	"network_fetch_outside_sources": {"warning", "Fetches a URL not listed in source=() during build/install that is not a normal language-toolchain dependency fetch"},
	"writes_outside_build":          {"warning", "Writes outside $srcdir/$pkgdir during build: $HOME, ~/.config, shell rc, systemd units, cron, udev, /etc outside fakeroot"},
	"unverifiable_provenance":       {"warning", "A source/download whose provenance the host cannot establish (generic object store, or a host unrelated to the stated upstream that is not a known forge)"},
	"unexplained_step":              {"warning", "A patch/fix/optimization/lockfile step with no plausible technical reason for this package, or a pkgname/pkgdesc mismatch with what the scripts do"},
	"reputation_risk":               {"warning", "A recently adopted/orphaned/newly-active package that gains build- or install-time network or package-manager behaviour, or a maintainer-field mismatch"},
	"incomplete_scan":               {"warning", "The package references a file that was not supplied to the scanner (an install= scriptlet, a local source, a .hook or a .patch), so its behaviour could not be reviewed"},
	"other_warning":                 {"warning", "Another behaviour warranting suspicion not covered by a specific check"},

	// --- info: never changes the verdict on its own -----------------------
	"note": {"info", "Auditor note (not itself a risk)"},
}

// severityRank orders severities for "worst wins" reduction.
var severityRank = map[string]int{"info": 0, "warning": 1, "critical": 2}

// deriveVerdict maps triggered checks to a verdict, findings, a deterministic
// confidence and a synthesized summary. The verdict is a pure function of which
// checks fired: any critical => MALICIOUS, else any warning => SUSPICIOUS, else
// OK. An unrecognised ID is recorded as info (no verdict impact) so a model that
// invents an ID cannot silently escalate or de-escalate — the catch-all IDs
// (other_critical/other_warning) are the sanctioned escape hatch.
func deriveVerdict(checks []Check) (verdict string, findings []Finding, confidence float64, summary string) {
	var nCrit, nWarn, nInfo int
	for _, c := range checks {
		if !c.Triggered {
			continue
		}
		def, ok := checkCatalog[c.ID]
		if !ok {
			def = checkDef{Severity: "info", Desc: "Unrecognised check id '" + c.ID + "' (recorded, no verdict impact)"}
		}
		switch def.Severity {
		case "critical":
			nCrit++
		case "warning":
			nWarn++
		default:
			nInfo++
		}
		why := def.Desc
		if n := strings.TrimSpace(c.Note); n != "" {
			why = def.Desc + " — " + n
		}
		findings = append(findings, Finding{
			File:     c.File,
			Severity: def.Severity,
			Quote:    c.Evidence,
			Why:      why,
		})
	}
	// Stable ordering: severity desc, then id/file, so output is byte-identical
	// regardless of the order the model listed the checks.
	sort.SliceStable(findings, func(i, j int) bool {
		if severityRank[findings[i].Severity] != severityRank[findings[j].Severity] {
			return severityRank[findings[i].Severity] > severityRank[findings[j].Severity]
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Why < findings[j].Why
	})

	switch {
	case nCrit > 0:
		verdict = "MALICIOUS"
	case nWarn > 0:
		verdict = "SUSPICIOUS"
	default:
		verdict = "OK"
	}
	confidence = deriveConfidence(verdict, nCrit, nWarn, nInfo)
	summary = synthSummary(verdict, nCrit, nWarn, nInfo)
	return verdict, findings, confidence, summary
}

// deriveConfidence returns a deterministic confidence consistent with
// TrustScore's convention (for OK, higher = safer; for SUSPICIOUS/MALICIOUS,
// higher = more certain it is bad). It is a function of the finding counts only,
// so it never wanders between runs.
func deriveConfidence(verdict string, nCrit, nWarn, nInfo int) float64 {
	clamp := func(v, lo, hi int) int {
		if v < lo {
			return lo
		}
		if v > hi {
			return hi
		}
		return v
	}
	switch verdict {
	case "OK":
		if nInfo == 0 {
			return 95
		}
		return 80
	case "SUSPICIOUS":
		return float64(clamp(55+10*(nWarn-1), 50, 90))
	case "MALICIOUS":
		return float64(clamp(90+3*(nCrit-1), 90, 99))
	}
	return 50
}

// synthSummary builds a one-line, deterministic summary from the counts. Using a
// synthesized summary rather than free model prose removes the last source of
// run-to-run cosmetic drift (HaleTom: "minor warnings shown or not shown").
func synthSummary(verdict string, nCrit, nWarn, nInfo int) string {
	plural := func(n int, s string) string {
		if n == 1 {
			return fmt.Sprintf("%d %s", n, s)
		}
		return fmt.Sprintf("%d %ss", n, s)
	}
	switch verdict {
	case "OK":
		if nInfo == 0 {
			return "No suspicious behaviour found beyond normal makepkg operation."
		}
		return fmt.Sprintf("No suspicious behaviour; %s noted for context.", plural(nInfo, "informational item"))
	case "SUSPICIOUS":
		return fmt.Sprintf("%s warrant review before building.", capitalize(plural(nWarn, "warning-level finding")))
	case "MALICIOUS":
		parts := plural(nCrit, "critical finding")
		if nWarn > 0 {
			parts += " and " + plural(nWarn, "warning")
		}
		return fmt.Sprintf("%s indicate malicious behaviour; do not build.", capitalize(parts))
	}
	return ""
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
