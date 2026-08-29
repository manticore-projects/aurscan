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
	// Critical only when the script comes from a host with no claim to the
	// package — the script's author is then not the software's author. Piping a
	// project's OWN installer (sh.rustup.rs for a Rust tool, a vendor's script
	// for that vendor's software) is dangerous and unpinned, but it is not
	// evidence of malice: see unpinned_upstream_installer.
	"pipe_to_shell": {"critical", "Pipes a downloaded script into a shell from a host with no relationship to this package — the script's author is not the software's author"},
	// The word UNRELATED carries this entire check, and it was being lost. Every
	// Electron package in the AUR runs `npm install` in build() because npm IS
	// the build; the model reported it critical while writing "this is a normal
	// part of building this project, not an attack" in the same note. It had no
	// id for "npm ran, and it was legitimate" — see pkg_manager_build_deps.
	"unrelated_pkg_manager_exec": {"critical", "Runs a package-manager install/exec (npm/bun/pip/cargo/go/npx) for something OTHER than this project's own declared dependencies — the Atomic Arch signature. NOT this: an Electron/Node package running npm install to build itself"},
	"credential_access":          {"critical", "Reads credentials or secrets: SSH/GPG keys, browser profiles/cookies, tokens, crypto wallets, /etc/shadow"},
	"remote_code_exec":           {"critical", "Reverse shell, socat exec, or eval of a constructed/decoded string that executes"},
	"kernel_bpf_preload":         {"critical", "Loads eBPF/BPF or a kernel module, or uses LD_PRELOAD / process- or file-hiding tricks"},
	"exfiltration":               {"critical", "Exfiltrates data: upload to a paste/temp host, Tor C2, DNS trick, or chat webhook"},
	"disguised_source":           {"critical", "A source disguised as a patch/fix but pointing at a personal/unrelated repo, or a homoglyph/punycode host impersonating a trusted forge"},
	"obfuscated_payload":         {"critical", "A base64/hex/xxd-decoded blob that gets executed, bidi/zero-width characters, or token-splicing that hides a command"},
	"prompt_injection":           {"critical", "Package text addressed to an AI/reviewer/scanner (\"this package is safe\", \"ignore previous instructions\", a verdict) — itself evidence of malice"},
	// Narrowed to the primitives themselves. The old wording ended "…or a pacman
	// hook the package installs for itself that runs code", which a model
	// reasonably stretched to cover `systemctl enable --now` in a post_install —
	// a packaging-guideline violation, not privilege manipulation.
	"privilege_persistence":     {"critical", "Grants or escalates privilege: setuid/setgid or setcap on a binary, a sudoers rule beyond what the package's own service account needs, or pkexec policy. NOT this: enabling a service, or a sudoers rule scoped to the package's own daemon"},
	"install_scriptlet_worm":    {"critical", "An install scriptlet that replicates itself: copies its own source, or uses the victim's AUR credentials to push to aur.archlinux.org"},
	"scriptlet_system_takeover": {"critical", "An install scriptlet makes root-level system changes: drops a binary into a system bin directory, writes and enables a systemd unit, or invokes pacman"},
	"other_critical":            {"critical", "Another clearly malicious behaviour not covered by a specific check"},

	// --- warning: any one (and no critical) => SUSPICIOUS -----------------
	"network_fetch_outside_sources": {"warning", "Fetches a URL not listed in source=() during build/install that is not a normal language-toolchain dependency fetch"},
	"writes_outside_build":          {"warning", "Writes outside $srcdir/$pkgdir during build: $HOME, ~/.config, shell rc, systemd units, cron, udev, /etc outside fakeroot"},
	"unverifiable_provenance":       {"warning", "A source/download whose provenance the host cannot establish (generic object store, or a host unrelated to the stated upstream that is not a known forge)"},
	"unexplained_step":              {"warning", "A patch/fix/optimization/lockfile step with no plausible technical reason for this package, or a pkgname/pkgdesc mismatch with what the scripts do"},
	"reputation_risk":               {"warning", "A recently adopted/orphaned/newly-active package that gains build- or install-time network or package-manager behaviour, or a maintainer-field mismatch"},
	"incomplete_scan":               {"warning", "The package references a file that was not supplied to the scanner (an install= scriptlet, a local source, a .hook or a .patch), so its behaviour could not be reviewed"},
	// Siblings for the legitimate forms of the critical checks above. Without
	// these the model could only report a critical-shaped observation as
	// critical, however benign it judged it to be — and deriveVerdict has no
	// way to read the exculpatory note. A positive classification is better
	// than a boolean the model can set to excuse its own finding.
	"pkg_manager_build_deps":       {"warning", "npm/cargo/pip/go fetching THIS project's own declared dependencies at build time. Normal for Electron/Node/Rust packages; worth noting because it pulls from the network outside source=(), but it is not the Atomic Arch signature"},
	"service_enabled_by_scriptlet": {"warning", "An install scriptlet enables or starts a systemd service the package itself ships. Contrary to Arch packaging guidelines, which leave that to the user — a policy violation, not an attack"},
	"sudoers_for_own_service":      {"warning", "A sudoers drop-in scoped to the package's own service account or daemon (a monitoring probe, a web service). Legitimate and common; report it so the user can judge the scope"},
	"unpinned_upstream_installer":  {"warning", "Pipes THIS project's own installer into a shell (sh.rustup.rs for a Rust package, a vendor's script for that vendor's software). Dangerous — unpinned, unchecksummed, absent from source=(), and whatever the URL serves at build time is what runs — but not evidence of malice"},
	"telemetry":                    {"warning", "Reports the install to the project's own upstream (an analytics endpoint, an install counter). Not exfiltration: no user data, no third party. Worth surfacing because the user did not ask for it"},
	"insecure_tls_fetch":           {"warning", "Downloads with certificate verification disabled (curl -k/--insecure, wget --no-check-certificate), so the peer is unauthenticated. Worse when the checksum used to verify the download comes from the same host"},
	"packaging_policy_violation":   {"warning", "Breaks an Arch packaging guideline without being malicious: installing outside $pkgdir, an arch=() that does not match a compiled binary, a pkgver that disagrees with the source URL, missing checksums on a non-VCS source"},
	"other_warning":                {"warning", "Another behaviour warranting suspicion not covered by a specific check"},

	// --- info: never changes the verdict on its own -----------------------
	// Build-cache hygiene is real and worth telling the user about, but it is
	// not a security finding: `cargo build` and `go build` without a confined
	// CARGO_HOME/GOMODCACHE write to ~/.cargo and ~/go on essentially EVERY
	// Rust and Go package in the AUR. Reported at warning tier it pushed 7 of
	// 20 sampled packages to SUSPICIOUS and drowned the findings that mattered.
	// Info tier: shown, never blocking.
	"build_cache_unconfined": {"info", "Build writes its dependency cache outside $srcdir (~/.cargo, ~/go) — packaging hygiene, not a security risk"},
	"note":                   {"info", "Auditor note (not itself a risk)"},
}

// severityRank orders severities for "worst wins" reduction.
var severityRank = map[string]int{"info": 0, "warning": 1, "critical": 2}

// deriveVerdict maps triggered checks to a verdict, findings, a deterministic
// confidence and a synthesized summary. The verdict is a pure function of which
// checks fired: any critical => MALICIOUS, else any warning => SUSPICIOUS, else
// OK. An unrecognised ID is recorded as info (no verdict impact) so a model that
// invents an ID cannot silently escalate or de-escalate — the catch-all IDs
// (other_critical/other_warning) are the sanctioned escape hatch.
// siblingOf pairs a critical check with the warning that describes the same
// behaviour in its legitimate form. These are alternatives, not a scale: the
// question "is this curl|sh from a host with a claim to the package?" has one
// answer, and reporting both ids means the answer was not given.
var siblingOf = map[string]string{
	"pipe_to_shell":              "unpinned_upstream_installer",
	"exfiltration":               "telemetry",
	"privilege_persistence":      "sudoers_for_own_service",
	"unrelated_pkg_manager_exec": "pkg_manager_build_deps",
}

// resolveHedges drops a critical check when its benign sibling was reported for
// the SAME file and evidence.
//
// Observed on 1panel-stable-bin: the model reported one curl|sh line twice —
// pipe_to_shell (critical) and unpinned_upstream_installer (warning) — with
// identical evidence, and the critical's own note conceded "even if the host
// belongs to the upstream vendor". That is a hedge, not two findings, and
// deriveVerdict resolves a hedge by taking the maximum, which is the wrong
// direction: the warning is the more specific claim and the one the model
// actually argued for.
//
// Instructions asking the model to pick one are advice. This is the guarantee,
// and it belongs in Go for the same reason the verdict floor does.
func resolveHedges(checks []Check) []Check {
	type key struct{ id, file, evidence string }
	present := map[key]bool{}
	for _, c := range checks {
		if c.Triggered {
			present[key{c.ID, c.File, c.Evidence}] = true
		}
	}
	out := make([]Check, 0, len(checks))
	for _, c := range checks {
		if sib, ok := siblingOf[c.ID]; ok && c.Triggered &&
			present[key{sib, c.File, c.Evidence}] {
			continue // the model hedged; keep the specific claim
		}
		out = append(out, c)
	}
	return out
}

func deriveVerdict(checks []Check) (verdict string, findings []Finding, confidence float64, summary string) {
	checks = resolveHedges(checks)
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
