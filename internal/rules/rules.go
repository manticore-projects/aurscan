// Package rules implements deterministic, offline static analysis of PKGBUILD
// and .install text. It is a fast, zero-cost pre-filter that runs before any
// model call: every hit is fed to the LLM as prior context, and the hits alone
// can also stand in for a verdict when no LLM backend is configured.
//
// The rule catalog is adapted from the patterns documented by
// KiefStudioMA/ks-aur-scanner (GPL-3.0); the codes (DLE-001, PERSIST-006, …)
// are kept compatible so findings are cross-referenceable. Regexes are
// intentionally conservative — static analysis cannot see intent, so these
// inform the LLM rather than replace it.
package rules

import (
	"regexp"
	"sort"
	"strings"
)

// Severity mirrors scan severities so findings merge cleanly.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "warning" // maps to the auditor's "warning" tier
	Medium   Severity = "info"
	Low      Severity = "info"
)

// Rule is a single static pattern.
type Rule struct {
	Code     string
	Name     string
	Severity Severity
	re       *regexp.Regexp
}

// Hit is a matched rule with the offending line.
type Hit struct {
	Code     string
	Name     string
	Severity Severity
	File     string
	Snippet  string
}

func mk(code, name string, sev Severity, pattern string) Rule {
	return Rule{code, name, sev, regexp.MustCompile(pattern)}
}

// catalog is the built-in rule set. Patterns are case-insensitive where useful.
var catalog = []Rule{
	// --- Critical: remote code execution -----------------------------------
	mk("DLE-001", "Curl pipe to shell", Critical, `(?i)curl\s[^|]*\|\s*(ba)?sh`),
	mk("DLE-002", "Wget pipe to shell", Critical, `(?i)wget\s[^|]*\|\s*(ba)?sh`),
	mk("DLE-003", "Download then execute", Critical, `(?i)(curl|wget)\s.*-o\s*(\S+).*(chmod\s*\+x|\./)`),
	mk("PASTE-001", "Paste-site download", Critical, `(?i)(pastebin\.com|ptpb\.pw|paste\.ee|0x0\.st|transfer\.sh)`),
	// --- Critical: reverse shells -------------------------------------------
	mk("SHELL-001", "Bash reverse shell", Critical, `/dev/tcp/`),
	mk("SHELL-002", "Netcat reverse shell", Critical, `(?i)\bn(c|cat)\b[^\n]*\s-e\b`),
	mk("SHELL-003", "Python reverse shell", Critical, `(?i)socket\.socket\(|pty\.spawn`),
	mk("SHELL-004", "Socat shell", Critical, `(?i)socat\s.*exec`),
	// --- Critical: credential / secret access -------------------------------
	mk("CRED-001", "SSH key access", Critical, `(?i)(~|\$HOME|/home/[^/]+)/\.ssh\b`),
	mk("CRED-002", "GPG key access", Critical, `(?i)(~|\$HOME|/home/[^/]+)/\.gnupg\b`),
	mk("CRED-003", "Secret file access", Critical, `(?i)(/etc/shadow|\.netrc|\.aws/credentials|\.config/gh/hosts)`),
	mk("BROWSER-001", "Browser profile access", Critical, `(?i)(~|\$HOME|/home/[^/]+)/\.(mozilla|config/(google-chrome|chromium))\b`),
	mk("BROWSER-002", "Browser secret DB access", Critical, `(?i)(logins\.json|cookies\.sqlite|Login Data)`),
	mk("WALLET-001", "Crypto wallet access", Critical, `(?i)(\.electrum|wallet\.dat|\.config/Exodus|keystore)`),
	// --- Critical: privilege / persistence ----------------------------------
	mk("PRIV-001", "sudo/pkexec in PKGBUILD", Critical, `(?i)\b(sudo|pkexec)\s`),
	mk("PRIV-003", "sudoers modification", Critical, `(?i)/etc/sudoers`),
	mk("INSTALL-003", "Network in install script", Critical, `(?i)(curl|wget|nc|ncat)\b`),
	mk("PERSIST-001", "systemd service creation", Critical, `(?i)(systemctl\s+enable|/etc/systemd/system/.*\.service|/usr/lib/systemd/system/.*\.service)`),
	mk("PERSIST-002", "systemd timer creation", Critical, `(?i)\.timer\b|OnBootSec|OnCalendar`),
	mk("PERSIST-004", "boot script modification", Critical, `(?i)/etc/rc\.local|/etc/profile\.d/`),
	mk("PERSIST-006", "systemd masquerading", Critical, `(?i)systemd-[a-z]+d\b`),
	// --- Critical: mining / exfil -------------------------------------------
	mk("CRYPTO-001", "Mining pool connection", Critical, `(?i)stratum\+tcp://|pool\.(minexmr|supportxmr|nanopool)`),
	mk("CRYPTO-002", "Cryptominer binary", Critical, `(?i)\b(xmrig|minerd|cpuminer|ethminer)\b`),
	mk("EXFIL-003", "Chat webhook (C2/exfil)", Critical, `(?i)(discord\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com)`),
	mk("ENV-001", "LD_PRELOAD manipulation", Critical, `(?i)\bLD_PRELOAD\b`),
	// --- Critical: the 2025/2026 AUR campaign signatures --------------------
	mk("NPM-001", "npm/bun install at build/install", Critical, `(?i)\b(npm|npx|bun|pnpm|yarn)\s+(install|add|x|run|exec)\b`),
	mk("NPM-002", "Known malicious npm payload", Critical, `(?i)\b(atomic-lockfile|lockfile-js|js-digest)\b`),
	// --- High: obfuscation & sourcing ---------------------------------------
	mk("OBF-001", "base64 decode", High, `(?i)base64\s+(-d|--decode)`),
	mk("OBF-002", "eval of dynamic string", High, `(?i)\beval\b`),
	mk("OBF-003", "hex-encoded payload", High, `(\\x[0-9a-fA-F]{2}){4,}`),
	mk("CHK-005", "non-VCS source uses SKIP", High, `(?i)sha256sums=\([^)]*SKIP`),
	mk("URL-001", "raw IP in URL", High, `https?://\d{1,3}(\.\d{1,3}){3}`),
	mk("URL-002", "URL shortener", High, `(?i)(bit\.ly|tinyurl\.com|t\.co|is\.gd)`),
	mk("URL-003", "dynamic DNS host", High, `(?i)(duckdns\.org|no-ip\.|ddns\.net)`),
	mk("HIDDEN-002", "execution from /tmp", High, `(?i)/tmp/\S+\.(sh|py|pl)\b`),
	mk("ENV-002", "PATH overwrite", High, `(?m)^\s*PATH=`),
	// --- Medium: weaker signals ---------------------------------------------
	mk("NET-001", "HTTP source URL", Medium, `(?i)source=\([^)]*http://`),
	mk("SRC-001", "git source on personal host", Medium, `(?i)git\+https?://(github|gitlab)\.com/[^/]+/`),
}

// VCS sources legitimately use SKIP; avoid flagging CHK-005 for them.
var vcsLine = regexp.MustCompile(`(?i)^\s*source=.*\b(git|svn|hg|bzr)\+`)

// Scan runs the catalog over a set of files and returns hits, de-duplicated by
// (code, file). SRC-001 is informational and only meaningful alongside other
// signals, so it is reported but never escalates on its own.
func Scan(files map[string]string) []Hit {
	var hits []Hit
	seen := map[string]bool{}
	for name, text := range files {
		isPKGBUILD := name == "PKGBUILD" || strings.HasSuffix(name, "/PKGBUILD")
		hasVCS := false
		for _, ln := range strings.Split(text, "\n") {
			if vcsLine.MatchString(ln) {
				hasVCS = true
				break
			}
		}
		for _, r := range catalog {
			// SRC-001 noise control: only on PKGBUILD.
			if r.Code == "SRC-001" && !isPKGBUILD {
				continue
			}
			loc := r.re.FindStringIndex(text)
			if loc == nil {
				continue
			}
			if r.Code == "CHK-005" && hasVCS {
				continue // SKIP is expected for VCS sources
			}
			key := r.Code + "|" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			hits = append(hits, Hit{
				Code: r.Code, Name: r.Name, Severity: r.Severity,
				File: name, Snippet: lineAround(text, loc[0]),
			})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].File != hits[j].File {
			return hits[i].File < hits[j].File
		}
		return hits[i].Code < hits[j].Code
	})
	return hits
}

// Worst returns the highest severity among hits ("" if none).
func Worst(hits []Hit) Severity {
	order := map[Severity]int{Medium: 1, High: 2, Critical: 3}
	var worst Severity
	best := 0
	for _, h := range hits {
		if order[h.Severity] > best {
			best, worst = order[h.Severity], h.Severity
		}
	}
	return worst
}

func lineAround(text string, idx int) string {
	start := strings.LastIndexByte(text[:idx], '\n') + 1
	end := strings.IndexByte(text[idx:], '\n')
	if end < 0 {
		end = len(text)
	} else {
		end += idx
	}
	s := strings.TrimSpace(text[start:end])
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
