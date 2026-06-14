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
	// INSTALL-003 is scoped to .install files in Scan (network access in a hook
	// that runs on the user's machine is the threat). The pattern requires a
	// command-like invocation, so a bare "nc" inside C code, a licence string
	// (CC-BY-NC-SA) or base64 signature data no longer matches.
	mk("INSTALL-003", "Network in install script", Critical, `(?i)\b(curl|wget|ncat)\b|\bnc\s+-{0,2}\w`),
	mk("PERSIST-001", "systemd service creation", Critical, `(?i)(systemctl\s+enable|/etc/systemd/system/.*\.service|/usr/lib/systemd/system/.*\.service)`),
	mk("PERSIST-002", "systemd timer creation", Critical, `(?i)\.timer\b|OnBootSec|OnCalendar`),
	mk("PERSIST-004", "boot script modification", Critical, `(?i)/etc/rc\.local|/etc/profile\.d/`),
	mk("PERSIST-006", "systemd masquerading", Critical, `(?i)systemd-[a-z]+d\b`),
	// --- Critical: mining / exfil -------------------------------------------
	mk("CRYPTO-001", "Mining pool connection", Critical, `(?i)stratum\+tcp://|pool\.(minexmr|supportxmr|nanopool)`),
	mk("CRYPTO-002", "Cryptominer binary", Critical, `(?i)\b(xmrig|minerd|cpuminer|ethminer)\b`),
	mk("EXFIL-003", "Chat webhook (C2/exfil)", Critical, `(?i)(discord\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com)`),
	mk("ENV-001", "LD_PRELOAD manipulation", Critical, `(?i)\bLD_PRELOAD\b`),
	// --- Critical: prompt-injection attempts against automated reviewers -----
	mk("AI-001", "Prompt-injection instruction", Critical, `(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|messages|prompts)\b`),
	mk("AI-002", "Forced benign verdict", Critical, `(?i)\b(verdict|classification|assessment)\s*[:=]\s*["']?(OK|SAFE|CLEAN|BENIGN)["']?\b`),
	mk("AI-003", "Reviewer-directed safety claim", Critical, `(?i)\b(this\s+package\s+is\s+(safe|clean|benign)|mark\s+this\s+(package\s+)?as\s+(safe|clean|benign|ok)|tell\s+the\s+(auditor|reviewer|scanner)\s+this\s+is\s+safe)\b`),
	mk("AI-004", "Role-marker prompt spoofing", Critical, `(?i)<\|?(system|developer|assistant)\|?>`),
	mk("AI-005", "Prompt boundary spoofing", Critical, `(?i)\b(end|begin)\s+(untrusted\s+)?(package\s+)?files\b`),
	// --- Critical: the 2025/2026 AUR campaign signatures --------------------
	mk("NPM-001", "npm/bun install at build/install", Critical, `(?i)\b(npm|npx|bun|pnpm|yarn)\s+(install|add|x|run|exec)\b`),
	mk("NPM-002", "Known malicious npm payload", Critical, `(?i)\b(atomic-lockfile|lockfile-js|js-digest)\b`),
	// --- High: obfuscation & sourcing ---------------------------------------
	mk("OBF-001", "base64 decode", High, `(?i)base64\s+(-d|--decode)`),
	mk("OBF-002", "eval of dynamic string", High, `(?i)\beval\b`),
	mk("OBF-003", "hex-encoded payload", High, `(\\x[0-9a-fA-F]{2}){4,}`),
	mk("CHK-005", "non-VCS source uses SKIP", High, `(?i)sha256sums=\([^)]*SKIP`),
	mk("URL-001", "raw IP in URL", High, `https?://\d{1,3}(\.\d{1,3}){3}`),
	// Anchored to a scheme + path so "t.co" no longer matches inside
	// "redhat.com" / "githubusercontent.com".
	mk("URL-002", "URL shortener", High, `(?i)https?://(bit\.ly|tinyurl\.com|t\.co|is\.gd|goo\.gl|ow\.ly|buff\.ly|rebrand\.ly|cutt\.ly|shorturl\.at)/`),
	mk("URL-003", "dynamic DNS host", High, `(?i)https?://[a-z0-9.\-]*(duckdns\.org|no-ip\.(com|org|biz|net)|ddns\.net|hopto\.org|zapto\.org)\b`),
	mk("HIDDEN-002", "execution from /tmp", High, `(?i)/tmp/\S+\.(sh|py|pl)\b`),
	mk("ENV-002", "PATH overwrite", High, `(?m)^\s*PATH=`),
	// --- Medium: weaker signals ---------------------------------------------
	mk("NET-001", "HTTP source URL", Medium, `(?i)source=\([^)]*http://`),
	// SRC-001 is handled specially in Scan via the reputable-host allowlist
	// (it cannot be expressed as a single regex); see checkGitHosts.
}

// VCS sources legitimately use SKIP; avoid flagging CHK-005 for them.
var vcsLine = regexp.MustCompile(`(?i)^\s*source=.*\b(git|svn|hg|bzr)\+`)

// commentLine matches a full-line shell/INI/desktop comment. Only whole-line
// comments are stripped: inline "# ..." is NOT treated as a comment because a
// PKGBUILD URL fragment (e.g. "...nomacs.git#tag=${pkgver}") legitimately
// contains '#'.
var commentLine = regexp.MustCompile(`^[ \t]*#`)

// gitSourceHost captures the host of a VCS source URL, e.g.
// `git+https://github.com/u/r.git` -> "github.com".
var gitSourceHost = regexp.MustCompile(`(?i)\b(?:git|svn|hg|bzr)\+https?://([a-z0-9.\-]+)`)

// reputableGitHosts is an allowlist of well-known forges and official
// distribution / upstream Git hosts. A VCS source on any of these is normal and
// must not be flagged by SRC-001. Extend via the user instructions file or a
// future config knob rather than editing this list in place.
var reputableGitHosts = map[string]bool{
	// major public forges
	"github.com": true, "www.github.com": true,
	"gitlab.com": true, "codeberg.org": true, "git.sr.ht": true,
	"bitbucket.org":   true,
	"sourceforge.net": true, "git.code.sf.net": true,
	// freedesktop / GNOME / KDE / X.Org
	"gitlab.freedesktop.org": true, "anongit.freedesktop.org": true,
	"gitlab.gnome.org": true, "invent.kde.org": true,
	"gitlab.x.org": true,
	// distributions
	"gitlab.archlinux.org": true, "aur.archlinux.org": true,
	"salsa.debian.org": true,
	"pagure.io":        true, "src.fedoraproject.org": true,
	"code.opensuse.org": true,
	"git.launchpad.net": true, "launchpad.net": true,
	// kernel / GNU / Apache / OpenStack
	"git.kernel.org":       true,
	"git.savannah.gnu.org": true, "git.savannah.nongnu.org": true,
	"savannah.gnu.org": true, "savannah.nongnu.org": true,
	"gitbox.apache.org": true, "opendev.org": true,
}

// isReputableGitHost reports whether host is on the allowlist, including the
// per-project *.googlesource.com mirrors (android, chromium, …).
func isReputableGitHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if reputableGitHosts[host] {
		return true
	}
	return strings.HasSuffix(host, ".googlesource.com")
}

// Scan runs the catalog over a set of files and returns hits, de-duplicated by
// (code, file). Matches that fall on a full-line comment are ignored, since a
// commented-out line is inert. SRC-001 is informational and only meaningful
// alongside other signals, so it is reported but never escalates on its own.
func Scan(files map[string]string) []Hit {
	var hits []Hit
	seen := map[string]bool{}
	add := func(code, name string, sev Severity, file, snippet string) {
		key := code + "|" + file
		if seen[key] {
			return
		}
		seen[key] = true
		hits = append(hits, Hit{Code: code, Name: name, Severity: sev, File: file, Snippet: snippet})
	}
	for name, text := range files {
		isPKGBUILD := name == "PKGBUILD" || strings.HasSuffix(name, "/PKGBUILD")
		isInstall := strings.HasSuffix(name, ".install")
		hasVCS := false
		for _, ln := range strings.Split(text, "\n") {
			if vcsLine.MatchString(ln) {
				hasVCS = true
				break
			}
		}
		for _, r := range catalog {
			// INSTALL-003 only applies to .install hook scripts.
			if r.Code == "INSTALL-003" && !isInstall {
				continue
			}
			// Find the first match that is not on a commented-out line. AI
			// prompt-injection text is still relevant in comments because the
			// model sees comments as package text.
			idx := firstLiveMatch(text, r.re, !isAIRule(r.Code))
			if idx < 0 {
				continue
			}
			if r.Code == "CHK-005" && hasVCS {
				continue // SKIP is expected for VCS sources
			}
			add(r.Code, r.Name, r.Severity, name, lineAround(text, idx))
		}
		// SRC-001: flag VCS sources on hosts that are NOT well-known forges or
		// official distribution / upstream Git hosts. Only on PKGBUILD.
		if isPKGBUILD {
			for _, m := range gitSourceHost.FindAllStringSubmatchIndex(text, -1) {
				start, host := m[0], text[m[2]:m[3]]
				if isCommentAt(text, start) || isReputableGitHost(host) {
					continue
				}
				add("SRC-001", "git source on uncommon host", Medium, name, lineAround(text, start))
			}
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

// firstLiveMatch returns the start offset of the first match of re that does not
// fall on a full-line comment, or -1 if there is none.
func firstLiveMatch(text string, re *regexp.Regexp, skipComments bool) int {
	for _, loc := range re.FindAllStringIndex(text, -1) {
		if !skipComments || !isCommentAt(text, loc[0]) {
			return loc[0]
		}
	}
	return -1
}

func isAIRule(code string) bool {
	return strings.HasPrefix(code, "AI-")
}

// isCommentAt reports whether the line containing offset idx is a full-line
// shell/desktop comment.
func isCommentAt(text string, idx int) bool {
	start := strings.LastIndexByte(text[:idx], '\n') + 1
	end := strings.IndexByte(text[start:], '\n')
	if end < 0 {
		end = len(text)
	} else {
		end += start
	}
	return commentLine.MatchString(text[start:end])
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
