# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.4] - 2026-08-25

### Changed
- **Build-cache hygiene warns but no longer blocks.** `cargo build`/`cargo fetch`
  without a confined `CARGO_HOME`, and `go build` without `GOPATH`/`GOMODCACHE`,
  do write to `~/.cargo` and `~/go` — and they do so on essentially every Rust
  and Go package in the AUR. Reported at warning level it pushed 7 of 20 sampled
  packages to SUSPICIOUS and buried the findings that mattered. There is now an
  info-tier checklist id, `build_cache_unconfined`, for the model to use instead
  of `writes_outside_build`, and `--rules-only` reserves SUSPICIOUS for
  high-severity and critical matches: medium and informational hits are shown
  with the verdict left at OK. Blocking on something true of nearly every
  package in an ecosystem trains people to pass `--force`.

### Fixed
- **A full sweep of the live AUR.** All 111,018 live packages were scanned
  offline with static rules only. Three trip a non-overridable rule, all of them
  piping a canonical upstream installer to a shell at build time
  (`sh.rustup.rs`, `get-ghcup.haskell.org`, a vendor installer). Nothing
  resembling the `xsnow` worm. That result is a floor rather than a clearance:
  it says no package matched the patterns someone thought to write. A closer
  look at 20 packages the rules did *not* flag found a `package()` running
  `sudo cp … /usr/bin` outside fakeroot, a patch fetched from a mutable GitLab
  merge-request diff URL, and a `pkgver` that does not match the version its
  source URL downloads — none malicious, none expressible as a regex.
- **The model's answer is no longer thrown away when it reasons in prose.** JSON
  was extracted with a greedy `\{.*\}` over the whole reply, so the first brace
  in the model's own prose — invariably inside a `${srcdir}` or `${pkgdir}` it
  was quoting back — started the match, and it ran to the last brace in the
  file. The result was "Scanner returned malformed JSON (fail-closed)" on 2 of
  20 packages in a sample, and in both the model had returned a perfectly valid
  `{"checks": []}`: a clean verdict discarded as SUSPICIOUS.

  Extraction now prefers a fenced ` ```json ` block, then scans forward for a
  brace-balanced object that is valid JSON *and* carries a `checks` or `verdict`
  key. Both halves of that test are load-bearing: string literals are tracked so
  a brace inside an evidence snippet does not close the object, and requiring
  the key stops a single check entry — valid JSON on its own — being returned as
  though it were the whole reply.
- **Behavioural rules no longer match package metadata.** `pkgdesc`, `url`,
  `license`, `groups`, `keywords`, `arch` and the version fields describe a
  package; nothing on their right-hand side executes. A sweep of the live AUR
  found `aur-malware-check-git` reported as MALICIOUS by `NPM-002` — a
  non-overridable rule matching the Atomic Arch payload names — because its
  `pkgdesc` names the campaign it exists to detect. A tool for finding an attack,
  flagged for naming the attack.

  The exclusion applies to the raw-text path and to the deobfuscated command
  view, since assignments are rendered into the latter. Two groups of rules are
  exempt: `AI-*` and `UNI-*`, for which the prose IS the attack surface — prompt
  injection works by living where a reviewer skims, and Trojan Source hides
  there — and `URL-*`, `SRC-*`, `NET-*`, `CHK-*`, `REF-*`, whose entire subject
  is the metadata. Excluding metadata from those would not reduce false
  positives, it would switch them off.

  `pkgname` is deliberately still in scope: a package *named* `xmrig-bin` is a
  miner, and `CRYPTO-002` detects miners largely by name. The name is what a
  package IS; the description is prose about it.

## [0.8.3] - 2026-08-24

### Fixed

Calibration against **all 19,934 AUR packages that declare `install=`**, cloned
from the GitHub mirror of the AUR. The 0.8.2 rules reported 195 of them as
MALICIOUS; after this release 30 remain, of which the ~8 openly-named
cryptominers are correct findings. The same defect recurs throughout: a rule
matching something *adjacent to* the thing it claims to detect.

- **`OBF-004`** treated every multi-part word as token splicing, so every `sed`
  script, `awk` program and quote-escape idiom in the AUR looked obfuscated —
  `'"'"'` is the only way to put a single quote inside a single-quoted string,
  and at the parse-tree level it is indistinguishable from splicing. Splicing
  now requires alphanumeric characters on *both* sides of the quoted fragment,
  which is what disguising a command name looks like (`s"ud"o`, `cu""rl`,
  `/etc/su""doers`) and what quoting a dot-delimited config-key segment does not
  (`git config submodule."c/c-ringbuf".url`). 112 hits, all false.
- **`UNI-002`** flagged `U+200C`/`U+200D`, which are *required orthography* in
  Indic, Arabic, Persian and Thai — a Malayalam application name in a `.desktop`
  file does not render without one. It also flagged a byte-order mark at offset
  zero, which hides nothing because nothing precedes it. Now scoped to shell
  content and to zero-width characters in the middle of the text.
- **`PKGMGR-001`** matched `pacman -Qs` (a query), `pacman --deptest`
  (case-insensitively hitting the `s` in "deptest"), `pacman -Sl`/`-Si` (sync
  queries) and `note "Use: pacman -S htop"` (where the command is `note`). Now
  anchored to the command position, case-sensitive, sync/upgrade operations only.
- **`PERSIST-009`** flagged `/etc/systemd/system/<unit>.service.d/override.conf`
  — the idiomatic drop-in for a unit the package already ships. The worm writes
  a whole new unit file, so the target must end in `.service`/`.socket`/`.timer`.
- **`PERSIST-007`** covered all of `/opt`; a package downloading a model file
  into `/opt/<pkg>/models/` with a checksum is not writing a binary. Now
  restricted to `bin`/`sbin` locations.
- **`SHELL-002`** matched any `nc … -e`. A listener serving an HTML log page
  (`nc -vlc -p 7998 -e 'printf …; cat log.html'`) is not a reverse shell; `-e`
  must execute a shell.
- **`CRED-004`** fired on `deny /home/*/.ssh/** r,` in an AppArmor profile —
  which *denies* the access — and on dropbear's initrd hook naming
  `/root/.ssh/authorized_keys`, which is the feature. Requires a reading or
  traversing verb.
- **`CRED-005`** fired on `ln -sf "$SSH_AUTH_SOCK" ~/.ssh/ssh_auth_sock`, the
  standard ssh-agent idiom. The worm replaces the *directory*.
- **`WALLET-001`** matched the bare word `keystore`, a Java/TLS term long before
  a crypto one, and hit a SIEM password tool.
- **`AI-004`** matched bare `<system>` — a usage placeholder in a help message
  and a Flask route parameter. Requires the chat-template pipe form.
- **`ENV-001`/`ENV-002`, `PRIV-001`/`PRIV-003`, `CRED-001`–`CRED-003`** scoped
  to shell content; **`EXFIL-003`/`EXFIL-004`, `DLE-001`/`DLE-002`,
  `WORM-002`/`WORM-003`** scoped to files makepkg or pacman actually executes. A
  Telegram notification in a maintainer's `check-version.sh` and an `.onion`
  address inside a `.patch` are not the package's behaviour.

### Changed
- **`CRYPTO-001`/`CRYPTO-002` are no longer non-overridable.** They are correct
  about `xmrig-bin` and friends — those packages *are* miners — but a verdict
  the model cannot clear stops someone installing one deliberately. The
  non-overridable set means "no legitimate form exists"; a knowingly-installed
  miner has one. Mining hidden in an unrelated package is still caught, because
  a model would not clear that.

## [0.8.2] - 2026-08-24

### Fixed

The v0.8.0 rules were calibrated against 158 packages, **almost none of which
ship an install scriptlet** — so the scriptlet rules, and the pre-existing rules
reused inside scriptlets, had never been exercised against a legitimate one.
Measured against 120 real AUR packages that do ship hidden scriptlets, 32 came
back MALICIOUS and none were malicious. All 120 now pass.

- **`PRIV-001`/`PRIV-003` no longer fire inside a scriptlet.** The rule asks
  whether the *build* tries to gain privileges. A scriptlet already runs as
  root, so there is nothing to gain: `sudo chmod 644 /etc/netctl/*` in a
  `post_install` is a redundant `sudo`, not an escalation.
- **`PERSIST-001` demoted to warning and narrowed.** It matched a bare
  `/usr/lib/systemd/system/*.service` path, so `install -Dm644 foo.service
  "$pkgdir/usr/lib/systemd/system/"` — how a package *ships* a unit — and
  `systemctl enable foo` in a scriptlet — how it enables the unit it just
  shipped — both read as persistence. A scriptlet *writing* a unit onto the live
  system remains fatal under `PERSIST-009`.
- **`PERSIST-006` requires a unit path**, not a mention. It matched any
  occurrence of `systemd-[a-z]+d`, so `systemd-journal-gatewayd` in a legitimate
  scriptlet read as a service masquerading as a systemd internal.
- **`PERSIST-008` removed.** It fired on `chmod +x` against a binary the package
  itself installed — a permission fix, common in `-bin` packages whose upstream
  tarball ships wrong modes. The rule conflated two acts: in the worm, the
  `chmod` follows a Tor *download* of that path, and the download is the attack.
  `PERSIST-007` catches the download. A `chmod` with nothing fetched behind it
  distinguishes nothing, and the code was non-overridable — three real packages
  would have been permanently unpassable on a permission bit.
- **`CRED-001`/`CRED-002`/`CRED-003` scoped to shell content.** An
  intrusion-detection tool's config naming `/etc/shadow` is a data file, not a
  script.

### Changed
- **`--rules-only` reserves MALICIOUS for the non-overridable rule set.** It
  previously mapped *any* critical hit to MALICIOUS, which is too strong for a
  mode with no model to weigh anything. The bar is now the same one the model is
  not allowed to clear when a model is present; everything else a critical rule
  finds lands on SUSPICIOUS and says it needs review rather than pronouncing a
  verdict.

## [0.8.1] - 2026-08-24

### Fixed
- **`REF-002` reports concealment as a warning, not a verdict.** As shipped in
  0.8.0 it was fatal on any dot-prefixed `install=`. A sweep of all 161,460 AUR
  package branches found **~120 packages** using a bare `.install` / `.INSTALL`
  as an ordinary naming convention, across years and unrelated maintainers —
  every one of which would have been condemned with no way for the model to
  clear it.

  An intermediate fix narrowed the rule to `.<pkgname>.install` on the theory
  that the per-package form was the worm's signature. That was also wrong, and
  for a more instructive reason: it rested on a base rate rather than a
  mechanism. Each AUR package is its own repository, so there is nothing for a
  filename to collide with — a worm calling itself `.install` replicates exactly
  as well and would evade the narrow check for free.

  Fatality belongs to **behaviour**, not to a filename. The worm is caught by
  what its scriptlet does, and is still MALICIOUS when the scriptlet is given an
  entirely ordinary name. The `hidden_install_scriptlet` checklist id was
  removed with it.

## [0.8.0] - 2026-08-24

### Added
- **Install-scriptlet scanning — the `xsnow` / `xsnow-bin` worm class.** A
  pacman install scriptlet is never executed by makepkg: it is embedded in the
  built package as `.INSTALL` and run by libalpm **as root on the installing
  machine**, on every install and every upgrade, with no `$pkgdir`. Nothing in
  the PKGBUILD sources it — the only link is a filename string in `install=`. A
  scanner that reviews the PKGBUILD alone can therefore report a package clean
  with complete syntactic honesty while never having seen its payload. This is
  exactly what the hostile `xsnow` package exploited: a dot-prefixed
  `.xsnow.install` that fetched a binary over Tor into `/usr/local/bin`,
  persisted it as a systemd unit, harvested `~/.ssh`, `/root/.ssh` and
  `/home/*/.ssh`, and pushed **itself** back to every AUR repository the
  victim's key could reach — so each new victim's PKGBUILD looked as clean as
  the last one's.
- **`REF-001`…`REF-004` — reference resolution.** Every file the package names
  (`install=`, local `source=()` entries) is resolved against the file set the
  scanner actually received, with iterative variable substitution so
  `install=$pkgname.install` resolves through `pkgname=jdk${java_}-graalvm-bin`.
  A referenced file that was **not supplied** means the scan is *incomplete*,
  which is a different claim from "the package is clean" and now blocks an `OK`
  verdict (`REF-001`, `REF-003`). `REF-002` reports a dot-prefixed
  scriptlet, which hides from `ls` and from dotfile-skipping tools.
  *(Shipped as a fatal finding; corrected in 0.8.1 — see below.)* `REF-004`
  reports a local source file that is genuinely absent.
- **Eleven rules for the worm family.** `PERSIST-007` (remote payload into a
  system binary directory), `PERSIST-009` (scriptlet writes a systemd unit), `PERSIST-010` (timer
  directives in a scriptlet), `PKGMGR-001` (`pacman -S` from a scriptlet),
  `EXFIL-004` (`.onion` C2), `EXFIL-005` (SOCKS proxying), `CRED-004`
  (root/all-user SSH enumeration), `CRED-005` (`~/.ssh` moved or symlinked
  away), `WORM-001` (script copies itself), `WORM-002`/`WORM-003` (AUR push
  credentials, `git push`), and `HOOK-001` (scriptlet detaches into the
  background). The install-scoped rules only fire in files pacman actually
  executes; `WORM-002`/`WORM-003` are further scoped away from maintainer
  tooling (`release`, `update.sh`) that makepkg never runs.
- **Redirection targets in the deobfuscated command view.** The payload of a
  heredoc-written systemd unit lives in a `Redirect`, not in the command's
  arguments, so `cat <<EOF >/etc/systemd/system/X.service` was previously
  invisible to every command-scoped rule. Redirect operators and targets are now
  rendered, along with a background (`&`) flag.
- **Trusted file manifest in the auditor prompt.** The model is told exactly
  which files it received, so it can distinguish "this package has no install
  scriptlet" from "I was not given the install scriptlet" — a distinction the
  PKGBUILD alone cannot express.

### Changed
- **Static findings are folded into the checklist rather than bolted on.**
  Deterministic rule hits are converted to first-class `Check` entries and run
  through the same `deriveVerdict` as the model's own answers, so one derivation
  produces the verdict, per-finding severities, confidence and summary. The
  model may always **escalate**; it has no mechanism to **clear** a finding in
  the non-overridable set. This is a floor, not an override: an ordinary
  critical hit in a PKGBUILD is still the model's call, and
  `AURSCAN_STRICT_FLOOR=1` widens it for those who want it.
- **Collectors no longer overstate their coverage.** `maxTotalBytes` raised from
  240 KB to 512 KB (`openssl-1.1` ships 41 patches totalling 382 KB, whose tail
  was silently dropped), and a file the collector skips — oversized, non-text,
  or past the aggregate cap — is now **recorded** rather than discarded. It
  appears in the file set marked as omitted, so reference resolution does not
  report the scanner's own truncation as a missing source, and the prompt lists
  it as *not reviewed* instead of asserting the supplied set is exhaustive.
- **Verdict-cache version bumped to `v3`** for the new checklist ids
  (`install_scriptlet_worm`, `scriptlet_system_takeover`, `incomplete_scan`).

### Fixed

The rule catalog was calibrated against **158 real AUR packages** cloned from
upstream. The unit suite was green at every stage below, including the stages
where a rule was wrong on every real package it touched. Across the corpus,
**53 MALICIOUS verdicts and ~120 findings became 1 and 20**, with no known false
positives remaining. The recurring defect was rules reporting the *scanner's*
confusion as a property of the package.

- **`PERSIST-002` matched a bare `.timer` in any file** — a `REUSE.toml` listing
  `"*.timer"` among its licence globs read as systemd persistence, 51 hits, all
  wrong. It now requires an *action* (`systemctl enable|start … .timer`, or a
  redirection into a systemd directory) and is scoped to shell content.
  Installing a timer unit into `$pkgdir` is normal packaging and no longer
  fires. `PERSIST-001`/`PERSIST-004` gained the same file scoping.
- **`PRIV-001` flagged `optdepends = sudo:` in `.SRCINFO`** — a dependency
  *declaration*, not an invocation. Command rules are now scoped to shell files:
  a non-shell file fails to parse and previously fell back to raw-text matching.
- **`DLE-001`/`DLE-002` matched `wget … | sha256sum`**, because `sh` matched the
  head of `sha256sum`. Both codes are non-overridable, so a missing word
  boundary would have made an ordinary checksum helper permanently unpassable.
- **`CHK-005` rewritten from a regex to positional pairing.** `SKIP` is correct
  and universal for a VCS checkout and for a detached signature verified by gpg.
  The crux was **brace expansion**: `source=(url{,.sig})` is one array token but
  two sources, so every checksum after it was off by one and the trailing `SKIP`
  — belonging to the signature — was attributed to whatever came next. Now also
  covers `b2sums`/`sha512sums`/etc. (previously `sha256sums` only) and
  arch-suffixed arrays, and exempts local files, whose integrity is the
  repository's. 13 hits became 2, both genuine.
- **Source-array parsing unified.** Quote stripping (never truncation — the
  `name::url` separator routinely sits outside the quotes), brace expansion,
  `$( )`-aware tokenisation (a substitution may contain spaces) and
  local-vs-remote classification (the scheme is often inside `$url`) are now done
  once and shared, after four separate bugs lived in the same decision.
- **Host classification split into three questions.** Canonical distribution
  points and language registries (`ftp.gnu.org`, `files.pythonhosted.org`,
  `registry.npmjs.org`, Maven Central, …) no longer trip a `url=` mismatch — a
  project's homepage is never its distribution host. GitHub's raw and object
  origins inherit `github.com`. Community asset hosts (`opendesktop.org`,
  `pling.com`, `store.kde.org`, …) are classified as **generic** rather than
  allowlisted: the upload path is chosen by whoever uploads, so the host
  establishes nothing about who produced the file.

- **Verdict reproducibility (discussion #56).** An identical re-scan no longer
  risks flipping the verdict. Two changes: sampling **temperature now defaults to
  0** (greedy) on the `api` and `openai` backends — the `api` path previously
  sent no temperature at all and ran at the provider default of 1.0 — with a
  backend-agnostic `AURSCAN_TEMPERATURE` override (and the existing
  `AURSCAN_OPENAI_TEMPERATURE`) for reasoning models that need `1.0`; and a
  **content-hash verdict cache** keyed on the package files, full instructions
  and resolved model id, so an identical input replays the stored verdict
  without calling the model. `--refresh` forces a fresh scan, `--no-cache` /
  `AURSCAN_NO_CACHE=1` disables it, `AURSCAN_CACHE_DIR` / `AURSCAN_CACHE_TTL`
  tune it. Fallback and failed scans are never cached; all cache I/O is
  best-effort and can never make a scan fail.
- **Model pinning in results.** Each result records the resolved model id that
  produced the verdict, shown in output so a cross-backend or cross-machine
  difference is explainable. The Codex CLI, which exposes no temperature/seed and
  cannot be made reproducible, is documented as such — prefer the `api` backend
  or a seeded local `openai` model when reproducibility matters.

### Changed
- **Deterministic verdict from a fixed checklist (discussion #56, Tier 2).** The
  model no longer emits the verdict, confidence or per-finding severity. It
  answers a fixed catalog of concrete yes/no checks (`pipe_to_shell`,
  `unrelated_pkg_manager_exec`, `credential_access`, `writes_outside_build`,
  `unverifiable_provenance`, …) and cites evidence; aurscan derives the verdict
  in code — any critical check → MALICIOUS, else any warning → SUSPICIOUS, else
  OK — with severities from a fixed table and a deterministic confidence and
  summary. Two runs answering the same checks yield a byte-identical result, so
  the OK/SUSPICIOUS boundary no longer flips on borderline packages. Unrecognised
  check ids are recorded as info and cannot escalate or de-escalate the verdict;
  the `other_critical`/`other_warning` catch-alls are the sanctioned escape
  hatch. Models that emit the previous `verdict`/`findings` shape are still
  accepted (without the reproducibility guarantee). The verdict-cache version was
  bumped to `v2`, so pre-existing cached verdicts are re-scanned under the new
  policy rather than replayed.

## [0.7.1] - 2026-07-04

### Added
- **`BLD-001` / `BLD-002` — build-cache confinement (#55).** A PKGBUILD that
  runs a cache-writing `go` subcommand (build/install/get/mod/…) without
  confining `GOPATH`/`GOMODCACHE` — or `cargo` (build/fetch/install/…) without
  `CARGO_HOME` — writes outside `$srcdir` into the invoking user's `$HOME`
  (`~/go/pkg/mod`, `~/.cargo`). Reported as **info**: failure by omission, not
  malice, but the user deserves to know before makepkg runs. Suppressed by a
  live export or inline prefix assignment anywhere in the file (functions share
  the makepkg process) and, for Go, by vendored builds (`-mod=vendor`). Runs on
  the deobfuscated command view, so echo'd text does not false-positive;
  non-writing subcommands (`go version`, `go env`, `cargo --version`) do not
  fire.

### Fixed
- **Usage line no longer shows `cost n/a` for priced OpenAI-compatible and Codex
  models (#52).** `callOpenAI` now prices its usage exactly like the Anthropic
  API path, so routed cloud models (LiteLLM & co.) with real token counts show a
  real cost. The built-in price table gained `gpt-5.x` / `gpt-5` / `gpt-4.x` /
  `o3` / `o4-mini` prefixes and matches proxy-qualified ids (`openai/gpt-4o`).
  The Codex CLI, which exposes neither tokens nor cost, now shows an *estimated*
  API-equivalent cost when the model is known (`AURSCAN_CODEX_MODEL` or the
  `AURSCAN_PRICE_IN`/`_OUT` override); a cost derived from estimated tokens is
  rendered `~$…`, keeping the `~tokens` / cost pair internally consistent.

## [0.7.0] - 2026-07-03

### Added
- **Shell-aware rules defeat split-token obfuscation (#43).** The command, flag
  and path rules now run against a *deobfuscated* view of each `PKGBUILD` /
  `.install`, parsed with a real shell parser ([`mvdan.cc/sh`](https://github.com/mvdan/sh),
  pure-Go, vendored, never executed). Quote- and encoding-splitting that kept the
  runtime command equal to `sudo` / `curl … | sh` but broke the literal — `s"ud"o`,
  `s''udo`, `su$'\x64'o`, line continuations, `${IFS:0:0}sudo` — is now caught as
  the command it actually runs. ~27 command/flag/path rules were bypassable this
  way; the data-literal rules (URLs, hosts, `\xNN`, `SKIP`) were not and are
  unchanged.
- **`OBF-004` — obfuscated command (token splicing).** Because a PKGBUILD has no
  honest reason to disguise a command name, the splicing itself is now flagged
  **critical**, independently of what the command is: interior quoting (`cu""rl`,
  `/etc/su""doers`), ANSI-C encoding (`su$'\x64'o`), and `${IFS…}` separator
  injection. Ordinary interpolation (`$pkgname-$pkgver`, `--prefix="/usr"`,
  `lib${pkgname}.so`) is deliberately *not* flagged.
- **Terminal-width-aware text wrapping (#50).** Findings, verdicts, the report
  block and the usage line now wrap to the terminal width instead of running off
  the edge, with per-caller indent preserved (numbered report items stay aligned)
  and named indent/width constants (`IndentBody`, `IndentBlock`, …) replacing the
  previous magic offsets. A too-wide prefix in a narrow terminal degrades to a
  20-column minimum rather than overflowing. (PR by HaleTom)
- **Pointer to LLamification.** The README links [magillos/LLamification](https://github.com/magillos/LLamification)
  as a GUI front-end option for managing the LLM configuration.

### Fixed
- **Streamlined INSTALL override prompt on the paru path (#51).** The `GateVia`
  hook (paru `PreBuildCommand`) no longer needs a `c`+Enter step before `INSTALL`;
  the prompt goes straight to `INSTALL`, rendered in bright white for visibility.
  `INSTALL` is matched case-insensitively; only `q`/`quit` exits, while empty
  input and misspellings re-prompt rather than aborting, so a typo never discards
  the already-reviewed verdicts and session usage. The direct `aurscan`/`yay`
  `Gate` path (with the `[r]eport` menu) is unchanged. (PR by HaleTom)
- **`PRIV-001` no longer false-positives on echo'd instructions (#43).** A `sudo`
  printed inside an `echo` string (post-install guidance in a `.install` hook) is
  data, not a command, and is no longer flagged — the regex could not tell a
  command position from quoted text, the shell parser can. Reported on
  `un-lock-git`.
- **Verdict-badge and colour regressions in the UI refresh.** Info-severity
  badges use bright white, colored severity badges render in every output path
  (`Gate`, `GateVia`, stderr), `printVerdict` indent dropped from 9 to 2 spaces,
  the 7-char padded badges (`  OK  ` / ` SUSP ` / ` MAL! `) are restored, and
  `Bold(ReportTo)` — briefly lost during the wrapping rewrite — is back.

### Changed
- **First vendored dependency: `mvdan.cc/sh/v3` (#43).** The shell parser (its
  `syntax`/`fileutil` packages only — pure Go, no cgo) is committed under
  `vendor/`, so the static single-binary build and the hardened release flags are
  unchanged and `go build` stays fully offline. `install.sh` and the `Makefile`
  force `-mod=vendor` when `vendor/` is present. None of the parser's test-only
  modules are compiled in.

## [0.6.4] - 2026-06-29

### Added
- **Tunable temperature and token budget for local models.** The OpenAI-
  compatible backend accepts `temperature` and `max_tokens` per backend
  (`llmN.conf`) and via `AURSCAN_OPENAI_TEMPERATURE` / `AURSCAN_OPENAI_MAX_TOKENS`.
  Reasoning models such as Gemma need `temperature=1.0` and a larger budget — with
  the old fixed 2000-token cap they spent it all on hidden reasoning and returned
  empty `content` with `finish_reason=length`, which now produces an actionable
  error instead of a silent empty verdict.
- **Startup env file (#42).** `~/.config/aurscan/env` is loaded at startup so a
  GUI or launcher can manage LLM configuration in one place. (PR by musqz)

### Changed
- **paru parity in messages (#48, #49).** Usage text and error messages mention
  `paru` alongside `yay`, and `--uninstall-yay-hook` / `--uninstall-paru-hook`
  now appear in `--help`. (PRs by HaleTom)

### Fixed
- **`syay` refresh/print/help edge cases (#37).** `-Sy`, `-Sp` and `-Sh` are
  classified as non-build, so the editor gate is not injected for them. (PR by musqz)
- **`yay -Qua` real errors no longer masked (#38).** An exit 1 with output on
  stderr is treated as a genuine failure rather than "no pending updates", so a
  real error is surfaced instead of silently reported as up-to-date. (PR by musqz)

## [0.6.3] - 2026-06-24

### Added
- **Source-provenance signals (#40).** The auditor cannot browse to confirm a
  URL belongs to a project, so a plausible but attacker-controlled source no
  longer passes on looks alone. Two offline rules flag downloads whose provenance
  the host cannot establish: `SRC-002` for generic object-storage / file hosts
  where the bucket, path or subdomain is attacker-choosable
  (`storage.googleapis.com`, `*.s3.amazonaws.com`, `*.r2.dev`, `*.pages.dev`,
  `transfer.sh`, …), and `SRC-003` for a download host that matches neither the
  package's stated upstream (`url=`) nor a known forge — both across `source=()`
  and `curl`/`wget` in `build()`/`package()`. The auditor prompt now treats
  unverifiable provenance as a risk and leans `SUSPICIOUS` rather than guessing `OK`.

## [0.6.2] - 2026-06-23

### Fixed
- Release CI now signs `SHA256SUMS` correctly in GitHub Actions (re-tag of the
  0.6.1 signing fix).

## [0.6.1] - 2026-06-23

### Fixed
- Fix GPG signing of the release `SHA256SUMS` in the GitHub Actions workflow.

## [0.6.0] - 2026-06-23

### Added
- **Backend fallback chain (#7, #35).** aurscan tries every configured backend —
  environment-detected first, then `~/.config/aurscan/llm1.conf … llmN.conf` in
  numeric order — before failing closed, instead of giving up on the first. A
  rate-limited or dead primary transparently falls through to the next. The first
  *genuine* verdict wins; only an exhausted chain falls closed to `SUSPICIOUS`.
  Behaviour is unchanged for a single healthy backend. (PR #36 by GeorgelPreput)
- **Degraded-scan awareness on the build hooks.** A verdict produced by a
  *fallback* backend is flagged and annotated; on the unattended build-hook path a
  fallback-produced `OK` requires explicit confirmation on a TTY and fails closed
  without one, closing the path where forcing the primary to fail could route
  approval to a weaker model. The standalone CLI stays lenient.
- **Unicode-abuse detection.** Static rules flag bidirectional control and
  zero-width/BOM characters (Trojan Source, CVE-2021-42574), punycode (`xn--`)
  hosts, and non-ASCII characters in source URLs (homoglyph host impersonation);
  the auditor prompt reasons about look-alike hosts and percent-encoded control
  characters too.

### Security
- **Hardened release binaries (#30).** Release artifacts are PIE with full RELRO,
  built as static-PIE via the external linker with `netgo,osusergo` so they stay
  fully static and portable. UPX was dropped (it stripped PIE/RELRO, tripped AV,
  and hurt reproducibility). Downstream `-bin` packages pass `namcap` cleanly.
- **Signed release checksums (#31).** Release CI publishes `SHA256SUMS` and a
  detached `SHA256SUMS.asc`, signed with the release-tag key, so binaries can be
  verified independently of GitHub transport.

### Fixed
- **Coloured output on the paru hook path (#34).** Colour is re-enabled against
  the controlling terminal when paru runs the hook with stdout redirected; a
  `FORCE_COLOR` escape hatch was added. The "no colour with Codex" report was the
  paru path, not the backend. (reported by HaleTom)
- **`syay` is operation-aware (#27).** Non-build yay operations pass straight
  through; the editor gate is injected only when yay actually builds a package,
  making `alias yay=syay` a safe drop-in. (PR by musqz)
- **`yay -Qua` exit 1 handled (#26).** Exit 1 meaning "no pending AUR updates" is
  treated as empty rather than an error, so `--update-check` / `--gen-file` no
  longer fail on an up-to-date system. (PR by musqz)

## [0.5.2] - 2026-06-21

### Changed
- `install.sh` advertises the native hooks and gives a version-aware yay hint
  (`--install-yay-hook` for yay v13+, the `syay` alias for older yay).

## [0.5.1] - 2026-06-21

### Added
- Warn when an old wrapper alias is made redundant by `--install-yay-hook` /
  `--install-paru-hook`.

## [0.5.0] - 2026-06-21

### Added
- **Native yay v13 integration.** `aurscan --install-yay-hook` registers an
  `AURPostDownload` Lua hook in `~/.config/yay/init.lua`, so plain `yay` (v13+)
  scans every AUR package after `makepkg --verifysource` and before build. Remove
  with `--uninstall-yay-hook`; for yay < 13 keep using `syay`.

### Changed
- The OpenAI-compatible backend omits the `model` field when
  `AURSCAN_OPENAI_MODEL` is unset, so a routing proxy (LiteLLM, …) can pick the
  model. Set it to pin a specific model. (PR #22 by magillos)

## [0.4.2] - 2026-06-20

### Added
- API key for the OpenAI-compatible backend via `AURSCAN_OPENAI_API_KEY` /
  `OPENAI_API_KEY`, for proxies like LiteLLM (#13).

### Fixed
- **paru interactive build gate (#3).** The `--prebuild` hook prompts over
  `/dev/tty` so a flagged package can be aborted or overridden even though paru
  runs `PreBuildCommand` with redirected stdio; with no terminal it fails closed.
  `--install-paru-hook` writes the user config and `Include`s `/etc/paru.conf`
  instead of shadowing it. (reported by Xaero252, rynti)
- Flush buffered terminal input before the confirmation prompt.

## [0.4.1] - 2026-06-18

### Fixed
- Claude Code CLI backend now parses the array/streaming `--output-format json`
  shape emitted by newer CLIs (v2.1.x), not only the single-object envelope.
  This resolves the "malformed JSON (fail-closed)" seen on the Claude
  subscription backend (#17): the parser walks the record array, takes the final
  `result`, and surfaces an `authentication_failed`/401 record under `--debug`.


## [0.4.0] - 2026-06-18

### Added
- **`--score` for script integration (#18).** Scans a single target and exits
  with a 0-100 trust score (MALICIOUS 0-33, SUSPICIOUS 34-66, OK 67-100; higher
  is safer), or 255 if the scan could not be completed. The score is printed to
  stdout and the verdict to stderr for clean capture.
- **Single PKGBUILD by filename or STDIN (#18).** `--score` (and the scanner
  generally) accept a regular file path or `-` to read a PKGBUILD from stdin,
  in addition to directories.
- **`--debug` LLM tracing (#17).** Prints the selected backend, the request
  payload sent to the model, the raw response, and the reason any JSON parse
  failed — diagnosing the "malformed JSON" case reported on the Claude
  subscription backend.

### Changed
- In-app security reports now draft to `aurscan@manticore-projects.com` for
  aggregation/triage instead of the Arch aur-general list. Still never sent
  automatically.
- `scan.Result` gained a `Failed` flag distinguishing an operational failure
  (backend/comms error, unparseable output) from a genuine low-trust verdict.
 
## [0.3.0] - 2026-06-14
 
### Added
- **paru support.** Integrates via paru's native `PreBuildCommand` hook, which
  runs once per package before build (covering `-S`, bare interactive search,
  `-Syu`, AUR dependencies, and cached builds). Two ways to enable:
  `aurscan --install-paru-hook` (no wrapper; one line in `paru.conf`, undo with
  `--uninstall-paru-hook`) or the `sparu` wrapper, symmetric with `syay`, which
  injects an ephemeral `PARU_CONF` that `Include`s the user's real config so it
  is preserved and never modified.
- `aurscan --prebuild <dir>` gate entrypoint (non-interactive, fail-closed, no
  editor chaining) used by the paru hook.
- `sparu` symlink installed alongside `syay`/`aurscan-edit`.
- **Codex CLI backend.** `AURSCAN_BACKEND=codex` runs the scan through the
  `codex` CLI (read-only sandbox, ephemeral, rules ignored); model selectable
  via `AURSCAN_CODEX_MODEL`. Auto-detected after `claude` when present.
- OpenAI-compatible requests now send `response_format: json_object` so servers
  that honor it return strict JSON.
### Changed
- Factored the verdict/usage printer so the interactive gate and the
  non-interactive `Decide` path share output formatting.


## [0.2.4] - 2026-06-15

### Changed
- avoid some false positives as shown in issue #10


## [0.2.3] - 2026-06-15

### Added
- `AURSCAN_TIMEOUT` (whole seconds) overrides the per-request LLM budget, which
  was previously a hard-coded 180&nbsp;s. Slow CPU-only local backends (e.g.
  Ollama on a handheld) routinely need longer to process a large prompt and
  generate a verdict (#8).

### Changed
- A request deadline now produces actionable guidance ("model did not respond
  within Ns; raise AURSCAN_TIMEOUT…") instead of the opaque
  `context deadline exceeded`.
- Each OpenAI-compatible URL in a primary/fallback pair gets its own full
  timeout budget, so a stalled primary no longer starves the fallback.
- The local-model request now sends `max_tokens`, bounding generation time on
  local servers the same way the direct-API backend already did.

### Documentation
- New "Choosing a local model" section (#1): a size-vs-suitability table (why
  ≤3B is unusable, 7–8B marginal, 14B the usable minimum, 32B the sweet spot,
  70B+ best), VRAM rules of thumb, and the two settings users most often get
  wrong — `num_ctx` (Ollama's 2048 default silently truncates the package out
  of the prompt) and `AURSCAN_TIMEOUT` on slow CPU-only hosts.

## [0.2.2] - 2026-06-14

### Changed
- Updated the auditor prompt and static-rule catalog to reflect the June 2026
  **Atomic Arch** campaign (1,500+ hijacked packages): npm `atomic-lockfile` and
  bun `js-digest`/`lockfile-js` payloads, the `src/hooks/deps` bundled stealer,
  eBPF-rootkit artifacts (`/sys/fs/bpf/hidden*`, `CAP_BPF`), paste/temp-host
  exfiltration, and user-mode + `Restart=always` systemd persistence.
- Reputation guidance now warns that the maintainer field cannot be trusted at
  face value, since attackers used git commit forgery to impersonate a
  legitimate maintainer; verdicts judge build-script behaviour over author name.

### Added
- Static rules `NPM-003` (stealer hook path), `BPF-001` (eBPF rootkit artifact),
  `EXFIL-004` (paste/temp-host upload); broadened `PERSIST-001`.
- `testdata/atomicarch-bin` wave-2 fixture (bun/js-digest, structure only).

## [0.2.1] - 2026-06-14

### Added
- Git-stamped `--version` / `-v` (also `syay --version`), printing version,
  commit, build date and Go/OS/arch. Resolution falls back through
  ldflags-stamped values → Go's embedded VCS buildinfo → a `dev` default, so
  the version is meaningful for AUR builds (no `.git`), `go install …@latest`,
  and local `go build` alike.

### Changed
- `Makefile`, `install.sh` and the AUR `PKGBUILD` now stamp version metadata via
  `-ldflags -X`. The PKGBUILD derives it from `$pkgver-$pkgrel` since release
  tarballs carry no `.git`; `git` added to `makedepends`.
- CI checks out full history (`fetch-depth: 0`), stamps release binaries with
  the tag version, and verifies the stamp before packaging.
- `install.sh` reports the built version on install.

## [0.2.0] - 2026-06-13

### Added
- **Static-rule pre-filter** (`internal/rules`): an offline, zero-cost regex
  catalog adapted from [KiefStudioMA/ks-aur-scanner] (GPL-3.0), with compatible
  codes (DLE-001, PERSIST-006, NPM-001/002, …). Runs before any model call; hits
  are fed to the model as context.
- **Local / self-hosted LLM backend** (`openai`): any OpenAI-compatible
  `/chat/completions` endpoint (llama.cpp, Ollama, vLLM) with primary→fallback
  failover and a swappable model. Generalises the community connector from
  [issue #1].
- **Configurable auditor instructions**: an optional file
  (`~/.config/aurscan/instructions.md` or `AURSCAN_INSTRUCTIONS`) appended to the
  built-in prompt; example at `packaging/instructions.example.md`.
- **Reputation signals**: AUR votes, popularity and orphan/maintainer status are
  passed to the model, which now weights low-popularity packages, recent
  maintainer changes, and changes with no obvious technical reason far more
  heavily.
- `--rules-only` flag (and `AURSCAN_RULES_ONLY`) for a free, fully-offline scan.
- Two-stage pipeline (`internal/pipeline`) with a deterministic rules-only
  verdict when no LLM backend is configured.

### Fixed
- Static-rule false positives: `sudo` vs `build()` declaration, and a browser
  profile rule matching `mozilla.org` in a homepage URL.

## [0.1.0] - 2026-06-13

### Added
- Initial release: a Claude-backed PKGBUILD/`.install` auditor that scans AUR
  packages **before `makepkg` runs**, with a fail-closed, prompt-injection-hardened
  JSON verdict contract.
- `syay` wrapper that gates builds via yay's editor step (a pacman hook fires
  too late, after `makepkg`), covering `-S`, bare search-install and `-Syu`,
  plus AUR dependencies.
- Backends: Claude Code CLI (no API key, exact cost), `ANTHROPIC_API_KEY`
  (exact tokens), and a custom command backend.
- Per-package and session token/cost reporting.
- Interactive gate (abort / report-to-mailing-list / typed override),
  in-memory AUR snapshot fetching, recursive AUR-dependency scanning.
- Makefile, installer with update/uninstall, AUR `PKGBUILD`, and CI that
  attaches UPX-packed release artifacts on tags.

[Unreleased]: https://github.com/manticore-projects/aurscan/compare/v0.8.4...HEAD
[0.8.4]: https://github.com/manticore-projects/aurscan/compare/v0.8.3...v0.8.4
[0.8.3]: https://github.com/manticore-projects/aurscan/compare/v0.8.2...v0.8.3
[0.8.2]: https://github.com/manticore-projects/aurscan/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/manticore-projects/aurscan/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/manticore-projects/aurscan/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/manticore-projects/aurscan/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/manticore-projects/aurscan/compare/v0.6.4...v0.7.0
[0.2.2]: https://github.com/manticore-projects/aurscan/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/manticore-projects/aurscan/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/manticore-projects/aurscan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/manticore-projects/aurscan/releases/tag/v0.1.0
[KiefStudioMA/ks-aur-scanner]: https://github.com/KiefStudioMA/ks-aur-scanner
[issue #1]: https://github.com/manticore-projects/aurscan/issues/1
