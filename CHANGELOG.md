# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **paru interactive build decision now works (#3).** The `--prebuild` hook
  prompts over `/dev/tty`, so you can abort or override a flagged package even
  though paru runs `PreBuildCommand` with redirected stdio. With no controlling
  terminal (CI) it fails closed as before. (reported by Xaero252)
- **`--install-paru-hook` no longer shadows a system config (#3).** It now
  writes to the user config and, when creating a fresh one while `/etc/paru.conf`
  exists, `Include`s the system file first so existing settings are preserved.
  Install/uninstall consistently target the user config and never need root.
  (reported by rynti)



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

[Unreleased]: https://github.com/manticore-projects/aurscan/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/manticore-projects/aurscan/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/manticore-projects/aurscan/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/manticore-projects/aurscan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/manticore-projects/aurscan/releases/tag/v0.1.0
[KiefStudioMA/ks-aur-scanner]: https://github.com/KiefStudioMA/ks-aur-scanner
[issue #1]: https://github.com/manticore-projects/aurscan/issues/1
