<div align="center">

# 🛡️ aurscan

### Catch malicious AUR packages *before* they build.

A Claude, Codex, or local model reads the `PKGBUILD` for you and blocks the build if it looks hostile.

[![GitHub stars](https://img.shields.io/github/stars/manticore-projects/aurscan?style=flat&logo=github&color=ff420e)](https://github.com/manticore-projects/aurscan/stargazers)
[![CI](https://github.com/manticore-projects/aurscan/actions/workflows/ci.yml/badge.svg)](https://github.com/manticore-projects/aurscan/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/manticore-projects/aurscan?sort=semver)](https://github.com/manticore-projects/aurscan/releases)
[![pacman repo](https://img.shields.io/badge/pacman%20repo-manticore-1793D1?logo=archlinux&logoColor=white)](https://manticore-projects.github.io/aurscan/)
[![Go](https://img.shields.io/badge/Go-1.22-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Go Report Card](https://goreportcard.com/badge/github.com/manticore-projects/aurscan)](https://goreportcard.com/report/github.com/manticore-projects/aurscan)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

</div>

---

Reading a PKGBUILD yourself only catches the attacks you already recognise. aurscan reads the package's `PKGBUILD`, `.install` scriptlets, `.SRCINFO`, and helper scripts the moment yay or paru downloads them, **before `makepkg` runs a single line**, and stops the build if the script looks malicious.

```console
$ syay firefox-patch-bin

  scanning firefox-patch-bin (3 files) ...

[ MAL! ] firefox-patch-bin  confidence 95%
         A source labelled "patches" points at a personal GitHub repo unrelated
         to Firefox and is executed during build — the July 2025 CHAOS RAT vector.
         [critical] PKGBUILD: Disguised source pulls attacker-controlled code.
             > patches::git+https://github.com/.../zenbrowser-patch.git
         ↳ tokens: 12,431 in / 214 out · $0.0413

scanner usage: 1 call(s) · tokens: 12,431 in / 214 out · $0.0413
!! Installation blocked: 1 package(s) flagged MALICIOUS.
  [A]bort (default) / [r]eport & abort / [c]ontinue anyway:
```

Two stages do the work. Fast, offline **static rules** catch the known campaign signatures at zero cost. Then a **model** — handed those rule hits plus the package's AUR reputation — makes the judgement call on everything subtle. With no model configured at all, the static rules still return a fail-closed verdict, so you are covered even fully offline.

> [!WARNING]
> An LLM scanner is a strong **extra layer, not a guarantee**. Keep building in a clean chroot, prefer official-repo packages, and stay wary of freshly-adopted orphaned packages. See [Limitations](#limitations).

## Contents

- [Why it exists](#why-it-exists)
- [Install](#install)
- [How it hooks into yay and paru](#how-it-hooks-into-yay-and-paru)
- [Authentication](#authentication)
- [Usage](#usage)
- [Configuration](#configuration)
- [Cost and tokens](#cost-and-tokens)
- [Customising detection](#customising-detection)
- [Reproducibility](#reproducibility)
- [Safety model](#safety-model)
- [Limitations](#limitations)
- [Project layout](#project-layout)
- [Contributing](#contributing)

## Why it exists

In July 2025 the AUR packages `firefox-patch-bin`, `librewolf-fix-bin`, and `zen-browser-patched-bin` shipped a `source=()` entry disguised as `patches`. It actually pulled a personal GitHub repo and ran **CHAOS RAT** at build time. They looked like ordinary browser fixes, a glance at the PKGBUILD gave nothing obvious away, and they stayed live for roughly 46 hours.

Then in June 2026 the **Atomic Arch** campaign made the point at scale. Attackers adopted **1,500+ orphaned** AUR packages and added a post-install step running `npm install atomic-lockfile`, later `bun install js-digest`, which pulled a Rust credential stealer and, when built as root, an **eBPF rootkit**. Some used git commit forgery to impersonate a trusted maintainer. The package name and history were unchanged. Only the build instructions, and who wrote them, had quietly changed.

aurscan is built for exactly this: the unfamiliar trick, not just the one you happen to know. Its prompt and static rules encode both of the signatures above, and the model is there to catch the next one nobody has seen yet.

## Install

### With yay or paru (recommended)

aurscan ships its own signed pacman repository, so `yay`/`paru` install and
upgrade it exactly like any other package — no toolchain, no AUR account, no
rebuild on every release.

**1. Trust the signing key** (once). Fetch it over HTTPS from the same host that
serves the repository:

```bash
curl -fsSL https://manticore-projects.github.io/aurscan/aurscan.gpg |
  sudo pacman-key --add -
sudo pacman-key --lsign-key 61E73AA7539ACB261ABCF10C188331308EF56D11
```

Or from a keyserver, if you prefer:

```bash
sudo pacman-key --recv-keys 61E73AA7539ACB261ABCF10C188331308EF56D11 \
  --keyserver hkps://keyserver.ubuntu.com
sudo pacman-key --lsign-key 61E73AA7539ACB261ABCF10C188331308EF56D11
```

> Keyservers are best-effort and frequently unreachable. If `--recv-keys` fails
> with *"Server indicated a failure"*, check what your system is querying with
> `grep -i '^keyserver ' /etc/pacman.d/gnupg/gpg.conf` — installs from before
> 2021 often still point at `pool.sks-keyservers.net`, which no longer exists.
> Use the HTTPS route above instead.

What establishes trust either way is the **fingerprint**, not the transport. It
is the same key that signs the release checksums on every GitHub release, so you
can cross-check it against `SHA256SUMS.asc` there.

**2. Add the repository** to the end of `/etc/pacman.conf`. Safe to re-run — it
does nothing if the section is already there:

```bash
grep -q '^\[manticore\]' /etc/pacman.conf ||
  printf '\n[manticore]\nSigLevel = Required DatabaseOptional\nServer = https://manticore-projects.github.io/aurscan/$arch\n' |
  sudo tee -a /etc/pacman.conf
```

Which appends:

```ini
[manticore]
SigLevel = Required DatabaseOptional
Server = https://manticore-projects.github.io/aurscan/$arch
```

Appending puts it last, so official repositories keep precedence over it. Leave
`$arch` exactly as written — pacman expands it, your shell must not.

**3. Install:**

```bash
yay -Syu aurscan-bin      # or: paru -Syu aurscan-bin  ·  sudo pacman -Syu aurscan-bin
```

From here `yay -Syu` keeps aurscan current along with everything else. `x86_64`
and `aarch64` are both published, and every package plus the repository database
is signed with the same key that signs the release checksums.

> Adding any third-party repository grants it root-level trust for anything it
> ships. `SigLevel = Required` means pacman rejects anything not signed by the
> key you locally signed above; the repository cannot be narrowed to specific
> package names, so add it only if you're willing to extend that trust.

### From source, with makepkg

Prefer to compile it yourself? The PKGBUILD lives in this repository:

```bash
git clone https://github.com/manticore-projects/aurscan
makepkg -si -D aurscan/packaging/aurscan      # needs Go; builds offline (deps vendored)
```

Updates are `git pull` then the same `makepkg -si`. There is also
`packaging/aurscan-git` if you want to track `master` rather than the latest
release.

### From source, without pacman

```bash
git clone https://github.com/manticore-projects/aurscan
cd aurscan
./install.sh                 # build (needs Go) + install into /usr/local/bin
#   update:    git pull && ./install.sh
#   uninstall: ./install.sh --uninstall
```

All routes install **one static binary** under four names: `aurscan` (the CLI),
`syay` (the yay wrapper), `sparu` (the paru wrapper), and `aurscan-edit` (the
editor gate the wrappers invoke).

> **Not on the AUR.** aurscan was previously published as
> `aurscan-manticore-release-git` and `aurscan-manticore-bin-release-git`. Those
> packages misused the `-git` suffix — they resolved the newest release tag at
> build time rather than tracking a VCS branch, which the
> [VCS package guidelines](https://wiki.archlinux.org/title/VCS_package_guidelines)
> do not permit — and were removed. The repository above replaces them.

### Turn it on

Pick the line for your helper — one command, then it scans every AUR build automatically.

```bash
aurscan --install-yay-hook         # yay v13+  (native Lua hook; recommended)
aurscan --install-paru-hook        # paru      (native PreBuildCommand hook)
```

On **yay older than v13**, alias the wrapper instead (it forces yay's edit step through the scanner):

```fish
alias yay=syay   # fish: funcsave yay   ·   bash/zsh: echo 'alias yay=syay' >> ~/.bashrc
```

Each `--install-*-hook` is reversible with the matching `--uninstall-*-hook`, and both preserve any existing config. How and why this is the right interception point is explained next.

## How it hooks into yay and paru

A pacman hook is the wrong layer, and this is the whole design idea. PKGBUILD code runs as your user during `makepkg`, *before* pacman ever sees a package, so a `PreTransaction` hook fires only after any build-time payload has already executed. Hook-based AUR "trust" tools score the *maintainer* at install time; they cannot read what the build script actually does.

aurscan intercepts at the only safe point: **after download, before build.** Which mechanism it uses depends on your helper.

**yay v13+** ships native Lua hooks, and this is the cleanest integration. `aurscan --install-yay-hook` registers an `AURPostDownload` hook in `~/.config/yay/init.lua`. Because that fires *after* `makepkg --verifysource`, the scanner sees the **downloaded sources**, not just the PKGBUILD — and there is no editor to hijack. A flagged package is stopped with `yay.abort`. Your existing `init.lua` is preserved; `--uninstall-yay-hook` removes only aurscan's block.

**yay older than v13** has no build hook, so the `syay` wrapper points yay's editor at `aurscan-edit` and forces the edit prompt on. The scanner then runs on every AUR PKGBUILD yay is about to build.

| You type | What gets scanned |
|---|---|
| `syay -S pkg` | the named package |
| `syay pkg` | the package you pick from yay's interactive search menu |
| `syay -Syu` | every AUR upgrade |
| *(any of the above)* | and their AUR **dependencies**, which yay also presents before building |

On a clean verdict, `syay` chains to your real `$VISUAL`/`$EDITOR`, so your own manual review still happens. On a non-OK verdict it exits non-zero and yay aborts.

**paru** has a native `PreBuildCommand` hook. `aurscan --install-paru-hook` writes it to `~/.config/paru/paru.conf`; alternatively `alias paru=sparu` injects an ephemeral config (via `PARU_CONF`) that `Include`s your real `paru.conf`, so your own settings are preserved and never modified. Either way the scan runs once per package in its build directory, covering `-S`, interactive search, `-Syu`, AUR dependencies, and cached builds. A non-OK verdict makes paru abort.

All three paths share one gate: a flagged package prints its verdict and prompts on the controlling terminal — abort, or type `INSTALL` to override — and with no terminal it fails closed.

## Authentication

Backends are auto-detected in this order. **The first one needs no API key at all.**

1. **Claude Code CLI** (`claude` in `PATH`, logged in) — uses your existing Claude subscription and reports **exact cost** per scan.
2. **`ANTHROPIC_API_KEY`** — direct API (`claude-sonnet-4-6` by default). Reports exact tokens; cost is computed from a built-in price table.
3. **Codex CLI** (`codex` in `PATH`, logged in) — uses your existing Codex subscription. Tokens and cost are estimated.
4. **Local or self-hosted model** via `AURSCAN_OPENAI_URL` — any OpenAI-compatible `/chat/completions` endpoint (llama.cpp, Ollama, vLLM, LocalAI). Fully private. Set `AURSCAN_OPENAI_URL_FALLBACK` for automatic failover, e.g. GPU host to local CPU. A model is sent only when `AURSCAN_OPENAI_MODEL` is set; leave it unset and a routing proxy can pick the model itself. An API key, for proxies like LiteLLM, goes in `AURSCAN_OPENAI_API_KEY` (or the conventional `OPENAI_API_KEY`).
5. **`AURSCAN_BACKEND=/path/to/cmd`** — any executable that reads the prompt on stdin and prints the reply on stdout.
6. **No backend at all** — the static rules still run and still block on critical matches.

### Backend fallback chain

Those backends form a **chain**, not a single pick. aurscan tries them in the order above — a pinned `AURSCAN_BACKEND` stays first, otherwise every auto-detected backend is included — and when one fails (error, timeout, rate-limit, or unparseable output) it prints a one-line warning and tries the next. So a rate-limited Claude subscription transparently falls through to Codex or a local model ([#7](https://github.com/manticore-projects/aurscan/issues/7), [#35](https://github.com/manticore-projects/aurscan/issues/35)). Only when **every** backend fails does aurscan fall closed to `SUSPICIOUS` and block the build, exactly as before. On the success path only the first backend is ever called, so nothing changes for a single healthy backend.

Extend the chain with priority-ordered config files `~/.config/aurscan/llm1.conf`, `llm2.conf`, … — tried in **numeric** order (`llm2` before `llm10`), after the environment-derived backends, then de-duplicated. Each file describes one backend as flat `key = value`:

| key | meaning |
|---|---|
| `backend` | `claude` · `codex` · `api` · `openai` · or a `/path/to/exe` (a custom command, like `AURSCAN_BACKEND`) |
| `model` | model id for `api` / `codex` / `openai` |
| `url` | endpoint override (`openai` `/chat/completions`, or an Anthropic-compatible `/v1/messages` gateway for `api`) |
| `fallback` | secondary `openai` URL (intra-backend, like `AURSCAN_OPENAI_URL_FALLBACK`) |
| `api_key` | bearer / `x-api-key` for this backend |
| `temperature` | sampling temperature for `openai` (default `0.1`); reasoning models such as **Gemma** usually need `1.0` |
| `max_tokens` | output-token budget (default `2000`); raise it for reasoning models that would otherwise spend the budget on hidden reasoning and return empty |

```ini
# ~/.config/aurscan/llm1.conf — try the local GPU box first
backend = openai
url     = http://192.168.0.110:18080/v1/chat/completions
model   = qwen2.5-coder-32b
```
```ini
# ~/.config/aurscan/llm2.conf — then fall back to a custom command
backend = /usr/local/bin/my-scanner
```
```ini
# ~/.config/aurscan/llm3.conf — a reasoning model (Gemma) needs room to think
backend     = openai
url         = http://192.168.0.110:18080/v1/chat/completions
model       = gemma-thinking
temperature = 1.0      # Gemma is trained for temperature 1.0
max_tokens  = 32000    # reasoning is counted against the budget
```

- **Values are literal:** don't quote them, and a `#`/`;` starts a comment only at the start of a line (not inline).
- **Secrets:** prefer environment variables. If you put `api_key` in a file, `chmod 600` it — aurscan warns on startup when such a file is group- or other-readable.
- **Latency:** each backend gets its own full `AURSCAN_TIMEOUT`, so a K-entry chain can take up to K × that budget if backends *stall* (an `openai` entry with a `fallback` URL counts as two); lower `AURSCAN_TIMEOUT` for long chains.

<details>
<summary>Local model setup (llama.cpp / Ollama / LiteLLM)</summary>

```fish
# llama.cpp server, with a fallback to a second host
set -Ux AURSCAN_BACKEND openai
set -Ux AURSCAN_OPENAI_URL http://192.168.0.110:18080/v1/chat/completions
set -Ux AURSCAN_OPENAI_URL_FALLBACK http://127.0.0.1:18083/v1/chat/completions
set -Ux AURSCAN_OPENAI_MODEL qwen2.5-coder-32b
# API key, if your endpoint requires one (LiteLLM, vLLM, hosted proxies):
set -Ux AURSCAN_OPENAI_API_KEY sk-...
```

Pin a model behind a **LiteLLM** proxy:

```fish
set -Ux AURSCAN_BACKEND openai
set -Ux AURSCAN_OPENAI_URL http://localhost:4000/v1/chat/completions
set -Ux AURSCAN_OPENAI_MODEL gpt-4o-mini        # whatever your LiteLLM config exposes
set -Ux AURSCAN_OPENAI_API_KEY sk-your-litellm-key
```

Or let the proxy choose the model, so you can switch models server-side without touching env vars or restarting. Point at the proxy and set **no** `AURSCAN_OPENAI_MODEL`:

```fish
set -Ux AURSCAN_BACKEND openai
set -Ux AURSCAN_OPENAI_URL http://localhost:4000/v1/chat/completions
# no AURSCAN_OPENAI_MODEL — the proxy decides
set -Ux AURSCAN_OPENAI_API_KEY sk-your-litellm-key
```

> **Community tip:** to drive aurscan from a hosted provider (OpenRouter, Nvidia NIM, …) and switch models on the fly without LiteLLM, [LLamification](https://github.com/magillos/LLamification) presents one as a local OpenAI-compatible endpoint — point `AURSCAN_OPENAI_URL` at it ([#41](https://github.com/manticore-projects/aurscan/discussions/41)).

The key is sent as `Authorization: Bearer <key>`. With `AURSCAN_OPENAI_API_KEY` unset, aurscan falls back to `OPENAI_API_KEY`. Leave both unset for an open local server that needs no auth.

On a slow, CPU-only host the default 180&nbsp;s budget can expire before the model finishes, and you will see `context deadline exceeded`. Raise it, and make sure the model's context window is large enough for the prompt. A package is typically several thousand tokens, and Ollama's 2048 default will silently truncate it:

```fish
set -Ux AURSCAN_TIMEOUT 900        # 15 minutes
# on the Ollama side, give the model real context, e.g. a Modelfile with:
#   PARAMETER num_ctx 8192
```

Thanks to [@alexzk1](https://github.com/manticore-projects/aurscan/issues/1) for the original connector this backend generalises.
</details>

<details>
<summary>Choosing a local model — what actually works, and what's too small</summary>

aurscan asks more of a model than autocomplete or chat does. For each package it must reason about possibly-obfuscated shell across a multi-thousand-token prompt, return **strictly valid JSON** matching the verdict contract, and refuse to be talked out of a verdict by injected "this package is safe / ignore previous instructions" text in the untrusted files. Small models fail all three: they rubber-stamp, emit malformed JSON (which fails closed to `SUSPICIOUS` noise), or fall for the injection. Parameter count matters more here than it does for a coding assistant.

Rough guidance, with model names current as of mid-2026. The field moves fast, so check Ollama's library for equivalents.

| Size | Examples | Verdict for aurscan |
|---|---|---|
| ≤ 3B | `qwen2.5-coder:3b`, `llama3.2:3b`, `phi-*-mini` | ❌ **Don't.** Near-random verdicts, unreliable JSON. Use `--rules-only` instead. |
| 7–8B | `codellama:7b` *(the model in [#8](https://github.com/manticore-projects/aurscan/issues/8))*, `qwen2.5-coder:7b`, `llama3.1:8b` | ⚠️ **Marginal.** Catches only blatant cases, misses subtle supply-chain tricks, JSON sometimes breaks. 7B bug-catch benchmarks sit around ~45%. Treat it as a weak bonus on top of the static rules. |
| 14B | `qwen3:14b`, `phi-4:14b`, `deepseek-r1:14b` | ✅ **Usable minimum.** Reliable JSON, catches most planted issues (~75%). |
| 32B | `qwen2.5-coder:32b`, `qwen3-coder:32b` | ✅ **Recommended sweet spot.** Strong code-security reasoning (~85–88%), GPT-4o-class on coding, fits a 24&nbsp;GB GPU. |
| 70B+ / large MoE | `llama3.3:70b`, `qwen3-coder` (MoE), `gpt-oss:120b` | ✅ **Best local.** Approaches cloud quality; 70B-class is strongest for security analysis specifically. |

Approximate VRAM at `Q4_K_M`, including KV-cache headroom: **8B ≈ 6&nbsp;GB · 14B ≈ 10&nbsp;GB · 32B ≈ 20–22&nbsp;GB · 70B ≈ 43&nbsp;GB.** A GPU is strongly recommended from 14B up.

Two settings people get wrong:

1. **Context window.** Ollama defaults to `num_ctx 2048`, which silently truncates the package out of the prompt, so the model "scans" almost nothing. Set `num_ctx` to at least 8192 (16384 recommended). Bake it into a model so the OpenAI-compatible endpoint always uses it:

   ```bash
   printf 'FROM qwen2.5-coder:32b\nPARAMETER num_ctx 16384\n' > Modelfile
   ollama create aurscan-qwen -f Modelfile
   ```
   ```fish
   set -Ux AURSCAN_BACKEND openai
   set -Ux AURSCAN_OPENAI_URL http://127.0.0.1:11434/v1/chat/completions
   set -Ux AURSCAN_OPENAI_MODEL aurscan-qwen
   ```

2. **Timeout on slow hardware.** CPU-only inference runs at a few tokens per second, so a scan can take minutes. Raise the budget with `set -Ux AURSCAN_TIMEOUT 900`. If that is still painful, drop to a 7–14B model or run `--rules-only`.

A weak model never leaves you unprotected: the static rules always run, and any model error, timeout, or unparseable output fails closed to `SUSPICIOUS`. A package larger than your context window will also exceed most local models, and the static rules still cover it.
</details>

<details>
<summary>Getting an Anthropic API key (option 2)</summary>

Create one at **console.anthropic.com → Settings → API keys**, add billing, then:

```fish
set -Ux ANTHROPIC_API_KEY sk-ant-...
```

A typical scan is a few thousand input tokens: well under a cent on the API, and free against a subscription.
</details>

## Usage

```bash
syay <anything>             # normal yay usage; the scanner gates AUR builds
aurscan <pkgname> [...]     # standalone scan (fetches the AUR snapshot in memory)
aurscan ./builddir          # scan a local build directory
aurscan --update-check      # audit pending AUR updates without installing anything
aurscan --gen-file          # write pending AUR updates to ./aurscan.paclist
aurscan --scan-file         # scan packages listed in ./aurscan.paclist
```

**Offline admin workflow.** For machines without an LLM backend, install aurscan and run `aurscan --gen-file`. That writes `./aurscan.paclist`, a structured list of pending AUR updates from `yay -Qua`. Copy that single file to your scanner machine and run `aurscan --scan-file`, which validates the file is aurscan-generated and scans the listed packages through the same recursive scanner as `--update-check`.

When a package is flagged:

- **Abort** is the default. Pressing <kbd>Enter</kbd> is always safe.
- **Report** drafts `/tmp/aurscan-report-<pkg>.txt` and offers to open your mail client to [`aurscan@manticore-projects.com`](mailto:aurscan@manticore-projects.com), where reports are aggregated and triaged before any upstream disclosure. It also reminds you to file an AUR deletion request, and **never sends anything automatically**.
- **Continue** requires typing `INSTALL`, so nothing slips through by reflex.

Buffered keystrokes are flushed right before the prompt, so mashing <kbd>Enter</kbd> through earlier yay/paru prompts can never auto-answer the decision.

**Exit codes:** `0` clean/approved · `1` suspicious-abort · `2` malicious-abort · `3` operational error.

### Script integration

`--score` scans a single target and maps the result to an exit code: the **0–100 trust score** on success (higher is safer; MALICIOUS 0–33, SUSPICIOUS 34–66, OK 67–100), or `255` if the scan could not complete. The score also prints to stdout while the human-readable verdict goes to stderr, so it is clean to capture.

```bash
aurscan --score ./PKGBUILD        # exit code = trust score
aurscan --score ./builddir        # a directory works too
cat PKGBUILD | aurscan --score -  # from stdin

score=$(aurscan --score - < PKGBUILD)   # capture just the number
[ "$score" -ge 67 ] || echo "risky (score $score)"
```

Note that exit `0` means trust score 0 (most dangerous), so test the numeric value rather than relying on `&&`/`||`.

### Debugging the model

If a scan returns "malformed JSON", or you just want to see what went over the wire, add `--debug` anywhere on the command line. It traces, to stderr, the selected backend, the full request payload, the raw response, and the reason any parse failed.

```bash
aurscan --debug rocketchat-desktop
aurscan --debug --score ./PKGBUILD
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AURSCAN_BACKEND` | auto | `claude` · `codex` · `api` · `openai` · `/path/to/cmd` |
| `AURSCAN_MODEL` | `claude-sonnet-4-6` | model id for the API backend |
| `AURSCAN_CODEX_MODEL` | Codex default | model id passed to `codex exec` |
| `AURSCAN_MAX_PKGS` | `25` | recursion cap for AUR dependency scanning |
| `AURSCAN_PRICE_IN` / `AURSCAN_PRICE_OUT` | built-in | USD per million tokens |
| `AURSCAN_OPENAI_URL` / `_FALLBACK` | — | OpenAI-compatible endpoint(s) for a local model |
| `AURSCAN_OPENAI_MODEL` | omitted | when unset, no `model` field is sent, so a routing proxy (LiteLLM, etc.) can pick the model; set it to pin a specific model on servers that require one |
| `AURSCAN_OPENAI_API_KEY` | `OPENAI_API_KEY` | bearer token for the endpoint (e.g. LiteLLM); omit for open servers |
| `AURSCAN_OPENAI_TEMPERATURE` | `0` | sampling temperature; set `1.0` for reasoning models like Gemma |
| `AURSCAN_OPENAI_MAX_TOKENS` | `2000` | output-token budget; raise for reasoning models (empty reply with `finish_reason=length`) |
| `AURSCAN_TEMPERATURE` | `0` | backend-agnostic sampling temperature (applies to the `api` backend too); `0` = reproducible auditing |
| `AURSCAN_TIMEOUT` | `180` | per-request budget in **seconds**; raise it for slow CPU-only models |
| `AURSCAN_INSTRUCTIONS` | — | path to extra auditor instructions (appended) |
| `AURSCAN_RULES_ONLY` | — | `1` = static rules only, never call a model |
| `AURSCAN_NO_CACHE` | — | `1` = disable the verdict cache (no read, no write) |
| `AURSCAN_CACHE_DIR` | `$XDG_CACHE_HOME/aurscan/verdicts` | verdict-cache location |
| `AURSCAN_CACHE_TTL` | `30` | verdict-cache lifetime in **days**; `0` = never expire |
| `NO_COLOR` | — | disable coloured output |

## Cost and tokens

Every scan prints a per-package usage line and a session total.

```
↳ tokens: 12,431 in / 214 out · $0.0413
scanner usage: 1 call(s) · tokens: 12,431 in / 214 out · $0.0413
```

| Backend | Tokens | Cost |
|---|---|---|
| Claude Code CLI | exact | exact (`total_cost_usd`) |
| Codex CLI | estimated (`~`) | estimated (`~$`) when the model is priced, else `cost n/a` |
| API key | exact | computed from price table |
| OpenAI-compatible | exact when the server reports usage, else estimated (`~`) | computed from price table when the model is priced (routed cloud models), else `cost n/a` |
| Custom command | estimated (`~`) | `cost n/a` (or set the price override) |

The price table covers `claude-*`, `gpt-*` and `o*` model prefixes. A cost derived from *estimated* token counts carries the same `~` marker as the counts. The Codex CLI does not expose token or cost data, so its cost is an estimated API-equivalent — shown only when the model is known (`AURSCAN_CODEX_MODEL`); subscription usage has no marginal cost, so treat it as an upper bound.

Override the price table (USD per million tokens) for any backend — including local models where you want to account amortised hardware cost — so you never depend on a stale built-in: `AURSCAN_PRICE_IN` / `AURSCAN_PRICE_OUT`.

## Customising detection

**Add your own auditor guidance.** Drop a Markdown file at `~/.config/aurscan/instructions.md`, or point `AURSCAN_INSTRUCTIONS` at any path. Its contents are *appended* to the built-in instructions: it can sharpen the auditor but never weaken the core rules or the prompt-injection hardening. A ready-to-copy example lives at [`packaging/instructions.example.md`](packaging/instructions.example.md). It tells the auditor to weight low-popularity packages, recent maintainer changes, and changes with no obvious technical reason far more heavily.

**Static rules run first.** A deterministic catalog, adapted from [KiefStudioMA/ks-aur-scanner](https://github.com/KiefStudioMA/ks-aur-scanner) (GPL-3.0, codes kept compatible), matches known patterns: `curl|bash`, reverse shells, credential and browser-profile access, systemd persistence, the `npm install atomic-lockfile` / `bun install js-digest` campaign signatures, eBPF-rootkit artifacts, and more. It runs offline and for free, and every hit is fed to the model as prior context. Run the rules alone with no model call:

```bash
aurscan --rules-only <pkgname|./dir>     # or set AURSCAN_RULES_ONLY=1
```

**Quote-aware — obfuscation does not slip past.** The command, flag and path rules do not match raw text. The `PKGBUILD` and `.install` scripts are parsed with a real shell parser ([`mvdan.cc/sh`](https://github.com/mvdan/sh), pure-Go, vendored, **never executed**) and the rules run against the *deobfuscated* command view. So split-token tricks like `s"ud"o`, `cu""rl … | sh`, `su$'\x64'o` and `${IFS:0:0}sudo` are caught as the commands they actually run, while a `sudo` printed inside an `echo` instruction is correctly ignored instead of false-flagging. The splicing itself is also reported as **`OBF-004` (critical)** — a PKGBUILD has no honest reason to disguise a command name, so any attempt is treated as a strong signal in its own right, even when the disguised command is otherwise harmless.

**Build-cache hygiene — your `$HOME` should stay yours.** A `go build`/`go install` without a confined `GOPATH`/`GOMODCACHE` writes the module cache to `~/go/pkg/mod` (read-only files, unless `-modcacherw`); a `cargo build`/`cargo fetch` without `CARGO_HOME` writes registry and git caches to `~/.cargo`. Not malicious — failure by omission — but a scanner that promises "nothing ran yet" should tell you the build will write outside `$srcdir`. Reported as **`BLD-001`/`BLD-002` (info)**. Suppressed when the PKGBUILD exports or inline-prefixes the variable (an export in `prepare()` covers `build()` — same makepkg process) or, for Go, builds vendored with `-mod=vendor`. These checks use the same command-position-aware view: an echo'd `go build` does not fire.

## Reproducibility

An LLM is never perfectly deterministic, so the *same* PKGBUILD can otherwise earn different verdicts on repeat runs — a real trust problem when a borderline package sometimes blocks and sometimes passes. aurscan reduces this three ways:

- **Deterministic verdict from a fixed checklist.** The model no longer emits a verdict, a confidence number or a severity. It answers a fixed set of concrete yes/no checks about observable behaviours (`pipe_to_shell`, `credential_access`, `writes_outside_build`, `unverifiable_provenance`, …) and cites the evidence; aurscan then derives the verdict in code — **any critical check → MALICIOUS, else any warning → SUSPICIOUS, else OK** — assigns each finding's severity from a fixed table, and computes a deterministic confidence and summary. Two runs that answer the same booleans produce a byte-identical result, so the OK/SUSPICIOUS boundary is code we control rather than a sampled label. A borderline package (say, one that writes a toolchain into `$HOME`) lands on the *same* verdict every time instead of flip-flopping. Models that ignore the checklist and emit the old `verdict`/`findings` shape still work, just without this guarantee.
- **Temperature 0 by default** on the `api` and `openai` backends (greedy decoding), which collapses most of the remaining sampling variance in *how* the checks are answered. Raise it per backend (`temperature=` in `llmN.conf`) or via `AURSCAN_TEMPERATURE` / `AURSCAN_OPENAI_TEMPERATURE` for reasoning models like Gemma that need `1.0`. The **Codex CLI cannot** be pinned this way — `codex exec` exposes no temperature or seed and drives a reasoning model — so for reproducible verdicts prefer the `api` backend or a local `openai` model with a fixed seed.
- **A verdict cache** keyed on a hash of the package files, the full auditor instructions and the resolved model id. An identical re-scan replays the stored verdict without calling the model, so a re-run *cannot* flip. Any change to the package, the prompt, the instructions or the model misses the cache and re-scans; fallback (degraded) and failed scans are never cached. The recorded model id is shown so a cross-backend difference is explainable rather than mysterious. Force a fresh opinion with `--refresh` (re-scans and updates the entry) or disable the cache entirely with `--no-cache` / `AURSCAN_NO_CACHE=1`.

## Safety model

- **Fail-closed.** A backend error, timeout, or unparseable output is first retried against the next backend in the chain; once every configured backend is exhausted — or on a fetch failure — the result becomes **SUSPICIOUS** and blocks the build. The scanner can fail, but it never fails *open*.
- **Prompt-injection hardening.** Package files are sent as untrusted data, kept separate from the trusted instructions. The prompt treats embedded "this package is safe / ignore previous instructions" text as evidence of malice, and only the JSON contract is trusted when parsing. Both are covered by tests.
- **No execution, no disk writes.** AUR snapshots are parsed in memory. Nothing from the suspect package is written to disk or run.
- **Bounded context.** Binaries and files over 64 KB are skipped, and total context is capped at 240 KB.

## Limitations

- It is a heuristic, not a verifier. Build in a clean chroot when you can.
- `npm`, `bun`, `pip`, `go`, and `curl` are sometimes legitimate (Electron apps building from source, for instance), so expect occasional **false positives**. That is the safer direction to err.
- The wrapper enables yay's edit prompt for every AUR build. That is the price of seeing every script. Pass your own `--editor` and aurscan scans first, then chains to it.
- **Shell deobfuscation is bash-grade.** `PKGBUILD` and `.install` are bash, which is exactly what the parser handles (it also understands POSIX `sh` and `mksh`). Two things stay out of its reach by nature: obfuscation hidden *inside another language* — a reverse shell split across a `python -c '…'` or `perl -e '…'` string — is not un-spliced by a shell parser (the embedded interpreter call is still seen; the model is the backstop for in-language tricks); and values that only exist at build time — `$(…)`, `${var}` taken from the environment, deeply nested `eval` — cannot be resolved by any static tool. A file the parser cannot read at all falls back to raw-text matching, so detection is never lost.

## Project layout

```
cmd/aurscan/          entrypoint + argument dispatch
internal/scan/        prompt, backend calls, verdict parsing, usage/pricing
internal/aur/         AUR RPC, in-memory snapshot fetch, recursive dep scan
internal/rules/       deterministic static-rule catalog (offline pre-filter)
internal/pipeline/    orchestrates rules -> reputation -> LLM, rules-only fallback
internal/config/      user config + extra-instructions loader
internal/ui/          colours, verdict printing, interactive gate, report
internal/yay/         syay wrapper + edit-hook gate
packaging/PKGBUILD    publish aurscan to the AUR
testdata/             sanitised firefox-patch-bin fixture (structure only)
```

## Contributing

Issues and PRs are welcome. `make test` runs `go vet` and the unit tests; CI runs them on every push, and on a `v*` tag it attaches UPX-packed release binaries.

## Acknowledgements

- Original AUR packaging by [@HaleTom](https://github.com/HaleTom) ([#21](https://github.com/manticore-projects/aurscan/issues/21)).
- Static-rule catalog adapted from [KiefStudioMA/ks-aur-scanner](https://github.com/KiefStudioMA/ks-aur-scanner) (GPL-3.0).
- Local-LLM backend generalised from [@alexzk1's connector](https://github.com/manticore-projects/aurscan/issues/1).

## License

[Apache-2.0](LICENSE) © Manticore Projects Co., Ltd.
