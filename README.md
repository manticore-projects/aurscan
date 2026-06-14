<div align="center">

# 🛡️ aurscan

**Catch malicious AUR packages _before_ they build — with a Claude model reading the PKGBUILD for you.**

[![CI](https://github.com/manticore-projects/aurscan/actions/workflows/ci.yml/badge.svg)](https://github.com/manticore-projects/aurscan/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/manticore-projects/aurscan?sort=semver)](https://github.com/manticore-projects/aurscan/releases)
[![Go](https://img.shields.io/badge/Go-1.22-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Go Report Card](https://goreportcard.com/badge/github.com/manticore-projects/aurscan)](https://goreportcard.com/report/github.com/manticore-projects/aurscan)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Arch%20Linux-1793D1?logo=archlinux&logoColor=white)](https://archlinux.org)

</div>

---

Reading a PKGBUILD yourself only catches attacks you already recognise. **aurscan** reads a package's `PKGBUILD`, `.install` scriptlets, `.SRCINFO` and helper scripts **before `makepkg` executes a single line**, and blocks the build if the script looks malicious.

It runs in two stages: **fast deterministic static rules** (offline, zero-cost) catch the known campaign signatures, then a **Claude or local model** — informed by those rule hits and the package's AUR reputation — makes the judgement call on the subtle cases. With no model configured at all, the static rules alone still produce a fail-closed verdict, so you're protected even fully offline.

> [!WARNING]
> An LLM scanner is a strong **extra layer, not a guarantee**. Keep building in a clean chroot, prefer official-repo packages, and stay wary of freshly-adopted orphaned packages. See [Limitations](#%EF%B8%8F-limitations).

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
  [A]bort (default) / [r]eport to mailing list & abort / [c]ontinue anyway:
```

## Contents

- [Why](#-why)
- [How it hooks into yay](#-how-it-hooks-into-yay)
- [Install](#-install)
- [Authentication](#-authentication)
- [Usage](#-usage)
- [Token & cost reporting](#-token--cost-reporting)
- [Configuration](#%EF%B8%8F-configuration)
- [How it stays safe](#-how-it-stays-safe)
- [Project layout](#%EF%B8%8F-project-layout)
- [Limitations](#%EF%B8%8F-limitations)
- [Contributing](#-contributing)

## 🎯 Why

In July 2025 the AUR packages `firefox-patch-bin`, `librewolf-fix-bin` and `zen-browser-patched-bin` were uploaded with a `source=()` entry disguised as `patches` that actually pulled a personal GitHub repo and ran **CHAOS RAT** at build time. They looked like ordinary browser fixes; a quick glance at the PKGBUILD didn't obviously give them away. They were live for ~46 hours.

aurscan is built to flag exactly that class of thing — the unfamiliar trick, not just the one you happen to know.

In June 2026 the **Atomic Arch** campaign drove the point home at scale: attackers adopted **1,500+ orphaned** AUR packages and — in some cases using git commit *forgery* to impersonate a trusted maintainer — added a post-install step running `npm install atomic-lockfile` (then `bun install js-digest` in a second wave), pulling a Rust credential stealer and, when built as root, an **eBPF rootkit**. The package name and history were unchanged; only the build instructions, and who wrote them, had quietly changed. aurscan's prompt and static rules encode these exact signatures.

## 🔌 How it hooks into yay

> [!NOTE]
> A pacman hook is the **wrong** layer. PKGBUILD code runs as your user during `makepkg`, *before* pacman ever sees a package — so a `PreTransaction` hook fires only *after* any build-time payload has already executed. (Hook-based AUR "trust" tools score the *maintainer* at install time; they can't read what the build script actually *does*.)

aurscan intercepts at the only safe point — **after download, before build** — using yay's own editor step. The `syay` wrapper transparently points yay's editor at `aurscan-edit` and forces the edit prompt on, so the scanner runs on **every AUR PKGBUILD yay is about to build**:

| You type | What gets scanned |
|---|---|
| `syay -S pkg` | the named package |
| `syay pkg` | the package you pick from yay's **interactive** search menu |
| `syay -Syu` | every AUR upgrade |
| _(any of the above)_ | …and their AUR **dependencies**, which yay also presents before building |

On a **clean** verdict it chains to your real `$VISUAL`/`$EDITOR`, so your manual review still happens. On a **non-OK** verdict it exits non-zero and yay aborts the build.

## 📦 Install

```bash
git clone https://github.com/manticore-projects/aurscan
cd aurscan
./install.sh                 # build (needs Go) + install into /usr/local/bin
```

Then make it transparent — **fish**:

```fish
alias yay=syay
funcsave yay
```

<details>
<summary>bash / zsh</summary>

```bash
echo "alias yay=syay" >> ~/.bashrc   # or ~/.zshrc
```
</details>

This installs three names that are all the **same static binary**: `aurscan` (CLI), `syay` (the yay wrapper), and `aurscan-edit` (the editor-gate yay invokes).

| Task | Command |
|---|---|
| Update | `git pull && ./install.sh` |
| Uninstall | `./install.sh --uninstall` |
| Rootless install | `SUDO= PREFIX=~/.local ./install.sh` |
| Build only | `make build` |
| Run tests | `make test` |
| UPX-pack the binary | `make compress` |
| Cross-build release artifacts | `make release` |

> UPX packing (5.4 MB → 1.8 MB) is applied to the **release artifacts** only — it's deliberately kept out of the AUR `PKGBUILD`, since Arch users build from source.

## 🔑 Authentication

Auto-detected, in this order — **option 1 needs no API key at all**:

1. **Claude Code CLI** (`claude`) in `PATH` and logged in → uses your existing Claude subscription. Reports **exact cost** per scan.
2. **`ANTHROPIC_API_KEY`** → direct API (`claude-sonnet-4-6` by default). Reports exact tokens; cost computed from a built-in price table.
3. **Local / self-hosted model** via `AURSCAN_OPENAI_URL` → any OpenAI-compatible `/chat/completions` endpoint (**llama.cpp, Ollama, vLLM, LocalAI**). Fully private; set `AURSCAN_OPENAI_URL_FALLBACK` for automatic failover (e.g. GPU host → local CPU). The model is swappable via `AURSCAN_OPENAI_MODEL`.
4. **`AURSCAN_BACKEND=/path/to/cmd`** → any executable that reads the prompt on stdin and prints the reply on stdout.
5. **No backend at all** → static rules still run and block on critical matches.

<details>
<summary>Local model example (llama.cpp / Ollama)</summary>

```fish
# llama.cpp server, with a fallback to a second host
set -Ux AURSCAN_BACKEND openai
set -Ux AURSCAN_OPENAI_URL http://192.168.0.110:18080/v1/chat/completions
set -Ux AURSCAN_OPENAI_URL_FALLBACK http://127.0.0.1:18083/v1/chat/completions
set -Ux AURSCAN_OPENAI_MODEL qwen2.5-coder-32b
```

On a slow, CPU-only host (e.g. a handheld), the default 180&nbsp;s budget can expire before the model finishes — you'll see `context deadline exceeded`. Raise it and make sure the model's context window is large enough for the prompt (a package is typically several thousand tokens; Ollama's 2048 default will silently truncate it):

```fish
set -Ux AURSCAN_TIMEOUT 900        # 15 minutes
# and on the Ollama side, give the model real context, e.g.:
#   ollama run <model> with a Modelfile setting `PARAMETER num_ctx 8192`
```

Thanks to [@alexzk1](https://github.com/manticore-projects/aurscan/issues/1) for the original connector that this backend generalises.
</details>

<details>
<summary>Choosing a local model — what actually works (and what's too small)</summary>

aurscan asks more of a model than autocomplete or chat does. For each package it must (1) reason about possibly-obfuscated shell across a multi-thousand-token prompt, (2) return **strictly valid JSON** matching the verdict contract, and (3) **not be talked out of a verdict** by injected "this package is safe / ignore previous instructions" text in the untrusted files. Small models fail all three: they rubber-stamp, emit malformed JSON (→ fail-closed `SUSPICIOUS` noise), or fall for the injection. **Parameter count matters more here than it does for coding assistants.**

Rough guidance (names are current as of mid-2026 — check Ollama's library for equivalents, the field moves fast):

| Size | Examples | Verdict for aurscan |
|---|---|---|
| ≤ 3B | `qwen2.5-coder:3b`, `llama3.2:3b`, `phi-*-mini` | ❌ **Don't.** Near-random verdicts, unreliable JSON. Use `--rules-only` instead. |
| 7–8B | `codellama:7b` *(the model in [#8](https://github.com/manticore-projects/aurscan/issues/8))*, `qwen2.5-coder:7b`, `llama3.1:8b` | ⚠️ **Marginal.** Catches only blatant cases; misses subtle supply-chain tricks; JSON sometimes breaks. Independent code-review benchmarks put 7B bug-catch around ~45% — treat it as a weak bonus on top of the static rules, not a real auditor. |
| 14B | `qwen3:14b`, `phi-4:14b`, `deepseek-r1:14b` | ✅ **Usable minimum.** Reliable JSON, catches most planted issues (~75%). |
| 32B | `qwen2.5-coder:32b`, `qwen3-coder:32b` | ✅ **Recommended sweet spot.** Strong code-security reasoning (~85–88% in code-review tests), GPT-4o-class on coding, fits a 24&nbsp;GB GPU. |
| 70B+ / large MoE | `llama3.3:70b`, `qwen3-coder` (MoE), `gpt-oss:120b` | ✅ **Best local.** Approaches cloud quality; 70B-class is the strongest for *security* analysis specifically. |

Approximate VRAM at `Q4_K_M` (incl. KV-cache headroom): **8B ≈ 6&nbsp;GB · 14B ≈ 10&nbsp;GB · 32B ≈ 20–22&nbsp;GB · 70B ≈ 43&nbsp;GB.** A GPU is strongly recommended for 14B and up.

**The two settings people get wrong:**

1. **Context window.** Ollama defaults to `num_ctx 2048`, which silently truncates the package *out of the prompt* — the model then "scans" almost nothing. Set **`num_ctx` ≥ 8192 (16384 recommended)**. Bake it into a model so the OpenAI-compatible endpoint always uses it:

   ```bash
   printf 'FROM qwen2.5-coder:32b\nPARAMETER num_ctx 16384\n' > Modelfile
   ollama create aurscan-qwen -f Modelfile
   ```
   ```fish
   set -Ux AURSCAN_BACKEND openai
   set -Ux AURSCAN_OPENAI_URL http://127.0.0.1:11434/v1/chat/completions
   set -Ux AURSCAN_OPENAI_MODEL aurscan-qwen
   ```

2. **Timeout on slow hardware.** CPU-only inference (handhelds, NUCs) runs at a few tokens/sec — a scan can take minutes. Raise the budget: `set -Ux AURSCAN_TIMEOUT 900`. If that's still painful, drop to a 7–14B model or just run `--rules-only`.

You are never left unprotected by a weak model: the deterministic static rules always run, and any model error, timeout, or unparseable output **fails closed to `SUSPICIOUS`**. A package larger than your context window will also exceed most local models — the static rules still cover it.
</details>

<details>
<summary>Getting an Anthropic API key (option 2)</summary>

Create one at **console.anthropic.com → Settings → API keys**, add billing, then:

```fish
set -Ux ANTHROPIC_API_KEY sk-ant-...
```

A typical scan is a few thousand input tokens — well under a cent on the API, free against a subscription.
</details>

## 🚀 Usage

```bash
syay <anything>             # normal yay usage; the scanner gates AUR builds
aurscan <pkgname> [...]     # standalone scan (fetches the AUR snapshot in memory)
aurscan ./builddir          # scan a local build directory
aurscan --update-check      # audit pending AUR updates without installing anything
aurscan --gen-file          # write pending AUR updates to ./aurscan.paclist
aurscan --scan-file         # scan packages listed in ./aurscan.paclist
```

**Offline admin workflow.** If you maintain machines that do not have an LLM
backend configured, install aurscan there and run:

```bash
aurscan --gen-file
```

That overwrites `./aurscan.paclist` with a structured list of pending AUR
updates from `yay -Qua`. Copy that single file to your scanner machine and run:

```bash
aurscan --scan-file
```

The scan command requires `aurscan.paclist` in the current directory, validates
that it is an aurscan-generated file, and scans the listed packages through the
same recursive AUR scanner used by `--update-check`.

When a package is flagged:

- **Abort** — the default; pressing <kbd>Enter</kbd> is always safe.
- **Report** — drafts `/tmp/aurscan-report-<pkg>.txt`, offers to open your mail client to [`aur-general@lists.archlinux.org`](https://lists.archlinux.org/mailman3/lists/aur-general.lists.archlinux.org/) (where the CHAOS RAT cleanup was coordinated), and reminds you to file an AUR deletion request. **Never sends automatically.**
- **Continue** — requires typing `INSTALL`, so nothing slips through by reflex.

**Exit codes:** `0` clean/approved · `1` suspicious-abort · `2` malicious-abort · `3` operational error.

## 🧩 Customising detection

**Add your own auditor guidance.** Drop a Markdown file at `~/.config/aurscan/instructions.md` (or point `AURSCAN_INSTRUCTIONS` at any path). Its contents are *appended* to the built-in instructions — it can sharpen the auditor but never weakens the core rules or the prompt-injection hardening. A ready-to-copy example lives at [`packaging/instructions.example.md`](packaging/instructions.example.md); it tells the auditor to weight low-popularity packages, recent maintainer changes, and changes with no obvious technical reason far more heavily.

**Static rules run first.** A deterministic catalog (adapted from [KiefStudioMA/ks-aur-scanner](https://github.com/KiefStudioMA/ks-aur-scanner), GPL-3.0, codes kept compatible) matches known patterns — `curl|bash`, reverse shells, credential/browser-profile access, systemd persistence, the `npm install atomic-lockfile` / `bun install js-digest` campaign signatures, eBPF-rootkit artifacts, and more — offline and for free. Every hit is fed to the model as prior context. Run them alone with no model call:

```bash
aurscan --rules-only <pkgname|./dir>     # or set AURSCAN_RULES_ONLY=1
```

## 💸 Token & cost reporting

Every scan prints a per-package usage line and a session total:

```
↳ tokens: 12,431 in / 214 out · $0.0413
scanner usage: 1 call(s) · tokens: 12,431 in / 214 out · $0.0413
```

| Backend | Tokens | Cost |
|---|---|---|
| Claude Code CLI | exact | exact (`total_cost_usd`) |
| API key | exact | computed from price table |
| Custom command | estimated (`~`) | `cost n/a` |

Override the API price table (USD per million tokens) so you never depend on a stale built-in: `AURSCAN_PRICE_IN` / `AURSCAN_PRICE_OUT`.

## ⚙️ Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AURSCAN_BACKEND` | auto | `claude` · `api` · `openai` · `/path/to/cmd` |
| `AURSCAN_MODEL` | `claude-sonnet-4-6` | model id for the API backend |
| `AURSCAN_MAX_PKGS` | `25` | recursion cap for AUR dependency scanning |
| `AURSCAN_PRICE_IN` / `AURSCAN_PRICE_OUT` | built-in | USD per million tokens |
| `AURSCAN_OPENAI_URL` / `_FALLBACK` | — | OpenAI-compatible endpoint(s) for a local model |
| `AURSCAN_OPENAI_MODEL` | `default-model` | model name sent to the local endpoint |
| `AURSCAN_TIMEOUT` | `180` | per-request budget in **seconds**; raise it for slow CPU-only local models |
| `AURSCAN_INSTRUCTIONS` | — | path to extra auditor instructions (appended) |
| `AURSCAN_RULES_ONLY` | — | `1` = static rules only, never call a model |
| `NO_COLOR` | — | disable coloured output |

## 🔒 How it stays safe

- **Fail-closed.** Backend error, timeout, fetch failure, or unparseable output ⇒ **SUSPICIOUS**, build blocked. The scanner can fail, but never fails *open*.
- **Prompt-injection hardening.** Package files are sent as **untrusted data**, separated from the trusted instructions; the prompt treats embedded "this package is safe / ignore previous instructions" text as evidence of *malice*. Parsing only trusts the JSON contract — covered by tests.
- **No execution, no disk writes.** AUR snapshots are parsed **in memory**; nothing from the suspect package is written to disk or run.
- **Bounded context.** Binaries and files > 64 KB skipped; total context capped at 240 KB.

## 🗂️ Project layout

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

## ⚠️ Limitations

- Heuristic, not a verifier — build in a clean chroot when you can.
- `npm` / `bun` / `pip` / `go` / `curl` are sometimes legitimate (e.g. Electron apps building from source); expect occasional **false positives** — the safer direction to err.
- The wrapper enables yay's edit prompt for every AUR build; that's the price of seeing every script. Pass your own `--editor` and aurscan scans first, then chains to it.

## 🤝 Contributing

Issues and PRs welcome. `make test` runs `go vet` and the unit tests; CI runs them on every push and, on a `v*` tag, attaches UPX-packed release binaries.

## 🙏 Acknowledgements

- Static-rule catalog adapted from [KiefStudioMA/ks-aur-scanner](https://github.com/KiefStudioMA/ks-aur-scanner) (GPL-3.0).
- Local-LLM backend generalised from [@alexzk1's connector](https://github.com/manticore-projects/aurscan/issues/1).

## 📄 License

[Apache-2.0](LICENSE) © Manticore Projects Co., Ltd.
