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

Reading a PKGBUILD yourself only catches attacks you already recognise. **aurscan** reads a package's `PKGBUILD`, `.install` scriptlets, `.SRCINFO` and helper scripts with a Claude model **before `makepkg` executes a single line**, and blocks the build if the script looks malicious.

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
3. **`AURSCAN_BACKEND=/path/to/cmd`** → any local executable that reads the prompt on stdin and prints the reply on stdout. Fully offline.

<details>
<summary>Getting an API key (option 2)</summary>

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
```

When a package is flagged:

- **Abort** — the default; pressing <kbd>Enter</kbd> is always safe.
- **Report** — drafts `/tmp/aurscan-report-<pkg>.txt`, offers to open your mail client to [`aur-general@lists.archlinux.org`](https://lists.archlinux.org/mailman3/lists/aur-general.lists.archlinux.org/) (where the CHAOS RAT cleanup was coordinated), and reminds you to file an AUR deletion request. **Never sends automatically.**
- **Continue** — requires typing `INSTALL`, so nothing slips through by reflex.

**Exit codes:** `0` clean/approved · `1` suspicious-abort · `2` malicious-abort · `3` operational error.

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
| `AURSCAN_BACKEND` | auto | `claude` · `api` · `/path/to/cmd` |
| `AURSCAN_MODEL` | `claude-sonnet-4-6` | model id for the API backend |
| `AURSCAN_MAX_PKGS` | `25` | recursion cap for AUR dependency scanning |
| `AURSCAN_PRICE_IN` / `AURSCAN_PRICE_OUT` | built-in | USD per million tokens |
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

## 📄 License

[Apache-2.0](LICENSE) © Manticore Projects Co., Ltd.
