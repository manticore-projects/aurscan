# Contributing to aurscan

Issues and pull requests are welcome. This file is the answer to "what counts as
an acceptable contribution" — read the section for the kind of change you are
making, because the bar is deliberately different for each.

Security vulnerabilities do **not** go in a public issue. See
[SECURITY.md](SECURITY.md), which also explains what counts as a vulnerability
here (a missed package is a detection gap and belongs in a normal issue; a
prompt injection that *clears* a verdict does not).

## Before you open a pull request

```bash
make test        # go vet ./... && go test ./...
gofmt -l .       # must print nothing
```

CI runs the same, plus a `vendor` job. Dependencies are vendored, so if you
touch `go.mod` you must run `go mod tidy && go mod vendor` and commit the
result — otherwise the vendor job fails by design.

Commit messages use [Conventional Commits](https://www.conventionalcommits.org):
a single subject line, no body unless the change genuinely needs one.

```
fix(rules): stop OBF-004 firing on '"'"' quote escaping
feat(scan): report masqueraded file types
docs(readme): correct the context cap
```

## The project is maintained by one person

There is no review queue and no second pair of eyes. That is worth knowing
before you invest in a large change: open an issue describing the approach
first, and get a reaction, rather than arriving with a finished branch.

It also means changes land on `main` without a reviewer, which is why the gates
below are mechanical rather than social. The corpus run, not a reviewer, is what
stops a bad rule reaching users.

## Changing detection rules

This is where most of the care goes, because a rule that fires wrongly is worse
than a rule that does not exist. A scanner that blocks packages people know are
fine teaches them to type INSTALL without reading, and that costs more than the
rule ever bought.

**Every new or changed rule needs a test in both directions.** One that proves
it fires on the thing it is for, and one that proves it does *not* fire on the
benign construct closest to it. A rule with only a positive test is not ready.

**Run the corpora before proposing a rule for the non-overridable set.** The
`fatalCodes` map in `internal/rules/rules.go` lists codes that block a build and
that the model cannot clear. Nothing joins it on the strength of unit tests.

```bash
go test ./internal/rules/ -run 'Corpus|FalsePos'
```

Sixteen rule corrections in this project's history came from running the rules
over packages people actually install. Not one came from a unit test. The
history is in [CHANGELOG.md](CHANGELOG.md) and it is worth skimming before you
write a rule: `PRIV-001` cannot mean anything inside a scriptlet that already
runs as root; shipping a `.service` file and enabling it is how packaging works,
not persistence; `'"'"'` is the only way to put a single quote inside a
single-quoted string and so cannot be treated as obfuscation.

**Keep the sibling invariant.** Several critical checks have a warning-tier twin
for the case that has a legitimate form — `pipe_to_shell` /
`unpinned_upstream_installer`, `exfiltration` / `telemetry`,
`privilege_persistence` / `sudoers_for_own_service`,
`unrelated_pkg_manager_exec` / `pkg_manager_build_deps`. If your check has a
benign form, give it a twin rather than widening the critical one. A scan should
be able to say *dangerous, not malware* and mean it.

**Severity is policy, not taste.** Changing an entry in `checkCatalog`
(`internal/scan/checks.go`) changes what blocks a build. Bump `cacheVersion` in
`internal/scan/cache.go` in the same commit, or cached verdicts replay under the
old policy and your change appears not to work.

## Changing the auditor prompt

`internal/scan/prompt.go` has no regression harness. There is no way to prove a
reworded instruction did not reintroduce a false positive, so the standing rule
is: do not compress the discriminating text. Every `NOT this:` clause and every
sibling distinction in that file was written because a terser version produced a
documented false positive.

Adding a check id to the prompt means adding it to `checkCatalog` and
`checkLabel` too, or the model emits an id nothing knows about.

Prompt instructions are advice. If a property must hold, enforce it in Go —
that is why `resolveHedges`, `confineIncompleteScan` and `collapsePerPackage`
exist alongside prompt text saying the same thing.

## Fuzzing

The rule engine consumes attacker-chosen bytes by definition. `go test ./...`
runs the seed corpora; run the fuzzers properly when you touch the shell parser
or the file-identity rules:

```bash
go test ./internal/rules -run FuzzScan -fuzz 'FuzzScan$' -fuzztime 60s
```

A panic here is not a SUSPICIOUS verdict — aurscan is invoked from a shell
wrapper, so a crash is an exit code. Fail-closed does not save you.

## Writing user-visible text

README, CHANGELOG, `--help`, finding notes and mailing-list posts get a
different standard from code comments. aurscan makes claims about other people's
packages, so its own prose has to survive being quoted by someone hostile:

- State the limitation before a critic does. Say what the scan did not read.
- Give numbers, not adjectives. "7 of 19,934" beats "very few".
- Never overclaim coverage. A check that catches a *delivery trigger* is not a
  check that catches a *campaign*.
- No marketing tone.

## What tends to get rejected

- A rule with no benign-case test.
- A fatal rule with no corpus run.
- A catalog severity change with no `cacheVersion` bump.
- Prompt edits that shorten a discriminating clause.
- Reformatting or renaming mixed into a behavioural change. Send those
  separately — they make the real diff unreviewable, and there is only one
  reviewer.
