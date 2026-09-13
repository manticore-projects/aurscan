# Security Policy

## Supported versions

Only the latest release receives fixes. aurscan is distributed through its own
signed pacman repository, so `pacman -Syu` is the upgrade path; there are no
maintained back-branches.

| Version | Supported |
| ------- | --------- |
| latest release | yes |
| anything older | no |

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/manticore-projects/aurscan/security/advisories/new).
If that is not workable for you, email **security@manticore-projects.com**.

Please do not open a public issue for a vulnerability report.

Include what you have: the package or input that triggers it, the aurscan
version (`aurscan --version`), the backend in use, and what you expected to
happen instead. A reproducer beats a description.

Expect an acknowledgement within 5 working days and an assessment within 15.
aurscan is maintained by a three-person company, so those are honest numbers
rather than an SLA — if a report is urgent and the acknowledgement is late,
email again rather than assuming it was read.

Disclosure is coordinated: we will agree a date with you, and we will credit you
in the advisory and the changelog unless you ask us not to.

## What counts as a vulnerability here

aurscan is a scanner, so the interesting failures are not the usual ones.

**In scope, and treated as vulnerabilities:**

- **Prompt injection that changes a verdict.** Content in a PKGBUILD, scriptlet
  or retrieved file that causes the auditor to clear a package it would
  otherwise flag. Escalation is not a vulnerability; suppression is.
- **Bypassing the non-overridable floor.** Any input that makes a fatal static
  rule fail to block a build.
- **Deobfuscation evasion.** Shell that runs a command the command-view does not
  report — token splicing, quoting or parser tricks the rules do not see
  through. Note the documented limits first: obfuscation *inside another
  language* and values that only exist at build time are known gaps, not bugs.
- **Code execution, file writes or network calls caused by scanning a hostile
  package.** aurscan parses in memory and must never execute or write anything
  from the package under review.
- **Leaking package contents or configuration** to a backend or endpoint the
  user did not configure.
- **Supply-chain integrity of our own releases**: signing, the pacman
  repository, the release workflow.

**Out of scope:**

- A false negative on a novel attack with no evasion involved. aurscan is a
  heuristic and says so; a missed package is a detection gap. Open a normal
  issue — those are welcome and useful.
- A false positive, however annoying. Also a normal issue.
- Vulnerabilities in the LLM backend you configured, or in yay/paru.
- Anything requiring the attacker to already control the machine running the
  scan.

## What aurscan does not protect you from

Stated plainly because a security policy that oversells its tool is worse than
none. aurscan reads the AUR repository's build scripts. It does not open
`source=()` archives or upstream git checkouts, does not execute anything, and
does not verify that a maintainer is who they claim to be. An OK verdict covers
the build scripts it read, not the upstream tarball they download. Build in a
clean chroot.
