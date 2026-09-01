package rules

// DEP-001: a dependency fetch that is pinned to a lockfile.
//
// This rule reports a MITIGATION, not a risk, and it is the only one in the
// catalog that does. The reason is that the question the checklist actually
// needs answered about `npm install` or `cargo build` is not "did a package
// manager run" — it did, on essentially every Node, Electron and Rust package
// in the AUR, and a check that fires on a whole ecosystem blocks builds without
// distinguishing anything. The useful question is whether what it fetches is
// DETERMINED IN ADVANCE.
//
//	npm ci                      -> package-lock.json decides; fails without one
//	cargo build --locked        -> Cargo.lock decides; fails if it would change
//	pnpm/yarn --frozen-lockfile -> same
//	pip install --require-hashes -> every artifact hash-pinned
//	go build                    -> go.mod/go.sum by construction
//
// against
//
//	npm install                 -> resolves semver ranges at build time
//	cargo build                 -> may update the lock
//	pip install -r requirements -> resolves at build time
//
// The difference is the one that mattered in the Atomic Arch campaign: an
// unpinned resolve is a build-time decision made by whoever controls the
// registry, so the bytes that compile are not the bytes anyone reviewed. A
// pinned resolve is still a network fetch outside source=() and still worth
// showing, but it is a materially weaker claim and should not block.
//
// Only the PINNED case is emitted deterministically. Emitting the unpinned case
// as a static hit would fire on the same whole ecosystem this rule exists to
// stop punishing, so "unpinned" stays the model's call via
// pkg_manager_build_deps; DEP-001 exists to let checks.go downgrade that call
// when the evidence contradicts it.
//
// Detection is by FLAG, not by lockfile presence. A lockfile normally lives
// inside the upstream tarball rather than the AUR repository, so testing for
// Cargo.lock in the supplied files would be false almost always. The flags are
// a sound proxy precisely because they fail the build when the lockfile is
// missing or stale — that is what they are for.

import "regexp"

var (
	// A command that fetches third-party dependencies at build time.
	depFetchCmd = regexp.MustCompile(
		`(?:^|\|\s*)(?:[A-Za-z_][A-Za-z0-9_]*=[^\s|]*\s+)*(?:npm|pnpm|yarn|bun|cargo|pip|pip3|go)\b`)
	depFetchRaw = regexp.MustCompile(
		`(?m)(?:^|[;&|({]|\bthen\b|\bdo\b)[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=\S*[ \t]+)*(?:npm|pnpm|yarn|bun|cargo|pip|pip3|go)[ \t]`)

	// Pinning. Any one of these anywhere live in the PKGBUILD is enough:
	// makepkg runs every function in one process, so a flag in prepare()
	// governs the fetch it performs there just as well as one in build().
	//
	//   --locked / --frozen / --offline  cargo
	//   npm|pnpm|yarn|bun ci             npm's pinned installer
	//   --frozen-lockfile / --immutable  pnpm, yarn classic, yarn berry
	//   --require-hashes                 pip
	//   -mod=vendor / -mod=readonly      go, explicit
	//   GOFLAGS=-mod=...                 go, via environment
	depPinned = regexp.MustCompile(
		`--locked\b|--frozen\b|--offline\b|--frozen-lockfile\b|--immutable\b|--require-hashes\b|` +
			`\b(?:npm|pnpm|yarn|bun)[ \t]+ci\b|-mod=(?:vendor|readonly)\b`)

	// Go resolves through go.mod/go.sum by construction: a `go build` verifies
	// every module against a recorded hash without any flag. Treated as pinned
	// on its own, unless GONOSUMCHECK/GONOSUMDB/GOFLAGS=-mod=mod turns that off
	// or GOPRIVATE/GONOSUMDB exempts a path.
	goBuildCmd   = regexp.MustCompile(`(?:^|\|\s*)(?:[A-Za-z_][A-Za-z0-9_]*=[^\s|]*\s+)*go[ \t]+(?:build|install|test|run)\b`)
	goSumDisable = regexp.MustCompile(`\bGO(?:NOSUMCHECK|NOSUMDB|FLAGS=-mod=mod|PRIVATE)\b|\bGONOSUMDB=|\bGOSUMDB=off\b`)
)

// checkDepPinning raises DEP-001 when the PKGBUILD fetches dependencies in a
// way that is pinned to a lockfile. Info severity: it never escalates a
// verdict, and Floor never acts on it. Its only job is to be present in the
// checklist so scan.confinePinnedDeps can downgrade a pkg_manager_build_deps
// warning that the pinning contradicts.
func checkDepPinning(name, text string, cmds []cmdLine, parsed bool,
	add func(code, rname string, sev Severity, file, snippet string)) {

	pinIdx := firstLiveMatch(text, depPinned, true, true)
	pinned := pinIdx >= 0

	// Go's own module verification counts, but only where nothing switches it
	// off. Checked separately so a Rust package does not inherit it.
	goPinned := false
	if !pinned && firstLiveMatch(text, goSumDisable, true, true) < 0 {
		if parsed {
			for _, cl := range cmds {
				if goBuildCmd.MatchString(cl.text) {
					goPinned = true
					break
				}
			}
		} else if firstLiveMatch(text, goBuildCmd, true, true) >= 0 {
			goPinned = true
		}
	}
	if !pinned && !goPinned {
		return
	}

	// Only report pinning where there is actually a dependency fetch to pin.
	snippet := ""
	if parsed {
		for _, cl := range cmds {
			if depFetchCmd.MatchString(cl.text) {
				snippet = cl.text
				break
			}
		}
	} else if idx := firstLiveMatch(text, depFetchRaw, true, true); idx >= 0 {
		snippet = lineAround(text, idx)
	}
	if snippet == "" {
		return
	}
	if pinned {
		add("DEP-001", "dependency fetch pinned to a lockfile", Low, name, snippet)
		return
	}
	add("DEP-001", "go module fetch verified against go.sum", Low, name, snippet)
}
