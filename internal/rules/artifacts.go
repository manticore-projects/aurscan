package rules

// Names makepkg writes into a build directory.
//
// A local build directory (the one yay/paru hand to aurscan, or one the user
// ran makepkg in) is the AUR repository PLUS whatever makepkg left there:
// every remote source=() entry is downloaded next to the PKGBUILD, and a
// finished build leaves a .pkg.tar.* behind. None of that is part of the
// package's repository, and none of it should be described to the auditor as
// if it were.

import (
	"regexp"
	"strings"
)

// DownloadedSourceNames returns the file names makepkg saves in $startdir for
// the package's REMOTE source=() entries (all source arrays, including the
// architecture-specific ones), following makepkg's get_filename:
//
//   - "name::url"  -> name
//   - "url#frag"   -> basename of url, fragment removed
//   - VCS entries  -> skipped: those are checkout DIRECTORIES, which the
//     collector already skips as git checkouts
//
// Entries whose name still contains an unresolved '$' after variable
// substitution are skipped rather than guessed at: a name that cannot be
// computed cannot be matched, and a guess that matched the wrong file would
// relabel a repository file as a download.
func DownloadedSourceNames(pkgbuild string) map[string]bool {
	out := map[string]bool{}
	vars := varMap(pkgbuild)
	for _, m := range sourceArray.FindAllStringSubmatch(pkgbuild, -1) {
		for _, e := range arrayEntries(m[1]) {
			resolved := substVars(e, vars)
			if isLocalEntry(resolved, vars["url"]) || isVCSEntry(resolved) {
				continue
			}
			name := resolved
			if i := strings.Index(name, "::"); i >= 0 {
				name = name[:i]
			} else {
				if i := strings.IndexByte(name, '#'); i >= 0 {
					name = name[:i]
				}
				if i := strings.LastIndexByte(name, '/'); i >= 0 {
					name = name[i+1:]
				}
			}
			if name == "" || strings.ContainsAny(name, "$/`") {
				continue
			}
			out[name] = true
		}
	}
	return out
}

// makepkgOutput matches what makepkg itself produces in $startdir: built
// packages (--package), source packages (--source / --allsource), and the
// per-phase logs written by --log.
var makepkgOutput = regexp.MustCompile(
	`(?i)(\.pkg\.tar(\.[a-z0-9]+)?|\.src\.tar(\.[a-z0-9]+)?)(\.sig)?$|-(pkgver|prepare|build|check|package(_[a-z0-9_.+-]+)?)\.log(\.\d+)?$`)

// IsMakepkgOutput reports whether a top-level build-directory name is a file
// makepkg produced rather than one the repository contains.
func IsMakepkgOutput(name string) bool { return makepkgOutput.MatchString(name) }
