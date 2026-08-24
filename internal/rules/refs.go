package rules

// Reference resolution: does every file the package REFERENCES actually reach
// the scanner?
//
// A PKGBUILD executes at build time and is what a reviewer reads. The
// `install=` scriptlet is different: makepkg never runs it, it is embedded in
// the built package as `.INSTALL`, and libalpm executes it AS ROOT on the
// installing machine at pacman -U/-S time. Nothing in the PKGBUILD sources it —
// the only link between the two is a filename string. So a scanner that reads
// the PKGBUILD and nothing else can review a package whose entire payload it
// never saw, and report OK with complete syntactic honesty.
//
// That is the gap these rules close. They do not look for malice; they look for
// the scanner's own blind spots and make them loud:
//
//   REF-001  referenced file was NOT supplied  -> the scan is INCOMPLETE
//   REF-002  install= names a hidden (dot-prefixed) file -> concealment
//   REF-003  the reference cannot be resolved statically -> unknown coverage
//   REF-004  a local source=() entry was not supplied
//
// REF-001 is deliberately not "malicious": it means "you cannot conclude
// anything yet". The floor (see Floor) turns it into a verdict the model is not
// allowed to clear.

import (
	"regexp"
	"strings"
)

var (
	// install=foo.install / install="$pkgname.install" / install=('a.install')
	installAssign = regexp.MustCompile(`(?m)^[ \t]*install=([^\n#]+)`)
	// .SRCINFO: "	install = foo.install"
	srcinfoInstall = regexp.MustCompile(`(?m)^[ \t]*install[ \t]*=[ \t]*(\S+)[ \t]*$`)
	// pkgname=foo / pkgname=('foo' 'bar') — first value wins, used to resolve
	// the very common install="$pkgname.install" form.
	pkgnameAssign = regexp.MustCompile(`(?m)^[ \t]*pkgname=([^\n#]+)`)
	pkgverAssign  = regexp.MustCompile(`(?m)^[ \t]*pkgver=([^\n#]+)`)
	// source=( ... ) across lines; entries without a scheme are local files
	// that must be present in the repository.
	sourceArray = regexp.MustCompile(`(?s)(?m)^[ \t]*source(?:_[a-z0-9_]+)?=\(([^)]*)\)`)
)

// unquote strips surrounding quotes and array parentheses from an assignment
// right-hand side and returns the first value.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(s, ")")
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 && !strings.HasPrefix(s, `"`) && !strings.HasPrefix(s, `'`) {
		s = s[:i]
	}
	for _, q := range []string{`"`, `'`} {
		if strings.HasPrefix(s, q) {
			s = strings.TrimPrefix(s, q)
			if i := strings.Index(s, q); i >= 0 {
				s = s[:i]
			}
		}
	}
	return strings.TrimSpace(s)
}

// simpleAssign captures a top-level `name=value` on one line. Function bodies
// and array continuations produce junk entries, which is harmless: a name is
// only ever consulted when a reference actually mentions it.
var simpleAssign = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)=([^\n#]*)`)

// varRef matches $name and ${name}. It deliberately does NOT match parameter
// expansions carrying an operator (${pkgver%.?}), which cannot be resolved
// without evaluating shell.
var varRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// varMap collects the PKGBUILD's simple assignments. First definition wins,
// matching makepkg's top-to-bottom evaluation closely enough for name
// resolution.
func varMap(text string) map[string]string {
	m := map[string]string{}
	for _, mm := range simpleAssign.FindAllStringSubmatch(text, -1) {
		if _, dup := m[mm[1]]; dup {
			continue
		}
		if v := unquote(mm[2]); v != "" {
			m[mm[1]] = v
		}
	}
	return m
}

// substVars resolves variables in a file reference, iterating so that one
// definition may be written in terms of another. The original version knew only
// pkgname/pkgbase/pkgver, so a single level of indirection —
// `install=$pkgname.install` where `pkgname=jdk${java_}-graalvm-bin` and
// `java_=19` — came back unresolved and was reported as REF-003, which carries
// a floor. That is the scanner reporting its own shallow substitution as a
// finding about the package.
//
// Anything still containing '$' after the passes is genuinely unresolvable
// (a command substitution, an operator expansion) and IS reported.
func substVars(ref string, vars map[string]string) string {
	for i := 0; i < 5; i++ {
		out := varRef.ReplaceAllStringFunc(ref, func(m string) string {
			if v, ok := vars[strings.Trim(m, "${}")]; ok {
				return v
			}
			return m
		})
		if out == ref {
			break
		}
		ref = out
	}
	return ref
}

// hasFile reports whether the file set contains name, tolerating the leading
// "<pkgbase>/" path component some collection paths keep.
func hasFile(files map[string]string, name string) bool {
	if name == "" {
		return false
	}
	if _, ok := files[name]; ok {
		return true
	}
	for k := range files {
		if k == name {
			return true
		}
		if i := strings.LastIndexByte(k, '/'); i >= 0 && k[i+1:] == name {
			return true
		}
	}
	return false
}

// firstValue extracts the first value of an assignment from text.
func firstValue(re *regexp.Regexp, text string) string {
	m := re.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return unquote(m[1])
}

// checkReferences resolves every file the package points at by name and reports
// the ones the scanner did not receive. It runs once per package (not per
// file), because the whole point is the relationship BETWEEN files.
func checkReferences(files map[string]string, add func(code, name string, sev Severity, file, snippet string)) {
	pkgbuild, hasPKGBUILD := files["PKGBUILD"]
	srcinfo := files[".SRCINFO"]
	if !hasPKGBUILD && srcinfo == "" {
		return
	}
	vars := varMap(pkgbuild)
	if _, ok := vars["pkgname"]; !ok {
		if b := firstValue(regexp.MustCompile(`(?m)^[ \t]*pkgbase[ \t]*=[ \t]*(\S+)`), srcinfo); b != "" {
			vars["pkgname"] = b
		}
	}
	if v, ok := vars["pkgname"]; ok {
		if _, has := vars["pkgbase"]; !has {
			vars["pkgbase"] = v
		}
	}

	// --- install= scriptlets -------------------------------------------------
	seen := map[string]bool{}
	type ref struct{ raw, where string }
	var installRefs []ref
	for _, m := range installAssign.FindAllStringSubmatch(pkgbuild, -1) {
		installRefs = append(installRefs, ref{unquote(m[1]), "PKGBUILD"})
	}
	for _, m := range srcinfoInstall.FindAllStringSubmatch(srcinfo, -1) {
		installRefs = append(installRefs, ref{unquote(m[1]), ".SRCINFO"})
	}
	for _, r := range installRefs {
		if r.raw == "" || seen[r.raw] {
			continue
		}
		seen[r.raw] = true
		resolved := substVars(r.raw, vars)

		// A dot-prefixed scriptlet is concealment, not convention: it hides
		// from `ls` and from any directory walk that skips dotfiles, while
		// pacman resolves it perfectly well. No legitimate package needs it.
		if strings.HasPrefix(baseName(resolved), ".") || strings.HasPrefix(baseName(r.raw), ".") {
			add("REF-002", "install= names a hidden (dot-prefixed) scriptlet", Critical,
				r.where, "install="+r.raw)
		}
		if strings.Contains(resolved, "$") {
			add("REF-003", "install= reference cannot be resolved statically", High,
				r.where, "install="+r.raw)
			continue
		}
		if !hasFile(files, resolved) {
			// High, NOT Critical. "I was not given this file" means the scan
			// is incomplete, which is a different claim from "this package is
			// malicious" — and in rules-only mode Worst() maps Critical
			// straight to MALICIOUS, which would condemn every legitimate
			// package scanned with `--scan-file PKGBUILD`. The Floor still
			// forbids an OK verdict; it just does not invent guilt.
			add("REF-001", "referenced install scriptlet was not supplied to the scanner (scan incomplete)",
				High, r.where, "install="+r.raw)
		}
	}

	// --- local source=() entries --------------------------------------------
	if !hasPKGBUILD {
		return
	}
	for _, m := range sourceArray.FindAllStringSubmatch(pkgbuild, -1) {
		// splitArrayTokens, not strings.Fields: a $( ) substitution may contain
		// spaces, and splitting inside it produces fragments that look like
		// local filenames (checksums.go).
		for _, tok := range splitArrayTokens(m[1]) {
			// stripQuotes, NOT unquote: the "name::url" separator routinely
			// sits OUTSIDE the quotes with quotes on both sides —
			//
			//	source=("${pkgname}-${pkgver}"::"https://example.org/bin")
			//
			// and unquote truncates at the closing quote, discarding the URL
			// half so the entry reads as a local file. Same failure as
			// "url"{,.sig} in checksums.go; source entries are quote-stripped,
			// never quote-truncated.
			e := stripQuotes(tok)
			// A bare "\" is a line continuation, not a source entry. Field
			// splitting picks it up and it was being reported as a missing
			// local file named "\".
			if e == "" || e == `\` || strings.HasPrefix(e, "#") {
				continue
			}
			// Resolve BEFORE deciding local-vs-remote. The scheme is routinely
			// hidden behind a variable — `$url/archive/v$pkgver.tar.gz` has no
			// literal "://" — so testing the raw entry classifies a download as
			// a missing local file. isLocalEntry (checksums.go) does the same
			// resolution for CHK-005; this loop must use it too, or improving
			// variable resolution turns every variable-built URL into a
			// phantom REF-004.
			resolved := substVars(e, vars)
			if !isLocalEntry(resolved, vars["url"]) {
				continue
			}
			if strings.Contains(resolved, "$") || seen[resolved] {
				continue
			}
			seen[resolved] = true
			if !hasFile(files, resolved) {
				add("REF-004", "local source=() file was not supplied to the scanner",
					Medium, "PKGBUILD", "source: "+e)
			}
		}
	}
}
