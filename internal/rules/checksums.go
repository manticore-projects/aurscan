package rules

// CHK-005, done positionally.
//
// The original rule was a regex over the checksum array: sha256sums=(...SKIP.
// That asks "does any checksum say SKIP?", which is not the question. SKIP is
// correct and universal for two cases:
//
//   - a VCS source (git+/svn+/hg+/bzr+), where there is no fixed tarball to
//     hash;
//   - a detached signature (.sig/.asc), which is verified by gpg against
//     validpgpkeys rather than by checksum. Every upstream-signed package in
//     the AUR looks like sha256sums=('<hash>' 'SKIP').
//
// The old pattern flagged the second case as a warning, and missed the first
// whenever the source array spanned multiple lines: its VCS check required
// source= and git+ to sit on the SAME line. It also only examined sha256sums,
// so a package using b2sums or sha512sums was never checked at all.
//
// The question that actually matters is "is there a source entry whose integrity
// nothing verifies?" — which requires pairing each checksum with the source at
// the same index.

import (
	"regexp"
	"strings"
)

// checksumArray matches any of makepkg's integrity arrays, including the
// architecture-suffixed forms (sha256sums_x86_64=). Group 1 is the algorithm,
// group 2 the architecture suffix (empty for the generic array), group 3 the
// body.
var checksumArray = regexp.MustCompile(
	`(?s)(?m)^[ \t]*(b2|md5|sha1|sha224|sha256|sha384|sha512)sums(_[a-z0-9_]+)?=\(([^)]*)\)`)

// sourceArrayWithArch mirrors it for source=/source_x86_64=.
var sourceArrayWithArch = regexp.MustCompile(
	`(?s)(?m)^[ \t]*source(_[a-z0-9_]+)?=\(([^)]*)\)`)

// stripQuotes removes quote characters without truncating the token. This
// matters because an entry is routinely quote-then-brace:
//
//	"https://example.org/foo.tar.gz"{,.sig}
//
// Truncating at the closing quote would silently drop the brace suffix and
// lose one of the two sources it expands to.
func stripQuotes(s string) string {
	return strings.NewReplacer(`"`, "", `'`, "").Replace(s)
}

// maxBraceExpansion caps the entries one token may expand to, so a pathological
// or hostile PKGBUILD cannot make the scanner allocate without bound.
const maxBraceExpansion = 64

// expandBraces performs makepkg's brace expansion on a source entry, so that
//
//	https://example.org/foo.tar.gz{,.sig}
//
// yields BOTH foo.tar.gz and foo.tar.gz.sig. This is the whole reason CHK-005
// mispaired: `source=(url{,.sig})` is ONE array token but TWO sources, so every
// checksum after it was off by one and the trailing SKIP — which belongs to the
// signature — was attributed to whatever came next. It is the single most
// common shape in signed AUR packages.
//
// A '{' preceded by '$' is a parameter expansion (${pkgver}), not a brace list,
// and is left alone.
func expandBraces(s string) []string {
	for i := 0; i < len(s); i++ {
		if s[i] != '{' || (i > 0 && s[i-1] == '$') {
			continue
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			break
		}
		j += i
		inner := s[i+1 : j]
		if !strings.Contains(inner, ",") || strings.ContainsAny(inner, "{}") {
			continue
		}
		var out []string
		for _, alt := range strings.Split(inner, ",") {
			out = append(out, expandBraces(s[:i]+alt+s[j+1:])...)
			if len(out) > maxBraceExpansion {
				return out[:maxBraceExpansion]
			}
		}
		return out
	}
	return []string{s}
}

// splitArrayTokens splits an array body on whitespace, but NOT inside quotes or
// inside a $( ) command substitution.
//
// The naive strings.Fields is wrong because a substitution may contain spaces:
//
//	source=("$_model_file::$(__model_url $_model)")
//
// splits into `"$_model_file::$(__model_url` and `$_model)"`, and the second
// fragment resolves to `base)` — a plausible-looking local filename that is of
// course absent, reported as a missing source. Entry splitting is the shared
// foundation for CHK-005 and REF-004, so it is done once, here.
func splitArrayTokens(body string) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	var quote byte
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, ln := range strings.Split(body, "\n") {
		// A '#' outside quotes starts a comment, unless it is a URL fragment.
		if quote == 0 && depth == 0 {
			if i := strings.Index(ln, "#"); i >= 0 && !strings.Contains(ln[:i], "://") {
				ln = ln[:i]
			}
		}
		for i := 0; i < len(ln); i++ {
			c := ln[i]
			switch {
			case quote != 0:
				if c == quote {
					quote = 0
				}
				cur.WriteByte(c)
			case c == '\'' || c == '"':
				quote = c
				cur.WriteByte(c)
			case c == '$' && i+1 < len(ln) && ln[i+1] == '(':
				depth++
				cur.WriteString("$(")
				i++
			case c == ')' && depth > 0:
				depth--
				cur.WriteByte(c)
			case (c == ' ' || c == '\t') && depth == 0:
				flush()
			default:
				cur.WriteByte(c)
			}
		}
		if depth == 0 && quote == 0 {
			flush()
		} else {
			cur.WriteByte(' ')
		}
	}
	flush()
	return out
}

// arrayEntries splits an array body into entries, dropping comments and
// expanding braces.
func arrayEntries(body string) []string {
	var out []string
	for _, tok := range splitArrayTokens(body) {
		tok = strings.TrimSpace(tok)
		if tok == "" || tok == `\` {
			continue
		}
		for _, e := range expandBraces(stripQuotes(tok)) {
			if e != "" {
				out = append(out, e)
			}
		}
	}
	return out
}

// isVCSEntry reports whether a source entry is a version-control checkout, for
// which SKIP is the only possible value.
func isVCSEntry(e string) bool {
	if i := strings.Index(e, "::"); i >= 0 {
		e = e[i+2:]
	}
	for _, p := range []string{"git+", "svn+", "hg+", "bzr+", "fossil+"} {
		if strings.Contains(strings.ToLower(e), p) {
			return true
		}
	}
	return strings.HasSuffix(strings.ToLower(e), ".git")
}

// isLocalEntry reports whether a source entry is a file committed to the
// package repository rather than something fetched. SKIP on a local file is not
// an integrity gap: nothing is downloaded, the file's integrity is the
// repository's, any change to it appears in the git diff that yay/paru show
// before building, and aurscan is reading its contents directly anyway. A
// referenced local file that is MISSING is a separate matter, reported by
// REF-004.
// It takes the PKGBUILD's url= value because the scheme is routinely hidden
// behind a variable: `source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")`
// contains no literal "://" yet is plainly a download. Without resolving $url
// that entry reads as a local file and its missing checksum goes unreported.
func isLocalEntry(e, pkgurl string) bool {
	if i := strings.Index(e, "::"); i >= 0 {
		e = e[i+2:]
	}
	if pkgurl != "" {
		e = strings.NewReplacer("${url}", pkgurl, "$url", pkgurl).Replace(e)
	}
	if strings.Contains(e, "://") {
		return false
	}
	// No scheme resolved. A bare filename (possibly with variables in it, e.g.
	// ${pkgname}.desktop) is local; anything with a path separator is more
	// likely an unresolved remote URL, so err toward reporting it.
	return !strings.Contains(e, "/")
}

// urlAssign captures the PKGBUILD's url= value (the upstream homepage), which
// source entries frequently interpolate.
var urlAssign = regexp.MustCompile(`(?m)^[ \t]*url=([^\n#]+)`)

// isSignatureEntry reports whether a source entry is a detached signature,
// whose integrity comes from gpg + validpgpkeys rather than from a checksum.
// SKIP here is not a weakening — it is how signed packages are written.
func isSignatureEntry(e string) bool {
	// Test the entry as written AND with a trailing query string removed. The
	// query strip is deliberately confined to the final path segment: a
	// makepkg URL routinely embeds shell parameter expansion containing '?'
	// (${pkgver%.?} is the standard "drop the last component" idiom), and
	// cutting at the first '?' anywhere would truncate the URL before its
	// extension and hide the .asc.
	cands := []string{e}
	if i := strings.LastIndexByte(e, '/'); i >= 0 {
		if j := strings.IndexByte(e[i:], '?'); j >= 0 {
			cands = append(cands, e[:i+j])
		}
	} else if j := strings.IndexByte(e, '?'); j >= 0 {
		cands = append(cands, e[:j])
	}
	for _, c := range cands {
		l := strings.ToLower(c)
		for _, suf := range []string{".sig", ".asc", ".sign", ".gpg"} {
			if strings.HasSuffix(l, suf) {
				return true
			}
		}
	}
	return false
}

// checkChecksums raises CHK-005 only for a source entry that is neither a VCS
// checkout nor a detached signature yet has SKIP as its checksum — i.e. a
// fetched artifact whose integrity genuinely nothing verifies.
func checkChecksums(name, text string,
	add func(code, rname string, sev Severity, file, snippet string)) {

	// Index the source arrays by architecture suffix so sha256sums_x86_64
	// pairs with source_x86_64 rather than with source.
	srcByArch := map[string][]string{}
	for _, m := range sourceArrayWithArch.FindAllStringSubmatchIndex(text, -1) {
		if isCommentAt(text, m[0]) {
			continue
		}
		arch := ""
		if m[2] >= 0 {
			arch = text[m[2]:m[3]]
		}
		srcByArch[arch] = arrayEntries(text[m[4]:m[5]])
	}
	if len(srcByArch) == 0 {
		return
	}
	pkgurl := ""
	if m := urlAssign.FindStringSubmatch(text); m != nil {
		pkgurl = stripQuotes(strings.TrimSpace(m[1]))
	}

	for _, m := range checksumArray.FindAllStringSubmatchIndex(text, -1) {
		if isCommentAt(text, m[0]) {
			continue
		}
		arch := ""
		if m[4] >= 0 {
			arch = text[m[4]:m[5]]
		}
		srcs, ok := srcByArch[arch]
		if !ok {
			srcs = srcByArch[""]
		}
		for i, sum := range arrayEntries(text[m[6]:m[7]]) {
			if !strings.EqualFold(sum, "SKIP") {
				continue
			}
			if i >= len(srcs) {
				// The arrays did not pair. That is a limit of this analysis,
				// not a property of the package — reporting it would mean
				// raising a finding because the scanner got confused, which is
				// how a rule teaches users to ignore it. Stay silent.
				break
			}
			if isVCSEntry(srcs[i]) || isSignatureEntry(srcs[i]) || isLocalEntry(srcs[i], pkgurl) {
				continue
			}
			add("CHK-005", "source with no integrity check (SKIP on a non-VCS, non-signature source)",
				High, name, srcs[i])
		}
	}
}
