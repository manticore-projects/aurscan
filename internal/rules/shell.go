package rules

// Shell-aware deobfuscation for the command/flag/path rules (issue #43).
//
// The regex catalog matches contiguous literal substrings, which is both
// bypassable by quote-splitting (`s"ud"o` runs `sudo` but breaks the literal)
// and prone to false positives (`sudo` inside an `echo` string is printed text,
// not a command). Both stem from the same cause: a regex cannot tell a command
// *position* from quoted *data*.
//
// We delegate tokenisation to a real shell parser (mvdan.cc/sh/v3/syntax, pure
// Go, stdlib-only) and reassemble each command word with quote removal, so the
// command/flag rules run against a deobfuscated, command-position-aware view:
//   - `s"ud"o make`            -> "sudo make"   (split-token caught)
//   - `echo "sudo gpasswd …"`  -> "echo"        (echo args are data, dropped)
//   - `cu""rl x | sh`          -> "curl x | sh" (pipeline preserved, caught)
//
// We never *execute* anything: that would be RCE on a hostile PKGBUILD, which
// is the whole reason aurscan scans before makepkg. Runtime expansions
// (`$(...)`, `${x}`, arithmetic) are inherently unresolvable statically; their
// literal skeleton is reassembled and the rest is left to the LLM backstop.

import (
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// cmdLine is one deobfuscated command (or pipeline) and the source line it came
// from. text is "name arg arg" (or "NAME=val … name args"); echo/printf
// arguments are dropped because they are printed data, not executed. obf is set
// when the command was assembled with token-splicing obfuscation (issue #43).
// Redirection targets are appended to text (" >/etc/systemd/system/x.service")
// so that rules about *where a file is written* can match: the payload of a
// heredoc-written systemd unit lives in a Redirect, not in the command args,
// and was previously invisible to every command-scoped rule. bg is set when the
// statement was backgrounded with "&" — in an .install scriptlet that means the
// work detaches from pacman and keeps running after the transaction reports
// success.
type cmdLine struct {
	line int
	text string
	obf  bool
	bg   bool
}

// commandScoped lists the rule codes whose target is a command name, flag,
// shell construct, or path argument — the ones the split-token trick defeats and
// that echo-string text falsely triggers (issue #43). They are matched against
// the deobfuscated command view. Every other rule (URLs, hosts, paste sites,
// \xNN escapes, SKIP, the Unicode rules) matches data that an external system
// requires to be literal, so it stays on the raw text.
var commandScoped = map[string]bool{
	"DLE-001": true, "DLE-002": true, "DLE-003": true,
	"SHELL-001": true, "SHELL-002": true, "SHELL-003": true, "SHELL-004": true,
	"CRED-001": true, "CRED-002": true, "CRED-003": true,
	"BROWSER-001": true, "BROWSER-002": true, "WALLET-001": true,
	"PRIV-001": true, "PRIV-003": true, "INSTALL-003": true,
	"PERSIST-001": true, "PERSIST-002": true, "PERSIST-004": true, "PERSIST-006": true,
	"CRYPTO-002": true, "ENV-001": true, "ENV-002": true,
	"NPM-001": true, "OBF-001": true, "OBF-002": true, "HIDDEN-002": true,
	"WORM-003": true, "CRED-005": true, "PKGMGR-001": true,
	"PERSIST-007": true, "PERSIST-008": true, "PERSIST-009": true,
}

// Deliberately NOT command-scoped, despite naming commands or paths:
//   CRED-004  "/home/*/.ssh /root/.ssh" appears in a `for` word list, which is
//             not a CallExpr and so never reaches the command view.
//   WORM-001  "$BASH_SOURCE" is a ParamExp; the command view resolves it away.
//   WORM-002  the AUR remote lives inside a URL string argument.
//   EXFIL-004/005  onion hosts and socks:// proxies are data literals.

// outputBuiltins print their arguments rather than executing them, so their
// argument text is data, not a command position. Dropping their args is what
// removes the `echo "sudo …"` false positive.
var outputBuiltins = map[string]bool{
	"echo": true, "printf": true, ":": true, "true": true, "false": true,
}

// extractCommands parses src as shell and returns the deobfuscated command view.
// A parse failure returns an error so the caller can fall back to raw-text
// matching (never losing detection on an unparseable file).
func extractCommands(src string) ([]cmdLine, error) {
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, err
	}
	var lines []cmdLine
	collectCommands(f, &lines, 0)
	return lines, nil
}

// collectCommands walks node, rendering maximal pipelines as a single line
// ("a | b | c") so pipe-spanning rules (curl|sh) still see the relationship, and
// every other simple command on its own line. depth bounds eval recursion.
func collectCommands(node syntax.Node, out *[]cmdLine, depth int) {
	// Map each simple command back to the statement that carries its
	// redirections and its "&" flag (both live on *syntax.Stmt, not on the
	// CallExpr), so renderCall can surface them.
	stmts := map[*syntax.CallExpr]*syntax.Stmt{}
	syntax.Walk(node, func(n syntax.Node) bool {
		if st, ok := n.(*syntax.Stmt); ok {
			if ce, ok := st.Cmd.(*syntax.CallExpr); ok {
				stmts[ce] = st
			}
		}
		return true
	})

	// First, find maximal pipelines and the CallExprs they consume.
	type pipe struct {
		start, end uint
		calls      []*syntax.CallExpr
	}
	var pipes []pipe
	syntax.Walk(node, func(n syntax.Node) bool {
		if bc, ok := n.(*syntax.BinaryCmd); ok && (bc.Op == syntax.Pipe || bc.Op == syntax.PipeAll) {
			var calls []*syntax.CallExpr
			syntax.Walk(bc, func(m syntax.Node) bool {
				if ce, ok := m.(*syntax.CallExpr); ok {
					calls = append(calls, ce)
				}
				return true
			})
			pipes = append(pipes, pipe{bc.Pos().Offset(), bc.End().Offset(), calls})
		}
		return true
	})
	consumed := map[*syntax.CallExpr]bool{}
	contained := func(i int) bool {
		for j, p := range pipes {
			if j == i {
				continue
			}
			if p.start <= pipes[i].start && pipes[i].end <= p.end &&
				!(p.start == pipes[i].start && p.end == pipes[i].end) {
				return true
			}
		}
		return false
	}
	for i, p := range pipes {
		for _, ce := range p.calls {
			consumed[ce] = true
		}
		if contained(i) || len(p.calls) == 0 {
			continue
		}
		var parts []string
		obf, bg := false, false
		for _, ce := range p.calls {
			parts = append(parts, renderCall(ce, stmts[ce]))
			obf = obf || callObfuscated(ce)
			bg = bg || isBackground(stmts[ce])
		}
		*out = append(*out, cmdLine{int(p.calls[0].Pos().Line()), strings.Join(parts, " | "), obf, bg})
	}

	// Then every non-piped simple command.
	syntax.Walk(node, func(n syntax.Node) bool {
		ce, ok := n.(*syntax.CallExpr)
		if !ok || consumed[ce] || (len(ce.Args) == 0 && len(ce.Assigns) == 0) {
			return true
		}
		consumed[ce] = true
		text := renderCall(ce, stmts[ce])
		*out = append(*out, cmdLine{int(ce.Pos().Line()), text, callObfuscated(ce), isBackground(stmts[ce])})
		// Depth-1 eval: re-parse a literal eval/source string as shell so
		// `eval "s\"ud\"o …"` is deobfuscated too.
		if depth < 1 && len(ce.Args) >= 2 {
			if base := baseName(firstWord(ce.Args[0])); base == "eval" || base == "source" || base == "." {
				if inner, _ := resolveWord(ce.Args[1]); strings.TrimSpace(inner) != "" {
					if sub, err := syntax.NewParser().Parse(strings.NewReader(inner), ""); err == nil {
						collectCommands(sub, out, depth+1)
					}
				}
			}
		}
		return true
	})
}

// isBackground reports whether the statement carrying this command ended in
// "&". A backgrounded call in an install scriptlet outlives the pacman
// transaction, which is how a hook hides long-running work behind an install
// that appears to finish cleanly.
func isBackground(st *syntax.Stmt) bool { return st != nil && st.Background }

// renderRedirs appends the redirection operators and targets of st to b, e.g.
// " <<EOF >/etc/systemd/system/x.service". Heredoc BODIES are deliberately not
// rendered here — they are file *content*, already covered by the raw-text
// rules — but the destination path is what turns "cat a heredoc" into "install
// a systemd unit", so it must be visible to the command-scoped rules.
func renderRedirs(b *strings.Builder, st *syntax.Stmt) {
	if st == nil {
		return
	}
	for _, r := range st.Redirs {
		if r == nil {
			continue
		}
		b.WriteByte(' ')
		if r.N != nil {
			b.WriteString(r.N.Value)
		}
		b.WriteString(r.Op.String())
		if v, _ := resolveWord(r.Word); v != "" {
			b.WriteString(v)
		}
	}
}

// renderCall reassembles a simple command as deobfuscated "NAME=val … name args"
// text, followed by its redirection targets. Output-builtin arguments are
// dropped (they are printed data) but their redirections are not: `echo x
// >/etc/sudoers` is a write, not printed text.
func renderCall(ce *syntax.CallExpr, st *syntax.Stmt) string {
	var b strings.Builder
	for _, as := range ce.Assigns {
		if as.Name != nil {
			b.WriteString(as.Name.Value)
			b.WriteByte('=')
			if as.Value != nil {
				v, _ := resolveWord(as.Value)
				b.WriteString(v)
			}
			b.WriteByte(' ')
		}
	}
	if len(ce.Args) == 0 {
		renderRedirs(&b, st)
		return strings.TrimSpace(b.String())
	}
	name, _ := resolveWord(ce.Args[0])
	b.WriteString(name)
	if !outputBuiltins[baseName(name)] {
		for _, a := range ce.Args[1:] {
			v, _ := resolveWord(a)
			b.WriteByte(' ')
			b.WriteString(v)
		}
	}
	renderRedirs(&b, st)
	return b.String()
}

// callObfuscated reports whether a command was disguised with token-splicing
// obfuscation — the command word, or (for non-output builtins) any argument.
// Output-builtin arguments are printed data, so quoting inside them is ignored.
func callObfuscated(ce *syntax.CallExpr) bool {
	if len(ce.Args) == 0 {
		return false
	}
	if wordObfuscated(ce.Args[0]) {
		return true
	}
	if outputBuiltins[baseName(firstWord(ce.Args[0]))] {
		return false
	}
	for _, a := range ce.Args[1:] {
		if wordObfuscated(a) {
			return true
		}
	}
	return false
}

// wordObfuscated detects token-splicing that has no functional purpose and is
// therefore a deliberate evasion signal: an interior quoted fragment with no
// expansion (s"ud"o, cu""rl, /etc/su""doers), an ANSI-C $'…' splice
// (su$'\x64'o), or an ${IFS…} separator injection. It deliberately does NOT
// flag ordinary variable interpolation such as $pkgname-$pkgver or a quoted
// value like --prefix="/usr", which are normal in PKGBUILDs.
func wordObfuscated(w *syntax.Word) bool {
	if w == nil || len(w.Parts) < 2 {
		return false
	}
	n := len(w.Parts)
	for i, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.SglQuoted:
			if x.Dollar { // $'…' ANSI-C encoding used to build a larger word
				return true
			}
			if interior(i, n) && !strings.ContainsAny(x.Value, " \t\n") {
				return true // '…' fragment splicing a token from the inside
			}
		case *syntax.DblQuoted:
			if interior(i, n) && !dquotedHasExpansion(x) &&
				!strings.ContainsAny(dquotedText(x), " \t\n") {
				return true // "…" fragment (incl. empty "") splicing a token
			}
		case *syntax.ParamExp:
			if x.Param != nil && x.Param.Value == "IFS" {
				return true // ${IFS…} spliced into a word — separator injection
			}
		}
	}
	return false
}

// interior is true when part i is neither the first nor last part of the word,
// i.e. it sits between other content and so splits a token from the inside.
func interior(i, n int) bool { return i > 0 && i < n-1 }

func dquotedHasExpansion(d *syntax.DblQuoted) bool {
	for _, p := range d.Parts {
		if _, ok := p.(*syntax.Lit); !ok {
			return true
		}
	}
	return false
}

func dquotedText(d *syntax.DblQuoted) string {
	var b strings.Builder
	for _, p := range d.Parts {
		if lit, ok := p.(*syntax.Lit); ok {
			b.WriteString(lit.Value)
		}
	}
	return b.String()
}

// ANSI-C ($'…') escapes. dyn=true means at least one part was a runtime
// expansion (${x}, $(...), arithmetic) that cannot be resolved statically.
func resolveWord(w *syntax.Word) (text string, dyn bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	for _, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.Lit:
			b.WriteString(x.Value)
		case *syntax.SglQuoted:
			if x.Dollar { // $'…' ANSI-C quoting
				b.WriteString(ansiC(x.Value))
			} else {
				b.WriteString(x.Value)
			}
		case *syntax.DblQuoted:
			for _, dp := range x.Parts {
				if lit, ok := dp.(*syntax.Lit); ok {
					b.WriteString(dquoteUnescape(lit.Value))
				} else {
					dyn = true
				}
			}
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ProcSubst:
			dyn = true // ${x}, $(...), $((...)), <(...) — unresolved
		default:
			dyn = true
		}
	}
	return b.String(), dyn
}

func firstWord(w *syntax.Word) string { s, _ := resolveWord(w); return s }

// dquoteUnescape processes the backslash escapes that are special inside double
// quotes (\" \\ \` \$), so an eval string like "s\"ud\"o" re-parses as quoting
// rather than literal quote characters.
func dquoteUnescape(s string) string {
	return strings.NewReplacer(`\\`, `\`, `\"`, `"`, "\\`", "`", `\$`, `$`).Replace(s)
}

// ansiC decodes the common $'…' escapes (\xNN, \t, \n, \r, octal, quotes) so a
// spliced character like su$'\x64'o resolves to "sudo".
func ansiC(s string) string {
	s = strings.NewReplacer(
		`\t`, "\t", `\n`, "\n", `\r`, "\r", `\\`, `\`, `\'`, `'`, `\"`, `"`,
	).Replace(s)
	for {
		i := strings.Index(s, `\x`)
		if i < 0 || i+4 > len(s) {
			break
		}
		n, err := strconv.ParseInt(s[i+2:i+4], 16, 16)
		if err != nil {
			break
		}
		s = s[:i] + string(rune(n)) + s[i+4:]
	}
	return s
}

func baseName(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}
