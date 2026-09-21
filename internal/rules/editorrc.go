package rules

// EDITOR-003 / EDITOR-008: editor project rc files.
//
// EDITOR-003 used to fire on the NAME alone — any .nvim.lua, .exrc or .lvimrc
// was critical and fatal. That was wrong in two ways, both visible on
// jre-jetbrains, whose .nvim.lua is the single line
//
//	vim.lsp.enable { 'termux_language_server' }
//
//   - The file's content is the finding, not its name. That line enables, by
//     name, an LSP server the reviewer must already have installed and
//     configured; termux-language-server is a language server FOR PKGBUILDs,
//     so it is exactly what an AUR maintainer would leave behind. Nothing in
//     the file spawns a process of the package's choosing.
//   - The "runs without consent" premise is false for current Neovim: 'exrc'
//     is off by default, and since 0.9 an exrc is loaded only after the user
//     trusts it via the vim.secure prompt (re-prompted on every change).
//     Plain Vim has no such prompt, which is why the rule stays.
//
// A fatal code has to mean "no legitimate form exists". An rc that only sets
// options has one — maintainer tooling leaking into the repository — so the
// presence observation is now EDITOR-008 at info tier, and EDITOR-003 is kept
// for an rc that contains an execution primitive, where the original reasoning
// holds in full.
//
// The primitive list errs toward arming. A false EDITOR-003 costs a package
// that ships a genuinely odd rc; a missed one costs the reviewer's machine.
// Comments are NOT stripped for the same reason: "-- os.execute(...)" is
// armed, because deciding what is commented out in a mixed Lua/vimscript file
// is exactly the kind of parse an attacker gets to exploit.

import (
	"path"
	"regexp"
	"strings"
)

// editorRCNames are the project rc files an editor reads from the directory
// it is started in.
var editorRCNames = map[string]bool{
	".exrc": true, ".nvim.lua": true, ".nvimrc": true, ".lvimrc": true,
	".vimrc": true, ".editorconfig-lua": true,
}

// vimVerbPrefix anchors an ex command: at the start of a line, after a '|'
// command separator, or at the start of a string literal (the argument of
// vim.cmd / nvim_command in a Lua rc). Optional ':' and modifiers.
const vimVerbPrefix = `(?:^|\||["'\[])\s*:*\s*(?:(?:sil(?:ent)?!?|verb(?:ose)?|vert(?:ical)?|keep\w*|noa(?:utocmd)?|unsilent|sandbox)\s+)*`

// rcExecPrimitives are the ways an rc file can run something, load code, or
// redirect which binary a later action runs.
var rcExecPrimitives = []*regexp.Regexp{
	// --- Lua: processes, files, dynamic code --------------------------------
	regexp.MustCompile(`\bos\.(?:execute|remove|rename|exit|tmpname)\b`),
	regexp.MustCompile(`\bio\.(?:popen|open|lines|output|input|write)\b`),
	regexp.MustCompile(`\b(?:loadstring|loadfile|dofile|load)\s*[\(\"'\[]`),
	regexp.MustCompile(`\bpackage\.(?:path|cpath|loadlib|preload|loaded|searchers|loaders)\b`),
	regexp.MustCompile(`\brequire\s*\(?\s*["'\[]+\s*ffi\b`),
	regexp.MustCompile(`\b(?:string\.dump|getfenv|setfenv|rawset|debug\.\w+)\b`),
	regexp.MustCompile(`\b_G\s*[\[.]`),
	// Encoded strings: the usual way to hide the verb from every rule above.
	regexp.MustCompile(`\bstring\.char\s*\(|\\x[0-9a-fA-F]{2}|\\[0-9]{2,3}`),
	// LuaJIT bytecode starts with ESC 'L' 'J'.
	regexp.MustCompile("\x1bLJ"),
	// --- Neovim API ---------------------------------------------------------
	regexp.MustCompile(`\bvim\.system\s*\(`),
	regexp.MustCompile(`\bvim\.(?:uv|loop)\.(?:spawn|kill|fs_\w+|new_\w+|exepath)\b`),
	regexp.MustCompile(`\bvim\.fn\s*\[`),
	regexp.MustCompile(`\bvim\.(?:call|fn\.call)\s*\(`),
	regexp.MustCompile(`\bvim\.api\.nvim_(?:command|exec2?|exec_lua|exec_autocmds|call_function|call_dict_function|eval|feedkeys|input|open_term|chan_send)\b`),
	regexp.MustCompile(`\bvim\.secure\b`),
	regexp.MustCompile(`\bvim\.env\b`),
	regexp.MustCompile(`\bvim\.(?:o|go|bo|wo|opt|opt_local|opt_global)\s*[\.\[]\s*["']?(?:shell\w*|sh|shcf|makeprg|mp|grepprg|gp|keywordprg|kp|formatprg|fp|equalprg|ep|runtimepath|rtp|packpath|pp|exrc|ex|secure|modeline\w*|ml|mle|mls|diffexpr|patchexpr|charconvert|printexpr|includeexpr|indentexpr|foldexpr|formatexpr|tagfunc|omnifunc|completefunc|operatorfunc|opfunc|thesaurusfunc|findfunc|backupdir|directory|undodir|viminfofile|shadafile)\b`),
	// vim.cmd is a general ex escape. A literal argument is judged by the ex
	// patterns below; a computed one, or the vim.cmd.<verb> / vim.cmd[...]
	// forms, cannot be judged and is armed.
	regexp.MustCompile(`\bvim\.cmd\s*[\.\[]`),
	regexp.MustCompile(`\bvim\.cmd\s*\(?\s*[^\s"'\[(]`),
	regexp.MustCompile(`\bvim\.cmd\s*\(\s*[^\s"'\[]`),
	// A tool definition that names its own command: vim.lsp.config/start,
	// nvim-lspconfig setup{cmd=...}, dap adapters, formatter tables.
	// vim.lsp.enable by NAME is deliberately absent: it runs a server the user
	// already configured, from their own runtimepath, not from this repo.
	regexp.MustCompile(`\bvim\.lsp\.(?:start|start_client|rpc)\b`),
	regexp.MustCompile(`\bcmd\s*=`),
	regexp.MustCompile(`\bcommand\s*=`),
	// --- vimscript functions (also reachable as vim.fn.<name>) --------------
	regexp.MustCompile(`\b(?:system|systemlist|job_start|jobstart|term_start|termopen|libcall|libcallnr|writefile|delete|rename|setenv|feedkeys|luaeval|pyeval|py3eval|pyxeval|perleval|rubyeval|execute|exepath|chdir|mkdir|filecopy)\s*\(`),
	// --- ex commands ----------------------------------------------------------
	// Verbs that do something only with an argument ("lua" alone as a word in
	// a filetype table is not a command; "lua os.exit()" is).
	regexp.MustCompile(`(?m)` + vimVerbPrefix + `(?:so(?:urce)?|runt(?:ime)?|luaf(?:ile)?|luado|lua|py(?:thon)?3?|pyx|pyf(?:ile)?|py3f(?:ile)?|pyxf(?:ile)?|pydo|py3do|perl|perldo|rub(?:y)?|rubydo|rubyf(?:ile)?|tcl|tcldo|tclf(?:ile)?|mz(?:scheme)?|exe(?:cute)?|ter(?:minal)?|pa(?:ckadd)?|mak(?:e)?|lmak(?:e)?|cal(?:l)?|norm(?:al)?!?|au(?:tocmd)?!?|com(?:mand)?!?)\s+\S`),
	// Shell escapes and environment/option redirection, which need no
	// whitespace after the verb.
	regexp.MustCompile(`(?m)` + vimVerbPrefix + `(?:!\s*\S|r(?:ead)?\s*!|w(?:rite)?\s*!|let\s+[$&])`),
	regexp.MustCompile(`(?m)` + vimVerbPrefix + `se(?:t)?(?:l(?:ocal)?|g(?:lobal)?)?\s+[^\n]*\b(?:shell\w*|sh|shcf|makeprg|mp|grepprg|gp|keywordprg|kp|formatprg|fp|equalprg|ep|runtimepath|rtp|packpath|pp|exrc|ex|secure|modeline\w*|ml|mle|mls|diffexpr|patchexpr|includeexpr|indentexpr|foldexpr|formatexpr|tagfunc|omnifunc|completefunc|operatorfunc|opfunc|backupdir|directory|undodir|shadafile|viminfofile)\b`),
}

// luaRequire captures the module name of require "x" / require('x').
var luaRequire = regexp.MustCompile(`\brequire\s*\(?\s*\[?\[?["']?([A-Za-z0-9_.\-]+)`)

// rcExecIndex returns the offset of the first execution primitive in an rc
// file, or -1. files is the whole repository, because one primitive depends on
// it: Lua's default package.path begins with "./?.lua", so require("x") in a
// .nvim.lua loads ./x.lua FROM THE REPOSITORY. require of a module the repo
// does not ship resolves from the user's own runtimepath and is not armed.
func rcExecIndex(text string, files map[string]string) int {
	best := -1
	take := func(i int) {
		if i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	for _, re := range rcExecPrimitives {
		if loc := re.FindStringIndex(text); loc != nil {
			take(loc[0])
		}
	}
	for _, m := range luaRequire.FindAllStringSubmatchIndex(text, -1) {
		mod := text[m[2]:m[3]]
		rel := strings.ReplaceAll(mod, ".", "/")
		for _, cand := range []string{rel + ".lua", rel + "/init.lua", rel + ".so", mod + ".lua"} {
			if hasFile(files, cand) {
				take(m[0])
				break
			}
		}
	}
	return best
}

// checkEditorRC reports editor project rc files: EDITOR-003 (critical, fatal)
// when the file can execute something, EDITOR-008 (info) when it cannot.
func checkEditorRC(files map[string]string, add func(code, name string, sev Severity, file, snippet string)) {
	for rel, text := range files {
		c := clean(rel)
		if !editorRCNames[path.Base(c)] || IsArtifact(text) {
			continue
		}
		if text == OmittedContent {
			// Unreadable as text or oversized. Both are exactly what LuaJIT
			// bytecode or a padded payload look like, and an rc has no
			// innocent reason to be either.
			add("EDITOR-003", "editor project rc executes code on open", Critical, rel,
				"(content not supplied: binary or oversized — cannot rule out bytecode)")
			continue
		}
		if i := rcExecIndex(text, files); i >= 0 {
			add("EDITOR-003", "editor project rc executes code on open", Critical, rel,
				lineAround(text, i))
			continue
		}
		add("EDITOR-008", "editor project rc present (no execution primitive)", Medium, rel,
			firstMeaningfulLine(text))
	}
}
