package rules

// File-identity rules: EDITOR-00x and MASQ-00x.
//
// Every other rule in this package asks what the package's scripts DO when
// makepkg or pacman runs them. These two ask a different question: what happens
// to the person who merely LOOKS at the package.
//
// That person is the one aurscan exists for. The AUR review workflow is
// literally "paru drops you into $EDITOR on the PKGBUILD before you decide", so
// a repository that executes code on directory entry or project open reaches the
// careful user first and the careless one never. Nothing in the checklist
// covered it, because nothing in the checklist was about the repository as a
// directory rather than as a build recipe.
//
// Scope note. These fire on files in the AUR REPOSITORY — the snapshot tarball
// or the local build directory. They deliberately do NOT try to analyse an
// upstream source tree fetched by source=(): that is an unbounded amount of
// third-party code per package and a different tool's job. The reported
// glance-linux sample would therefore not be caught by MASQ-001 through
// aurscan, and should not be claimed as such; what MASQ-001 catches is the same
// technique carried in the AUR repo itself.

import (
	"path"
	"regexp"
	"strings"
)

// editorTrigger describes one file whose mere presence, or whose presence in an
// armed form, causes a command to run when a directory is entered or a project
// is opened.
type editorTrigger struct {
	code string
	name string
	// match reports whether this trigger applies to the given repo-relative
	// path. Paths are matched case-sensitively: these names are fixed by the
	// tools that read them.
	match func(rel, base string) bool
	// armed, when non-nil, is a further test on the file's content. When nil,
	// presence alone is the finding.
	armed *regexp.Regexp
}

// vscodeFolderOpen matches a tasks.json task configured to run when the folder
// is opened. This is the form used by the EtherHiding loader reported in
// September 2026: a task labelled after a linter, hidden, output suppressed,
// runOn folderOpen, executing a file disguised as a font.
var vscodeFolderOpen = regexp.MustCompile(`(?is)"runOn"\s*:\s*"folderOpen"`)

// devcontainerHook matches the devcontainer lifecycle properties that execute a
// command when the container is created or started.
var devcontainerHook = regexp.MustCompile(
	`(?is)"(initializeCommand|onCreateCommand|updateContentCommand|postCreateCommand|postStartCommand|postAttachCommand)"\s*:`)

// vscodeExecHijack matches settings.json keys that do not themselves run a
// command but decide WHICH binary a later invocation runs, or what environment
// it runs in. Both redirect execution without looking like execution.
var vscodeExecHijack = regexp.MustCompile(
	`(?is)"(terminal\.integrated\.env\.[a-z]+|terminal\.integrated\.(profiles|automationProfile)\.[a-z]+|[a-z0-9.\-]*\.(executablePath|serverPath|interpreterPath|defaultInterpreterPath|pythonPath|cargoPath|goroot|toolsGopath))"\s*:`)

// ideaAutoRun matches an IDEA/JetBrains run configuration marked to start on
// its own rather than on an explicit user action.
var ideaAutoRun = regexp.MustCompile(`(?is)(activateToolWindowBeforeRun|RunOnceActivity|<option\s+name="autoStart"\s+value="true")`)

// editorTriggers is the catalog of directory-entry and project-open execution
// vectors. An AUR repository contains build scripts. It has no editor project,
// no dev container and no direnv environment, so none of these has a benign form
// here — which is why the armed ones are fatal (see fatalCodes).
var editorTriggers = []editorTrigger{
	{
		code: "EDITOR-001",
		name: "VS Code task runs on folder open",
		match: func(rel, base string) bool {
			return rel == ".vscode/tasks.json" || base == "tasks.json" && strings.Contains(rel, ".vscode/")
		},
		armed: vscodeFolderOpen,
	},
	{
		// direnv executes .envrc on cd into the directory. No project open, no
		// editor, no confirmation beyond a one-time `direnv allow` that many
		// people have configured away.
		code:  "EDITOR-002",
		name:  "direnv .envrc executes on directory entry",
		match: func(rel, base string) bool { return base == ".envrc" },
	},
	{
		// exrc/nvim.lua are read on startup in the directory for anyone who has
		// enabled 'exrc'. Arbitrary vimscript or Lua, no prompt.
		code: "EDITOR-003",
		name: "editor project rc executes on open",
		match: func(rel, base string) bool {
			switch base {
			case ".exrc", ".nvim.lua", ".nvimrc", ".lvimrc", ".vimrc", ".editorconfig-lua":
				return true
			}
			return false
		},
	},
	{
		code: "EDITOR-004",
		name: "devcontainer lifecycle command",
		match: func(rel, base string) bool {
			return base == "devcontainer.json" || strings.Contains(rel, ".devcontainer/")
		},
		armed: devcontainerHook,
	},
	{
		code: "EDITOR-005",
		name: "JetBrains run configuration starts automatically",
		match: func(rel, base string) bool {
			return strings.Contains(rel, ".idea/runConfigurations/") || rel == ".idea/workspace.xml"
		},
		armed: ideaAutoRun,
	},
	{
		code: "EDITOR-006",
		name: "VS Code setting redirects an executable or terminal environment",
		match: func(rel, base string) bool {
			return rel == ".vscode/settings.json" || base == "settings.json" && strings.Contains(rel, ".vscode/")
		},
		armed: vscodeExecHijack,
	},
	{
		// tasks.json that is NOT folderOpen-armed still has no business in an
		// AUR repository, and a task is one keystroke from running. Reported,
		// but as a warning: nothing executes on its own.
		code: "EDITOR-007",
		name: "VS Code task definitions present in an AUR repository",
		match: func(rel, base string) bool {
			return rel == ".vscode/tasks.json" || base == "tasks.json" && strings.Contains(rel, ".vscode/")
		},
	},
}

// editorTriggerSeverity: armed triggers are critical, the bare-presence
// observations are not. EDITOR-007 is the unarmed twin of EDITOR-001 and fires
// alongside it; dedupeEditorHits drops it when the armed form was found.
var editorTriggerWarning = map[string]bool{"EDITOR-007": true}

// checkEditorTriggers reports files that cause execution on directory entry or
// project open. It runs over the whole file set, including files whose content
// the collector omitted: for the presence-only triggers the NAME is the finding,
// and an omitted .envrc is still an .envrc.
func checkEditorTriggers(files map[string]string, add func(code, name string, sev Severity, file, snippet string)) {
	armedFound := map[string]bool{}
	for _, t := range editorTriggers {
		if t.armed == nil {
			continue
		}
		for rel, text := range files {
			if IsOmitted(text) || !t.match(clean(rel), path.Base(clean(rel))) {
				continue
			}
			if idx := t.armed.FindStringIndex(text); idx != nil {
				armedFound[rel] = true
				add(t.code, t.name, Critical, rel, lineAround(text, idx[0]))
			}
		}
	}
	for _, t := range editorTriggers {
		for rel, text := range files {
			c := clean(rel)
			if !t.match(c, path.Base(c)) {
				continue
			}
			if t.armed != nil {
				continue // handled above
			}
			// The unarmed twin is noise once the armed form was reported.
			if editorTriggerWarning[t.code] && armedFound[rel] {
				continue
			}
			sev := Critical
			if editorTriggerWarning[t.code] {
				sev = High
			}
			add(t.code, t.name, sev, rel, firstMeaningfulLine(text))
		}
	}
}

// clean normalises a repo-relative path for matching: forward slashes, no
// leading "./".
func clean(rel string) string {
	return strings.TrimPrefix(strings.ReplaceAll(rel, "\\", "/"), "./")
}

// ---------------------------------------------------------------------------
// MASQ-001 / MASQ-002: a file whose extension claims a binary format and whose
// contents are text.
//
// The narrow form is the attack: a name ending .woff2 / .png / .so holding a
// script. That is not a naming irregularity, it is a file placed where nobody
// opens it in order to be executed by something that does.
//
// The broad form — any extension/content mismatch — was deliberately NOT
// implemented as a single rule, for two reasons:
//
//   - Binary-vs-binary mismatch is normal and frequently correct. A modern .ico
//     CONTAINS PNG data; .ttf and .otf are both sfnt containers; a renamed .jpg
//     that is really a PNG is untidy, not hostile. Flagging those would make the
//     critical tier mean "some file naming irregularity", and the next time it
//     fired on a real loader it would read as more of the same.
//   - It is out of reach anyway. The collectors replace non-text file content
//     with a placeholder, so the bytes needed to identify the actual format are
//     never in the file set. A rule for it would be untestable against real
//     input.
//
// So MASQ-001 is text-that-is-script in a binary-named file (critical, fatal)
// and MASQ-002 is text-that-is-not-script in a binary-named file (warning:
// covers git-lfs pointers and stray README content, which are sloppy rather
// than dangerous). Promoting MASQ-002 is a one-word change if you want it.

// binaryExtensions are suffixes whose format is defined by magic bytes. A file
// carrying one of these names and holding text is not that format.
//
// Deliberately absent: .svg (XML text by definition), .eps and .ps (text
// PostScript), .pdf (text header, and LaTeX packages ship generated ones),
// .ico (a modern .ico legitimately contains PNG data, and this rule is not
// about which binary format it is).
var binaryExtensions = map[string]bool{
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".bmp": true, ".tiff": true, ".tif": true, ".avif": true,
	".zip": true, ".gz": true, ".xz": true, ".bz2": true, ".zst": true,
	".7z": true, ".rar": true, ".lz4": true, ".lzma": true,
	".so": true, ".dylib": true, ".dll": true, ".exe": true, ".bin": true,
	".o": true, ".a": true, ".class": true, ".jar": true, ".pyc": true,
	".wasm": true, ".mo": true,
	".mp3": true, ".mp4": true, ".wav": true, ".ogg": true, ".webm": true,
	".flac": true, ".opus": true,
}

// scriptMarkers identify text that is executable code rather than prose. The
// shebang and the shell parse are the strong signals; the language markers
// cover the obfuscated-JavaScript case, where the whole file is one line and
// there is no shebang because the caller supplies the interpreter.
var scriptMarkers = []*regexp.Regexp{
	regexp.MustCompile(`(?m)\A\s*#!`),
	regexp.MustCompile(`(?s)\brequire\s*\(\s*['"]`),
	regexp.MustCompile(`(?s)\bmodule\.exports\b`),
	regexp.MustCompile(`(?s)\bprocess\.(env|argv|exit|platform)\b`),
	regexp.MustCompile(`(?s)\bchild_process\b`),
	regexp.MustCompile(`(?s)\b(eval|Function)\s*\(`),
	regexp.MustCompile(`(?s)\bfunction\s*\**\s*[A-Za-z_$]*\s*\(`),
	regexp.MustCompile(`(?s)=>\s*\{`),
	regexp.MustCompile(`(?s)\bimport\s+[A-Za-z_{*][^\n;]{0,80}\bfrom\s+['"]`),
	regexp.MustCompile(`(?m)^\s*(def|class)\s+[A-Za-z_]\w*\s*[(:]`),
	regexp.MustCompile(`(?s)\b__import__\s*\(`),
	regexp.MustCompile(`(?s)\bsubprocess\.(run|Popen|call)\b`),
	// Shell payloads invoked by an external interpreter ("sh ./x.png") carry no
	// shebang, so match the shapes a payload actually uses rather than trying to
	// decide whether arbitrary text is shell.
	regexp.MustCompile(`(?is)\b(curl|wget)\s+-[a-z]*\s*https?://`),
	regexp.MustCompile(`(?is)\|\s*(ba|z|k|da)?sh\b`),
	regexp.MustCompile(`(?is)\bchmod\s+\+x\b`),
	regexp.MustCompile(`(?is)\bbase64\s+-{1,2}d`),
}

// leadingPad matches the long run of whitespace the reported loader used so a
// glance at the first bytes of the file showed nothing. It is corroboration
// recorded in the snippet, never the trigger on its own — leading whitespace is
// not by itself evidence of anything.
var leadingPad = regexp.MustCompile(`\A[ \t]{64,}\S`)

// checkMasqueradedTypes reports files whose extension claims a binary format
// while their contents are text.
func checkMasqueradedTypes(files map[string]string, add func(code, name string, sev Severity, file, snippet string)) {
	for rel, text := range files {
		// An omitted file is one the collector could not read as text, which is
		// exactly what a genuine binary looks like. No finding.
		if IsOmitted(text) || strings.TrimSpace(text) == "" {
			continue
		}
		if !claimsBinaryFormat(clean(rel)) {
			continue
		}
		snippet := firstMeaningfulLine(text)
		if leadingPad.MatchString(text) {
			snippet = "(content begins after a long run of spaces) " + snippet
		}
		if isScriptText(text) {
			add("MASQ-001", "file named as a binary format contains executable script",
				Critical, rel, snippet)
			continue
		}
		add("MASQ-002", "file named as a binary format contains text",
			High, rel, snippet)
	}
}

// versionedSuffix matches the trailing soname/version components a library
// carries: libz.so.1, libfoo.so.1.2.3. path.Ext on those returns ".1", so the
// binary claim would be missed without stripping them first.
var versionedSuffix = regexp.MustCompile(`(\.\d+)+$`)

// claimsBinaryFormat reports whether a repo-relative path names a format whose
// identity is defined by magic bytes.
func claimsBinaryFormat(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	base = versionedSuffix.ReplaceAllString(base, "")
	return binaryExtensions[path.Ext(base)]
}

// isScriptText reports whether text is executable code. A successful shell
// parse that yields at least one command counts, which reuses the same
// deobfuscating parser the command-scoped rules use.
// isScriptText reports whether text is executable code.
//
// An earlier draft treated "mvdan.cc/sh parses it and yields a command" as the
// shell test. That is far too loose to be a CRITICAL trigger: a git-lfs pointer
// file parses cleanly as three commands, because almost any run of words does.
// A test whose positive answer is "this text contains words" cannot carry a
// non-overridable verdict. So the shell case is covered by the shebang and by
// the specific shapes a payload uses, above, and prose behind a binary name
// falls through to MASQ-002 where it belongs.
func isScriptText(text string) bool {
	for _, re := range scriptMarkers {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// firstMeaningfulLine returns a short, printable excerpt for the evidence
// column: the first non-blank line, truncated. A masqueraded loader is often a
// single 200 KB line, so truncation is the normal case rather than the
// exception.
func firstMeaningfulLine(text string) string {
	const max = 120
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if len(t) > max {
			return t[:max] + "…"
		}
		return t
	}
	return ""
}
