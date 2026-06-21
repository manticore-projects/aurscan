package yay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallYayHookPreservesAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	conf := filepath.Join(dir, "yay", "init.lua")
	os.MkdirAll(filepath.Dir(conf), 0o755)
	os.WriteFile(conf, []byte("yay.opt.bottom_up = true\n"), 0o644)

	for i := 0; i < 2; i++ {
		if _, _, err := InstallYayHook(); err != nil {
			t.Fatalf("install %d: %v", i, err)
		}
	}
	data, _ := os.ReadFile(conf)
	s := string(data)
	if !strings.Contains(s, "yay.opt.bottom_up = true") {
		t.Fatal("user config was lost")
	}
	if n := strings.Count(s, "AURPostDownload"); n != 1 {
		t.Fatalf("hook registered %d times, want 1", n)
	}
	if n := strings.Count(s, yayHookBegin); n != 1 {
		t.Fatalf("managed block present %d times, want 1", n)
	}

	_, changed, err := UninstallYayHook()
	if err != nil || !changed {
		t.Fatalf("uninstall: changed=%v err=%v", changed, err)
	}
	data, _ = os.ReadFile(conf)
	s = string(data)
	if strings.Contains(s, "AURPostDownload") || strings.Contains(s, yayHookBegin) {
		t.Fatal("managed block not fully removed")
	}
	if !strings.Contains(s, "yay.opt.bottom_up = true") {
		t.Fatal("uninstall clobbered user config")
	}
}

func TestUninstallRemovesEmptyFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if _, _, err := InstallYayHook(); err != nil { // no prior init.lua
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "yay", "init.lua")
	if _, err := os.Stat(conf); err != nil {
		t.Fatalf("init.lua not created: %v", err)
	}
	if _, changed, err := UninstallYayHook(); err != nil || !changed {
		t.Fatalf("uninstall: %v changed=%v", err, changed)
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Fatal("init.lua should be removed when it held only our block")
	}
}

func TestYayMajorParsing(t *testing.T) {
	cases := map[string]int{
		"yay v13.0.0 - libalpm v15.0.0\n": 13,
		"yay v12.5.7 - libalpm v15\n":     12,
		"v13.1.2":                         13,
		"garbage":                         0,
	}
	for out, want := range cases {
		yayVersionCmd = func() (string, error) { return out, nil }
		if got := yayMajor(); got != want {
			t.Errorf("yayMajor(%q)=%d want %d", out, got, want)
		}
	}
}

func TestHookLuaContainsPrebuild(t *testing.T) {
	lua := yayHookLua("/usr/local/bin/aurscan")
	for _, want := range []string{"AURPostDownload", "--prebuild", "yay.abort", "event.data.dir", "os.execute"} {
		if !strings.Contains(lua, want) {
			t.Errorf("generated Lua missing %q", want)
		}
	}
}

func TestDetectWrapperAlias(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	// nothing set yet
	if p, found := DetectWrapperAlias("yay", "syay"); found {
		t.Fatalf("unexpected match at %s", p)
	}

	// fish funcsave style: ~/.config/fish/functions/yay.fish referencing syay
	fishFn := filepath.Join(home, ".config", "fish", "functions", "yay.fish")
	os.MkdirAll(filepath.Dir(fishFn), 0o755)
	os.WriteFile(fishFn, []byte("function yay\n    syay $argv\nend\n"), 0o644)
	if p, found := DetectWrapperAlias("yay", "syay"); !found {
		t.Fatal("expected fish function match")
	} else if p != fishFn {
		t.Fatalf("matched %s, want %s", p, fishFn)
	}

	// bashrc style for paru
	bashrc := filepath.Join(home, ".bashrc")
	os.WriteFile(bashrc, []byte("alias paru=sparu\n"), 0o644)
	if _, found := DetectWrapperAlias("paru", "sparu"); !found {
		t.Fatal("expected bashrc alias match")
	}

	// must not false-match a substring (e.g. 'syayly') — word-boundary check
	os.WriteFile(bashrc, []byte("alias foo=syayly\n"), 0o644)
	os.Remove(fishFn)
	if p, found := DetectWrapperAlias("yay", "syay"); found {
		t.Fatalf("substring should not match (%s)", p)
	}
}
