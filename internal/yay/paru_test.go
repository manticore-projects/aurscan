package yay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallParuHookIdempotent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("PARU_CONF", "")
	conf := filepath.Join(dir, "paru", "paru.conf")
	os.MkdirAll(filepath.Dir(conf), 0o755)
	os.WriteFile(conf, []byte("[options]\nBottomUp\n"), 0o644)

	for i := 0; i < 2; i++ {
		if _, err := InstallParuHook(); err != nil {
			t.Fatalf("install %d: %v", i, err)
		}
	}
	data, _ := os.ReadFile(conf)
	if n := strings.Count(string(data), "PreBuildCommand"); n != 1 {
		t.Fatalf("PreBuildCommand appears %d times, want 1", n)
	}
	if !strings.Contains(string(data), "BottomUp") {
		t.Fatal("user setting BottomUp was lost")
	}

	_, changed, err := UninstallParuHook()
	if err != nil || !changed {
		t.Fatalf("uninstall: changed=%v err=%v", changed, err)
	}
	data, _ = os.ReadFile(conf)
	if strings.Contains(string(data), "PreBuildCommand") {
		t.Fatal("PreBuildCommand not removed")
	}
	if !strings.Contains(string(data), "BottomUp") {
		t.Fatal("uninstall clobbered user setting")
	}
}

func TestInstallParuHookPreservesSystemConfigViaInclude(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("PARU_CONF", "")
	sysConf := filepath.Join(dir, "etc-paru.conf")
	os.WriteFile(sysConf, []byte("[options]\nBottomUp\n"), 0o644)
	old := systemParuConf
	systemParuConf = sysConf
	defer func() { systemParuConf = old }()

	path, err := InstallParuHook()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	s := string(data)
	if !strings.Contains(s, "PreBuildCommand") {
		t.Fatal("hook not written")
	}
	// Hermetic: point systemParuConf at a temp file so the Include branch runs.
	if !strings.Contains(s, "Include = "+sysConf) {
		t.Fatalf("system config not preserved via Include:\n%s", s)
	}
	// Idempotent.
	if _, err := InstallParuHook(); err != nil {
		t.Fatal(err)
	}
	data2, _ := os.ReadFile(path)
	if strings.Count(string(data2), "PreBuildCommand") != 1 {
		t.Fatal("hook duplicated on second install")
	}
}
