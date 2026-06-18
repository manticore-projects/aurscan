package yay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallParuHookIdempotent(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "paru.conf")
	os.WriteFile(conf, []byte("[options]\nBottomUp\n"), 0o644)
	t.Setenv("PARU_CONF", conf)

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
