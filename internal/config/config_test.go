package config

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConf writes a file into the (temp) config dir for a test.
func writeConf(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// captureStderr runs fn with os.Stderr redirected and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	os.Stderr = old
	return <-done
}

func TestLLMConfigsNumericOrder(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AURSCAN_CONFIG_DIR", dir)
	writeConf(t, dir, "llm10.conf", "backend = openai\nurl = http://ten")
	writeConf(t, dir, "llm2.conf", "backend = codex")
	writeConf(t, dir, "llm1.conf", "backend = claude")

	got := LLMConfigs()
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (%v)", len(got), got)
	}
	want := []string{"claude", "codex", "openai"} // 1, 2, 10 — numeric, not lexical
	for i, w := range want {
		if got[i]["backend"] != w {
			t.Fatalf("entry %d backend = %q, want %q (order: %v)", i, got[i]["backend"], w, got)
		}
	}
	if got[2]["url"] != "http://ten" {
		t.Fatalf("llm10 url = %q", got[2]["url"])
	}
}

func TestLLMConfigsParsingEdgeCases(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AURSCAN_CONFIG_DIR", dir)
	// BOM on the first line; comments; blank line; CRLF; '=' in value; quoted
	// literal; inline '#' kept verbatim; duplicate key (last wins); empty value.
	body := "\ufeffbackend = openai\r\n" +
		"# a comment\n" +
		"; another comment\n" +
		"\n" +
		"url = http://x # primary\r\n" +
		"api_key = sk-a=b\n" +
		"model = \"q-1\"\n" +
		"model = q-2\n" +
		"fallback =\n"
	writeConf(t, dir, "llm1.conf", body)

	got := LLMConfigs()
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	m := got[0]
	checks := map[string]string{
		"backend": "openai",
		"url":     "http://x # primary", // inline comment NOT stripped
		"api_key": "sk-a=b",             // only the first '=' splits
		"model":   "q-2",                // duplicate: last wins; quotes are literal on the first, overwritten
	}
	for k, want := range checks {
		if m[k] != want {
			t.Fatalf("key %q = %q, want %q", k, m[k], want)
		}
	}
	if _, ok := m["fallback"]; ok {
		t.Fatalf("empty value should not be stored, got fallback=%q", m["fallback"])
	}
}

func TestLLMConfigsQuotedValueLiteral(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AURSCAN_CONFIG_DIR", dir)
	writeConf(t, dir, "llm1.conf", "backend = openai\napi_key = \"sk-1\"")
	m := LLMConfigs()[0]
	if m["api_key"] != "\"sk-1\"" {
		t.Fatalf("api_key = %q, want the quotes preserved verbatim", m["api_key"])
	}
}

func TestLLMConfigsMissingDir(t *testing.T) {
	t.Setenv("AURSCAN_CONFIG_DIR", filepath.Join(t.TempDir(), "does-not-exist"))
	if got := LLMConfigs(); got != nil {
		t.Fatalf("want nil for missing dir, got %v", got)
	}
}

func TestLLMConfigsSkipsUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0000 is still readable")
	}
	dir := t.TempDir()
	t.Setenv("AURSCAN_CONFIG_DIR", dir)
	bad := writeConf(t, dir, "llm1.conf", "backend = openai")
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })
	writeConf(t, dir, "llm2.conf", "backend = codex")

	got := LLMConfigs()
	if len(got) != 1 || got[0]["backend"] != "codex" {
		t.Fatalf("want exactly the readable codex entry, got %v", got)
	}
}

func TestLLMConfigsAPIKeyPermissionWarning(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AURSCAN_CONFIG_DIR", dir)
	p := writeConf(t, dir, "llm1.conf", "backend = openai\napi_key = sk-test")
	if err := os.Chmod(p, 0o644); err != nil { // group/other-readable
		t.Fatalf("chmod: %v", err)
	}
	out := captureStderr(t, func() { LLMConfigs() })
	if !strings.Contains(out, "chmod 600") || !strings.Contains(out, "api_key") {
		t.Fatalf("expected a chmod-600 warning, got %q", out)
	}

	// 0600 → no warning.
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	out = captureStderr(t, func() { LLMConfigs() })
	if strings.Contains(out, "chmod 600") {
		t.Fatalf("did not expect a warning for a 0600 file, got %q", out)
	}
}

func TestLLMConfigsNoSecretNoWarning(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AURSCAN_CONFIG_DIR", dir)
	p := writeConf(t, dir, "llm1.conf", "backend = openai\nurl = http://x")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	out := captureStderr(t, func() { LLMConfigs() })
	if strings.Contains(out, "chmod 600") {
		t.Fatalf("a file without api_key must never warn, got %q", out)
	}
}
