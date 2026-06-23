package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// setExtraBackends installs config-derived backends for one test and clears them
// afterwards, so no test leaks chain state into another.
func setExtraBackends(t *testing.T, be ...Backend) {
	t.Helper()
	t.Cleanup(func() { ExtraBackends = nil })
	ExtraBackends = be
}

// startStub serves a fixed OpenAI-style response and counts the requests it sees.
func startStub(t *testing.T, status int, body string) (url string, hits *int32) {
	t.Helper()
	var c int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&c, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &c
}

// openAIEnvelope wraps a model "content" string in a valid /chat/completions body.
func openAIEnvelope(content string) string {
	b, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{"message": map[string]string{"content": content}}},
		"usage":   map[string]int{"prompt_tokens": 1, "completion_tokens": 1},
	})
	return string(b)
}

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

// isolateEnv clears every env signal envBackends() looks at, so a test starts
// from an empty environment chain and controls it explicitly.
func isolateEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir()) // no claude/codex on PATH
	t.Setenv("AURSCAN_BACKEND", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AURSCAN_OPENAI_URL", "")
	t.Setenv("AURSCAN_OPENAI_URL_FALLBACK", "")
	t.Setenv("AURSCAN_OPENAI_MODEL", "")
	t.Setenv("AURSCAN_RULES_ONLY", "")
}

var testFiles = Files{"PKGBUILD": "pkgname=x"}

func TestBackendsFromConfig(t *testing.T) {
	got := BackendsFromConfig([]map[string]string{
		{"backend": "openai", "url": "http://x", "model": "m", "api_key": "k"},
		{"backend": "/usr/local/bin/scan"}, // a path => custom command (mirrors AURSCAN_BACKEND=/path)
		{"backend": "claude"},
		{"model": "no-backend"}, // skipped: no backend=
	})
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (%v)", len(got), got)
	}
	if got[0] != (Backend{Kind: "openai", URL: "http://x", Model: "m", APIKey: "k"}) {
		t.Fatalf("entry0 = %v", got[0])
	}
	if got[1] != (Backend{Kind: "cmd", Cmd: "/usr/local/bin/scan"}) {
		t.Fatalf("entry1 = %v", got[1])
	}
	if got[2].Kind != "claude" {
		t.Fatalf("entry2 = %v", got[2])
	}
}

func TestDedupe(t *testing.T) {
	in := []Backend{
		{Kind: "claude"}, {Kind: "claude"},
		{Kind: "openai", URL: "a"}, {Kind: "openai", URL: "b"},
	}
	got := dedupe(in)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (%v)", len(got), got)
	}
}

func TestDedupeEnvVsConfigSameEndpointNotCollapsed(t *testing.T) {
	isolateEnv(t)
	t.Setenv("AURSCAN_OPENAI_URL", "http://x")
	setExtraBackends(t, Backend{Kind: "openai", URL: "http://x"})
	got := Backends()
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (env {openai,URL:\"\"} + config {openai,URL:http://x}); got %v", len(got), got)
	}
	if got[0].URL != "" || got[1].URL != "http://x" {
		t.Fatalf("order/fields wrong: %v", got)
	}
}

func TestChainFallthroughTransportError(t *testing.T) {
	bad, _ := startStub(t, 500, "")
	good, _ := startStub(t, 200, openAIEnvelope(`{"verdict":"OK"}`))
	t.Setenv("AURSCAN_BACKEND", "openai")
	t.Setenv("AURSCAN_OPENAI_URL", bad)
	t.Setenv("AURSCAN_OPENAI_MODEL", "")
	setExtraBackends(t, Backend{Kind: "openai", URL: good})

	res := Scan("pkg", testFiles, Signals{})
	if res.V.Verdict != "OK" || res.Failed {
		t.Fatalf("verdict=%q failed=%v, want OK/false", res.V.Verdict, res.Failed)
	}
}

func TestChainParseFallthrough(t *testing.T) {
	// First backend responds 200 but its content is not verdict JSON.
	bad, _ := startStub(t, 200, openAIEnvelope("hello, not json"))
	good, _ := startStub(t, 200, openAIEnvelope(`{"verdict":"OK"}`))
	t.Setenv("AURSCAN_BACKEND", "openai")
	t.Setenv("AURSCAN_OPENAI_URL", bad)
	t.Setenv("AURSCAN_OPENAI_MODEL", "")
	setExtraBackends(t, Backend{Kind: "openai", URL: good})

	res := Scan("pkg", testFiles, Signals{})
	if res.V.Verdict != "OK" || res.Failed {
		t.Fatalf("verdict=%q failed=%v, want OK/false (parse fall-through)", res.V.Verdict, res.Failed)
	}
}

func TestChainUnknownVerdictFallthrough(t *testing.T) {
	bad, _ := startStub(t, 200, openAIEnvelope(`{"verdict":"maybe"}`))
	good, _ := startStub(t, 200, openAIEnvelope(`{"verdict":"OK"}`))
	t.Setenv("AURSCAN_BACKEND", "openai")
	t.Setenv("AURSCAN_OPENAI_URL", bad)
	t.Setenv("AURSCAN_OPENAI_MODEL", "")
	setExtraBackends(t, Backend{Kind: "openai", URL: good})

	res := Scan("pkg", testFiles, Signals{})
	if res.V.Verdict != "OK" || res.Failed {
		t.Fatalf("verdict=%q failed=%v, want OK/false (unknown-verdict fall-through, NOT a stop at SUSPICIOUS)", res.V.Verdict, res.Failed)
	}
}

func TestGenuineConfidenceZeroStopsChain(t *testing.T) {
	// confidence omitted (=> 0) and summary literally contains "fail-closed";
	// this is still a GENUINE MALICIOUS verdict and must stop the chain.
	first, _ := startStub(t, 200, openAIEnvelope(`{"verdict":"MALICIOUS","summary":"prefer a fail-closed posture"}`))
	second, secondHits := startStub(t, 200, openAIEnvelope(`{"verdict":"OK"}`))
	t.Setenv("AURSCAN_BACKEND", "openai")
	t.Setenv("AURSCAN_OPENAI_URL", first)
	t.Setenv("AURSCAN_OPENAI_MODEL", "")
	setExtraBackends(t, Backend{Kind: "openai", URL: second})

	res := Scan("pkg", testFiles, Signals{})
	if res.V.Verdict != "MALICIOUS" || res.Failed {
		t.Fatalf("verdict=%q failed=%v, want MALICIOUS/false", res.V.Verdict, res.Failed)
	}
	if n := atomic.LoadInt32(secondHits); n != 0 {
		t.Fatalf("second backend was called %d time(s); a genuine verdict must stop the chain", n)
	}
}

func TestCmdFallthrough(t *testing.T) {
	dir := t.TempDir()
	fail := filepath.Join(dir, "fail.sh")
	ok := filepath.Join(dir, "ok.sh")
	if err := os.WriteFile(fail, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ok, []byte("#!/bin/sh\nprintf '{\"verdict\":\"OK\"}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AURSCAN_BACKEND", fail) // pinned path => {Kind:"cmd", Cmd:fail}
	setExtraBackends(t, Backend{Kind: "cmd", Cmd: ok})

	var res Result
	out := captureStderr(t, func() { res = Scan("pkg", testFiles, Signals{}) })
	if res.V.Verdict != "OK" || res.Failed {
		t.Fatalf("verdict=%q failed=%v, want OK/false", res.V.Verdict, res.Failed)
	}
	if !strings.Contains(out, "WARNING: backend cmd "+fail+" failed; trying next") {
		t.Fatalf("expected a cmd-labelled warning, got %q", out)
	}
}

func TestAutoDetectClaudeCodexFallthrough(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "codex"), []byte("#!/bin/sh\nprintf '{\"verdict\":\"OK\",\"confidence\":80}\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// PATH = our dir only, so envBackends() auto-detects exactly [claude, codex].
	t.Setenv("PATH", dir)
	t.Setenv("AURSCAN_BACKEND", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AURSCAN_OPENAI_URL", "")
	t.Setenv("AURSCAN_RULES_ONLY", "")
	setExtraBackends(t) // none

	var res Result
	_ = captureStderr(t, func() { res = Scan("pkg", testFiles, Signals{}) })
	if res.V.Verdict != "OK" || res.Failed {
		t.Fatalf("verdict=%q failed=%v, want OK/false (claude→codex auto fallback)", res.V.Verdict, res.Failed)
	}
}

func TestCallOpenAIPrefersSpecURLOverEnv(t *testing.T) {
	env500, _ := startStub(t, 500, "")
	spec, n := startStub(t, 200, openAIEnvelope(`{"verdict":"OK"}`))
	t.Setenv("AURSCAN_OPENAI_URL", env500)
	text, _, err := callOpenAI(context.Background(), time.Second, Backend{Kind: "openai", URL: spec}, "sys", "user", 1)
	if err != nil {
		t.Fatalf("callOpenAI: %v", err)
	}
	if !strings.Contains(text, `"verdict":"OK"`) {
		t.Fatalf("content = %q, want the spec-URL response", text)
	}
	if got := atomic.LoadInt32(n); got != 1 {
		t.Fatalf("spec URL called %d time(s), want 1", got)
	}
}

func TestEnvBackendsLeaveModelEmpty(t *testing.T) {
	isolateEnv(t)
	t.Setenv("ANTHROPIC_API_KEY", "key")
	t.Setenv("AURSCAN_OPENAI_URL", "http://x")
	t.Setenv("AURSCAN_MODEL", "api-x")
	t.Setenv("AURSCAN_CODEX_MODEL", "codex-x")
	t.Setenv("AURSCAN_OPENAI_MODEL", "oai-x")

	got := envBackends()
	if len(got) == 0 {
		t.Fatal("expected at least the api and openai env backends")
	}
	for _, be := range got {
		if be.Model != "" || be.URL != "" || be.APIKey != "" || be.Fallback != "" {
			t.Fatalf("env backend %v has non-empty settings; must stay empty so callX reads env", be)
		}
	}
}

func TestSecretNeverLeaksToStderr(t *testing.T) {
	Debug = true
	t.Cleanup(func() { Debug = false })
	isolateEnv(t)
	stub, _ := startStub(t, 200, openAIEnvelope(`{"verdict":"OK"}`))
	setExtraBackends(t, Backend{Kind: "openai", URL: stub, APIKey: "SENTINEL_SECRET_KEY"})

	out := captureStderr(t, func() { Scan("pkg", testFiles, Signals{}) })
	if strings.Contains(out, "SENTINEL_SECRET_KEY") {
		t.Fatalf("api key leaked to stderr:\n%s", out)
	}
	if !strings.Contains(out, "hasKey:yes") {
		t.Fatalf("expected redacted Backend.String() in chain debug line, got:\n%s", out)
	}
}

func TestChainExhausted(t *testing.T) {
	a, _ := startStub(t, 500, "")
	b, _ := startStub(t, 500, "")
	t.Setenv("AURSCAN_BACKEND", "openai")
	t.Setenv("AURSCAN_OPENAI_URL", a)
	t.Setenv("AURSCAN_OPENAI_MODEL", "")
	setExtraBackends(t, Backend{Kind: "openai", URL: b})

	res := Scan("pkg", testFiles, Signals{})
	if !res.Failed || res.V.Verdict != "SUSPICIOUS" {
		t.Fatalf("verdict=%q failed=%v, want SUSPICIOUS/true (chain exhausted, fail-closed)", res.V.Verdict, res.Failed)
	}
}

func TestSingleBackendFailureSilentOnStderr(t *testing.T) {
	isolateEnv(t)
	bad, _ := startStub(t, 500, "")
	t.Setenv("AURSCAN_BACKEND", "openai")
	t.Setenv("AURSCAN_OPENAI_URL", bad)
	setExtraBackends(t) // single-backend chain: no "next"

	var res Result
	out := captureStderr(t, func() { res = Scan("pkg", testFiles, Signals{}) })
	if !res.Failed || res.V.Verdict != "SUSPICIOUS" {
		t.Fatalf("verdict=%q failed=%v, want SUSPICIOUS/true", res.V.Verdict, res.Failed)
	}
	if strings.Contains(out, "WARNING:") {
		t.Fatalf("a lone backend failing must not print a 'trying next' warning, got %q", out)
	}
}
