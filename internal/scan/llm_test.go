package scan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func startOpenAIStub(t *testing.T) (url string, bodyCh chan []byte) {
	t.Helper()
	bodyCh = make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodyCh <- raw
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"OK\"}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, bodyCh
}

func requestModel(t *testing.T, raw []byte) (string, bool) {
	t.Helper()
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal request body: %v\n%s", err, raw)
	}
	m, ok := got["model"]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(m, &s); err != nil {
		t.Fatalf("unmarshal model field: %v", err)
	}
	return s, true
}

func TestCallOpenAIModelOmittedWhenEnvUnset(t *testing.T) {
	os.Unsetenv("AURSCAN_OPENAI_MODEL")
	url, bodyCh := startOpenAIStub(t)
	t.Setenv("AURSCAN_OPENAI_URL", url)
	if _, _, err := callOpenAI(context.Background(), time.Second, Backend{}, "sys", "user", 1); err != nil {
		t.Fatalf("callOpenAI: %v", err)
	}
	if model, ok := requestModel(t, <-bodyCh); ok {
		t.Fatalf("request sent model=%q; expected the field to be omitted", model)
	}
}

func TestCallOpenAIModelForwardedWhenEnvSet(t *testing.T) {
	const want = "z-ai/glm-5.1"
	t.Setenv("AURSCAN_OPENAI_MODEL", want)
	url, bodyCh := startOpenAIStub(t)
	t.Setenv("AURSCAN_OPENAI_URL", url)
	if _, _, err := callOpenAI(context.Background(), time.Second, Backend{}, "sys", "user", 1); err != nil {
		t.Fatalf("callOpenAI: %v", err)
	}
	if model, ok := requestModel(t, <-bodyCh); !ok || model != want {
		t.Fatalf("request model = %q ok=%v; want %q", model, ok, want)
	}
}

func TestLastNKeepsCodexTailError(t *testing.T) {
	// codex v0.160.1 prints a ~300-byte banner to stderr before the real
	// failure; firstN hides the cause, lastN must keep it. The banner plus the
	// echoed prompt/stdin easily exceed 300 bytes in a real scan.
	banner := "Reading additional input from stdin...\nOpenAI Codex v0.160.1\n--------\nworkdir: /tmp\nmodel: gpt-5.6-luna\nprovider: openai\napproval: never\nsandbox: read-only\nreasoning effort: medium\nreasoning summaries: none\nsession id: abc\n--------\nuser\nSay hi\n\n<stdin>\n" + strings.Repeat("pkg-content\n", 40) + "</stdin>\n"
	cause := "ERROR: You've hit your usage limit. Upgrade to Pro"
	stderr := banner + cause
	if got := firstN(stderr, 300); strings.Contains(got, "ERROR") {
		t.Fatalf("firstN unexpectedly contains ERROR; test needs a longer banner: %q", got)
	}
	if got := lastN(stderr, 500); !strings.Contains(got, "ERROR") {
		t.Fatalf("lastN dropped the tail error: %q", got)
	}
}
