package scan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
