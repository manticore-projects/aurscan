package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newOpenAIServer(t *testing.T, gotAuth *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"OK\",\"confidence\":80,\"summary\":\"ok\",\"findings\":[]}"}}],"usage":{"prompt_tokens":5,"completion_tokens":5}}`))
	}))
}

func TestOpenAISendsAPIKey(t *testing.T) {
	var gotAuth string
	srv := newOpenAIServer(t, &gotAuth)
	defer srv.Close()
	t.Setenv("AURSCAN_OPENAI_URL", srv.URL)
	t.Setenv("AURSCAN_OPENAI_API_KEY", "sk-litellm-secret")
	t.Setenv("OPENAI_API_KEY", "")
	if _, _, err := callOpenAI(context.Background(), 5*time.Second, Backend{}, "sys", "body", 10); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer sk-litellm-secret" {
		t.Fatalf("Authorization = %q, want Bearer sk-litellm-secret", gotAuth)
	}
}

func TestOpenAIFallsBackToOPENAI_API_KEY(t *testing.T) {
	var gotAuth string
	srv := newOpenAIServer(t, &gotAuth)
	defer srv.Close()
	t.Setenv("AURSCAN_OPENAI_URL", srv.URL)
	t.Setenv("AURSCAN_OPENAI_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "sk-fallback")
	if _, _, err := callOpenAI(context.Background(), 5*time.Second, Backend{}, "sys", "body", 10); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer sk-fallback" {
		t.Fatalf("Authorization = %q, want Bearer sk-fallback", gotAuth)
	}
}

func TestOpenAINoKeyNoHeader(t *testing.T) {
	var gotAuth string
	srv := newOpenAIServer(t, &gotAuth)
	defer srv.Close()
	t.Setenv("AURSCAN_OPENAI_URL", srv.URL)
	t.Setenv("AURSCAN_OPENAI_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	if _, _, err := callOpenAI(context.Background(), 5*time.Second, Backend{}, "sys", "body", 10); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization = %q, want empty (open server)", gotAuth)
	}
}
