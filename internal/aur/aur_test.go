package aur

import (
	"errors"
	"net/http"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestScanRecursiveDisabledSkipsNetwork(t *testing.T) {
	t.Setenv("AURSCAN_DISABLE", "1")

	called := false
	oldTransport := client.Transport
	client.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected network request")
	})
	t.Cleanup(func() { client.Transport = oldTransport })

	results := ScanRecursive([]string{"example"}, nil)
	if called {
		t.Fatal("AUR request made while scanning is disabled")
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if got := results[0].V.Verdict; got != "SKIPPED" {
		t.Fatalf("verdict = %q, want SKIPPED", got)
	}
}
