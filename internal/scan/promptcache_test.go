package scan

import (
	"encoding/json"
	"strings"
	"testing"
)

// The system prompt is ~4,200 tokens and byte-identical on every call, while
// the user message is a different package each time. That is exactly the shape
// prompt caching is for — and exactly the shape that falls into the documented
// automatic-caching trap, since the LAST cacheable block is the package files.
func TestSystemPromptIsTheCacheBreakpoint(t *testing.T) {
	if len(Instructions) < 4096 {
		t.Errorf("Instructions is %d chars; below the minimum cacheable prompt length "+
			"the breakpoint is silently ignored", len(Instructions))
	}
}

func TestPromptCacheControl(t *testing.T) {
	t.Run("default 5m", func(t *testing.T) {
		t.Setenv("AURSCAN_PROMPT_CACHE_TTL", "")
		cc := promptCacheControl()
		if cc["type"] != "ephemeral" {
			t.Errorf("type = %q", cc["type"])
		}
		if _, ok := cc["ttl"]; ok {
			t.Error("the 5-minute default must not send an explicit ttl")
		}
	})
	t.Run("1h opt-in", func(t *testing.T) {
		t.Setenv("AURSCAN_PROMPT_CACHE_TTL", "1h")
		if promptCacheControl()["ttl"] != "1h" {
			t.Error("AURSCAN_PROMPT_CACHE_TTL=1h should request the hour cache")
		}
	})
	t.Run("opt-out", func(t *testing.T) {
		t.Setenv("AURSCAN_PROMPT_CACHE", "0")
		if promptCacheEnabled() {
			t.Error("AURSCAN_PROMPT_CACHE=0 must disable the breakpoint")
		}
	})
	t.Run("enabled by default", func(t *testing.T) {
		t.Setenv("AURSCAN_PROMPT_CACHE", "")
		if !promptCacheEnabled() {
			t.Error("caching should be on by default")
		}
	})
}

// input_tokens counts only what FOLLOWS the last cache breakpoint. Reporting it
// alone would understate a cached scan by about 70% and make the cost look far
// better than it is.
func TestCachedUsageAccounting(t *testing.T) {
	u := priceUsage(Usage{In: 1900, CacheRead: 4200, Out: 600}, "claude-sonnet-4-6")
	if !u.HaveCost {
		t.Fatal("expected a known price")
	}
	// 1900 @ $3/MTok + 4200 @ $0.30/MTok + 600 @ $15/MTok
	want := 1900.0/1e6*3 + 4200.0/1e6*0.30 + 600.0/1e6*15
	if diff := u.CostUSD - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("cost = %v, want %v — cache reads bill at 10%% of base input", u.CostUSD, want)
	}
	if s := u.String(); !strings.Contains(s, "6,100 in") || !strings.Contains(s, "4,200 cached") {
		t.Errorf("usage line must show the true total and the cached share: %q", s)
	}
}

// A write costs 25% more than plain input, so an isolated scan is marginally
// worse off. The accounting has to reflect that rather than quietly ignoring it.
func TestCacheWriteCostsMore(t *testing.T) {
	warm := priceUsage(Usage{In: 1900, CacheRead: 4200, Out: 600}, "claude-sonnet-4-6")
	cold := priceUsage(Usage{In: 1900, CacheWrite: 4200, Out: 600}, "claude-sonnet-4-6")
	plain := priceUsage(Usage{In: 6100, Out: 600}, "claude-sonnet-4-6")
	if !(warm.CostUSD < plain.CostUSD) {
		t.Error("a cache hit must be cheaper than an uncached scan")
	}
	if !(cold.CostUSD > plain.CostUSD) {
		t.Error("a cache write must be dearer than an uncached scan; it is the price of the first call")
	}
}

// The request must carry the breakpoint on the system block, not at the top
// level: automatic caching would place it on the package files, which differ
// every request, so the prefix hash would never match.
func TestRequestShapeHasSystemBreakpoint(t *testing.T) {
	sysBlock := map[string]any{"type": "text", "text": "SYS"}
	sysBlock["cache_control"] = promptCacheControl()
	body, err := json.Marshal(map[string]any{
		"system":   []map[string]any{sysBlock},
		"messages": []map[string]string{{"role": "user", "content": "PKG"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		System []struct {
			CacheControl map[string]string `json:"cache_control"`
		} `json:"system"`
		CacheControl map[string]string `json:"cache_control"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		t.Fatal(err)
	}
	if len(probe.System) != 1 || probe.System[0].CacheControl["type"] != "ephemeral" {
		t.Error("the breakpoint must sit on the system block")
	}
	if probe.CacheControl != nil {
		t.Error("no top-level cache_control: automatic caching would break on the package files")
	}
}
