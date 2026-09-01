package scan

import (
	"fmt"
	"os"
	"strings"
)

// Usage captures token counts and cost for one or more model calls.
type Usage struct {
	In, Out int // token counts
	// CacheRead/CacheWrite are the prompt-cache halves of the input. The API
	// reports input_tokens as only what FOLLOWS the last cache breakpoint, so
	// the true total is In + CacheRead + CacheWrite — reporting In alone would
	// understate a cached scan by about 70%.
	CacheRead  int
	CacheWrite int
	CostUSD    float64 // total cost in USD, if known
	HaveCost   bool    // whether CostUSD is meaningful
	Estimated  bool    // token counts are estimated (custom backend / fallback)
}

// Add merges another Usage into u (used to accumulate a session total).
func (u *Usage) Add(o Usage) {
	u.In += o.In
	u.Out += o.Out
	u.CacheRead += o.CacheRead
	u.CacheWrite += o.CacheWrite
	u.CostUSD += o.CostUSD
	u.HaveCost = u.HaveCost || o.HaveCost
	u.Estimated = u.Estimated || o.Estimated
}

// String renders a single human-readable line, e.g.
//
//	tokens: 12,431 in / 214 out · $0.0410
func (u Usage) String() string {
	approx := ""
	if u.Estimated {
		approx = "~"
	}
	cost := "cost n/a"
	if u.HaveCost {
		// An estimated cost (computed from estimated token counts) carries
		// the same "~" marker as the token counts, so the line stays
		// internally consistent (issue #52).
		cost = fmt.Sprintf("%s$%.4f", approx, u.CostUSD)
	}
	if u.CacheRead > 0 || u.CacheWrite > 0 {
		return fmt.Sprintf("tokens: %s%s in (%s cached) / %s%s out · %s",
			approx, thousands(u.In+u.CacheRead+u.CacheWrite), thousands(u.CacheRead),
			approx, thousands(u.Out), cost)
	}
	return fmt.Sprintf("tokens: %s%s in / %s%s out · %s",
		approx, thousands(u.In), approx, thousands(u.Out), cost)
}

func thousands(n int) string {
	s := fmt.Sprintf("%d", n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// priceUsage fills CostUSD/HaveCost on u when a per-token price is known for
// model (built-in table or AURSCAN_PRICE_IN/OUT override). When the token
// counts are estimated the resulting cost is an estimate too, which
// Usage.String renders as "~$…" (issue #52). Unknown models pass through
// unchanged and keep rendering "cost n/a".
func priceUsage(u Usage, model string) Usage {
	if pin, pout, ok := ModelPrice(model); ok {
		// Cache reads bill at 10% of base input, 5-minute writes at 125%.
		u.CostUSD = float64(u.In)/1e6*pin +
			float64(u.CacheRead)/1e6*pin*0.10 +
			float64(u.CacheWrite)/1e6*pin*1.25 +
			float64(u.Out)/1e6*pout
		u.HaveCost = true
	}
	return u
}

// ModelPrice returns USD-per-million-token rates for a model id (prefix match).
// Override with AURSCAN_PRICE_IN / AURSCAN_PRICE_OUT. Rates are checked at
// release time against https://platform.claude.com/docs/en/about-claude/pricing
// and https://developers.openai.com/api/docs/pricing and may drift; the env
// override exists precisely so you never depend on a stale built-in table.
func ModelPrice(model string) (in, out float64, ok bool) {
	if pi, po := os.Getenv("AURSCAN_PRICE_IN"), os.Getenv("AURSCAN_PRICE_OUT"); pi != "" && po != "" {
		fmt.Sscanf(pi, "%f", &in)
		fmt.Sscanf(po, "%f", &out)
		return in, out, true
	}
	// Routing proxies (LiteLLM, OpenRouter, …) often qualify the id, e.g.
	// "openai/gpt-4o"; match on the bare model id.
	if i := strings.LastIndexByte(model, '/'); i >= 0 {
		model = model[i+1:]
	}
	model = strings.ToLower(model)
	// Entries are matched top-down, so a more specific prefix must precede
	// its shorter parent ("gpt-5-mini" before "gpt-5", "gpt-5.4-nano"
	// before "gpt-5.4", …).
	table := []struct {
		prefix  string
		in, out float64
	}{
		{"claude-opus", 5, 25},
		{"claude-sonnet", 3, 15},
		{"claude-haiku", 1, 5},
		// OpenAI — current lineup.
		{"gpt-5.5", 5, 30},
		{"gpt-5.4-mini", 0.75, 4.50},
		{"gpt-5.4-nano", 0.20, 1.25},
		{"gpt-5.4", 2.50, 15},
		// OpenAI — older snapshots still reachable via the API and the
		// Codex CLI (codex variants were priced like their base model).
		{"gpt-5.2", 1.75, 14},
		{"gpt-5.1-codex-mini", 0.25, 2},
		{"gpt-5.1", 1.25, 10}, // also covers gpt-5.1-codex
		{"gpt-5-mini", 0.25, 2},
		{"gpt-5-nano", 0.05, 0.40},
		{"gpt-5", 1.25, 10}, // also covers gpt-5-codex; keep last of gpt-5*
		{"gpt-4.1-mini", 0.40, 1.60},
		{"gpt-4.1-nano", 0.10, 0.40},
		{"gpt-4.1", 2, 8},
		{"gpt-4o-mini", 0.15, 0.60},
		{"gpt-4o", 2.50, 10},
		{"o4-mini", 1.10, 4.40},
		{"o3-mini", 1.10, 4.40},
		{"o3", 2, 8},
	}
	for _, p := range table {
		if strings.HasPrefix(model, p.prefix) {
			return p.in, p.out, true
		}
	}
	return 0, 0, false
}
