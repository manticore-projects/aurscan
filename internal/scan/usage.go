package scan

import (
	"fmt"
	"os"
	"strings"
)

// Usage captures token counts and cost for one or more model calls.
type Usage struct {
	In, Out   int     // token counts
	CostUSD   float64 // total cost in USD, if known
	HaveCost  bool    // whether CostUSD is meaningful
	Estimated bool    // token counts are estimated (custom backend / fallback)
}

// Add merges another Usage into u (used to accumulate a session total).
func (u *Usage) Add(o Usage) {
	u.In += o.In
	u.Out += o.Out
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
		cost = fmt.Sprintf("$%.4f", u.CostUSD)
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

// ModelPrice returns USD-per-million-token rates for a model id (prefix match).
// Override with AURSCAN_PRICE_IN / AURSCAN_PRICE_OUT. Rates are checked at
// release time against https://platform.claude.com/docs/en/about-claude/pricing
// and may drift; the env override exists precisely so you never depend on a
// stale built-in table.
func ModelPrice(model string) (in, out float64, ok bool) {
	if pi, po := os.Getenv("AURSCAN_PRICE_IN"), os.Getenv("AURSCAN_PRICE_OUT"); pi != "" && po != "" {
		fmt.Sscanf(pi, "%f", &in)
		fmt.Sscanf(po, "%f", &out)
		return in, out, true
	}
	table := []struct {
		prefix  string
		in, out float64
	}{
		{"claude-opus", 5, 25},
		{"claude-sonnet", 3, 15},
		{"claude-haiku", 1, 5},
	}
	for _, p := range table {
		if strings.HasPrefix(model, p.prefix) {
			return p.in, p.out, true
		}
	}
	return 0, 0, false
}
