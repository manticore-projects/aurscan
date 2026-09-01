package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	apiURL         = "https://api.anthropic.com/v1/messages"
	defaultTimeout = 180 * time.Second
	maxOutTokens   = 2000

	// defaultTemperature is 0 (greedy decoding) for reproducible auditing: the
	// same package should yield the same verdict run-to-run (discussion #56).
	// Reasoning models (e.g. Gemma) that misbehave at 0 can be raised per
	// backend in llmN.conf (temperature=) or via AURSCAN_TEMPERATURE /
	// AURSCAN_OPENAI_TEMPERATURE.
	defaultTemperature = 0.0
)

// llmTimeout is the per-request deadline. It defaults to defaultTimeout but can
// be raised with AURSCAN_TIMEOUT (whole seconds) — slow CPU-only local backends
// (e.g. Ollama on a handheld) routinely need more than three minutes to process
// a large prompt and generate a verdict. A value <= 0 or unparseable falls back
// to the default.
func llmTimeout() time.Duration {
	if s := strings.TrimSpace(os.Getenv("AURSCAN_TIMEOUT")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return defaultTimeout
}

// DefaultModel is the model id used by the direct-API backend.
func DefaultModel() string {
	if m := os.Getenv("AURSCAN_MODEL"); m != "" {
		return m
	}
	return "claude-sonnet-4-6"
}

// Backend describes one resolved LLM backend in the fallback chain.
//
// Backend MUST stay all-comparable (every field a string) because dedupe keys a
// map[Backend]bool on it. NEVER print a Backend or []Backend with %v/%+v — use
// String(), which redacts APIKey so a stray debug line cannot leak a secret.
//
// Empty setting fields mean "use the legacy environment lookup". Env-derived
// specs keep them empty so each callX reads its own env var at call time; only
// llmN.conf-derived specs populate them.
type Backend struct {
	Kind     string // "claude", "codex", "api", "openai", or "cmd"
	Cmd      string // executable path when Kind == "cmd"
	Model    string // AURSCAN_MODEL / AURSCAN_CODEX_MODEL / AURSCAN_OPENAI_MODEL (per kind)
	URL      string // openai /chat/completions URL (or an Anthropic-compatible /v1/messages gateway for "api")
	Fallback string // openai secondary URL (intra-backend, like AURSCAN_OPENAI_URL_FALLBACK)
	APIKey   string // ANTHROPIC_API_KEY / AURSCAN_OPENAI_API_KEY
	// Temperature is the sampling temperature for the openai backend. nil means
	// "unset" (use AURSCAN_OPENAI_TEMPERATURE or the default). Reasoning models
	// such as Gemma generally require temperature=1.0.
	Temperature *float64
	// MaxTokens is the output-token budget. 0 means "unset" (use the env var or
	// the default). Reasoning models spend the budget on hidden reasoning before
	// the answer, so a small cap can be exhausted before any content is emitted.
	MaxTokens int
}

// String renders a Backend for debug output with the secret redacted.
func (b Backend) String() string {
	key := "no"
	if b.APIKey != "" {
		key = "yes"
	}
	return fmt.Sprintf("{kind:%s cmd:%q model:%q url:%q fallback:%q hasKey:%s}",
		b.Kind, b.Cmd, b.Model, b.URL, b.Fallback, key)
}

// ExtraBackends holds the fallback backends parsed from ~/.config/aurscan/llmN.conf.
// It is set once at startup by the CLI (mirroring ExtraInstructions) and appended
// after the environment-derived backends to form the chain. Empty by default, so
// with no config files the chain is exactly the auto-detected/pinned env backend.
var ExtraBackends []Backend

// nz returns a if non-empty, else b — used to let a per-backend spec field
// override the legacy environment lookup while keeping the env path intact.
func nz(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ModelID returns the effective model id this backend will request, resolving
// the same per-kind env fallbacks the callX functions use. It is used to record
// which model produced a verdict and to key the verdict cache (discussion #56),
// so that switching models re-scans rather than serving a stale opinion. The
// Codex and Claude Code CLIs may leave this empty when no model is pinned; the
// key is still stable, just less specific.
func (b Backend) ModelID() string {
	switch b.Kind {
	case "api":
		return nz(b.Model, DefaultModel())
	case "openai":
		return nz(b.Model, os.Getenv("AURSCAN_OPENAI_MODEL"))
	case "codex":
		return nz(b.Model, os.Getenv("AURSCAN_CODEX_MODEL"))
	case "claude":
		return nz(b.Model, os.Getenv("AURSCAN_MODEL"))
	case "cmd":
		return b.Cmd
	default:
		return b.Model
	}
}

// backendLabel is the short name used in the "trying next" warning. Distinct
// cmd backends are disambiguated by their path.
func backendLabel(be Backend) string {
	if be.Kind == "cmd" && be.Cmd != "" {
		return "cmd " + be.Cmd
	}
	return be.Kind
}

// BackendsFromConfig turns parsed llmN.conf maps into backend specs. The
// "backend" value mirrors AURSCAN_BACKEND: one of claude/codex/api/openai, or
// any other value (e.g. a /path/to/exe) treated as a custom command.
func BackendsFromConfig(maps []map[string]string) []Backend {
	var out []Backend
	for _, m := range maps {
		var be Backend
		switch b := m["backend"]; {
		case b == "claude" || b == "codex" || b == "api" || b == "openai":
			be = Backend{Kind: b}
		case b != "": // a path or any other value => custom command (mirrors AURSCAN_BACKEND=/path)
			be = Backend{Kind: "cmd", Cmd: b}
		default:
			dbg("config: skipping llmN.conf entry with no backend= value")
			continue
		}
		be.Model, be.URL, be.Fallback, be.APIKey = m["model"], m["url"], m["fallback"], m["api_key"]
		if v := m["temperature"]; v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				be.Temperature = &f
			} else {
				dbg("config: invalid temperature=%q (ignored)", v)
			}
		}
		if v := m["max_tokens"]; v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				be.MaxTokens = n
			} else {
				dbg("config: invalid max_tokens=%q (ignored)", v)
			}
		}
		out = append(out, be)
	}
	return out
}

// envBackends resolves the backend(s) from the environment, honoring
// AURSCAN_BACKEND. A pinned value yields exactly one backend (recognised kind,
// or any other value as a custom executable path). Unpinned, it auto-detects
// ALL available backends in the documented preference order — so a failure of
// the first (e.g. Claude) falls through to the next (e.g. Codex). On the success
// path only the first is ever invoked, so standard operation is unchanged.
func envBackends() []Backend {
	switch b := os.Getenv("AURSCAN_BACKEND"); {
	case b == "claude" || b == "codex" || b == "api" || b == "openai":
		return []Backend{{Kind: b}}
	case b != "":
		return []Backend{{Kind: "cmd", Cmd: b}}
	}
	var out []Backend
	if _, err := exec.LookPath("claude"); err == nil {
		out = append(out, Backend{Kind: "claude"})
	}
	if _, err := exec.LookPath("codex"); err == nil {
		out = append(out, Backend{Kind: "codex"})
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		out = append(out, Backend{Kind: "api"})
	}
	if os.Getenv("AURSCAN_OPENAI_URL") != "" {
		out = append(out, Backend{Kind: "openai"})
	}
	return out
}

// Backends is the ordered fallback chain: environment-derived backends first,
// then the llmN.conf-derived ExtraBackends, deduplicated (first occurrence wins).
func Backends() []Backend {
	return dedupe(append(envBackends(), ExtraBackends...))
}

// dedupe drops exact duplicate specs while preserving order. Equality is full
// struct equality, so two backends differing only in URL/model remain distinct.
func dedupe(in []Backend) []Backend {
	seen := map[Backend]bool{}
	var out []Backend
	for _, be := range in {
		if seen[be] {
			continue
		}
		seen[be] = true
		out = append(out, be)
	}
	return out
}

// PickBackend returns the first backend in the chain, or an error if the chain
// is empty. It is the gate pipeline.Run uses to decide LLM-vs-rules; Scan walks
// the full chain itself.
func PickBackend() (Backend, error) {
	bs := Backends()
	if len(bs) == 0 {
		return Backend{}, fmt.Errorf("no backend: install Claude Code (`claude`) or Codex CLI (`codex`) and log in, " +
			"set ANTHROPIC_API_KEY, set AURSCAN_OPENAI_URL for a local model, " +
			"or AURSCAN_BACKEND=/path/to/cmd")
	}
	return bs[0], nil
}

func estimateTokens(s string) int { return len(s) / 4 }

// openAIKey resolves the bearer token for the OpenAI-compatible backend. It
// prefers AURSCAN_OPENAI_API_KEY, then falls back to the conventional
// OPENAI_API_KEY that local proxies like LiteLLM, vLLM and Ollama already use
// (issue #13). Empty means no Authorization header is sent (open local server).
func openAIKey() string {
	if k := os.Getenv("AURSCAN_OPENAI_API_KEY"); k != "" {
		return k
	}
	return os.Getenv("OPENAI_API_KEY")
}

// Call sends instructions + content to the selected backend and returns the
// raw model text plus usage. The Claude Code backend reports exact cost; the
// API backend reports exact tokens (cost computed from ModelPrice); Codex CLI,
// OpenAI-compatible, and custom command backends may estimate.
func Call(instructions, content string) (string, Usage, error) {
	be, err := PickBackend()
	if err != nil {
		return "", Usage{}, err
	}
	return CallBackend(be, instructions, content)
}

// CallBackend sends instructions + content to a specific backend and returns
// the raw model text plus usage. Scan calls this once per backend as it walks
// the fallback chain. Each backend gets its own full llmTimeout budget.
func CallBackend(be Backend, instructions, content string) (string, Usage, error) {
	dbg("backend=%s cmd=%q", be.Kind, be.Cmd)
	to := llmTimeout()
	estIn := estimateTokens(instructions + content)

	var (
		text string
		u    Usage
		err  error
	)
	switch be.Kind {
	case "openai":
		// Per-attempt deadlines live inside callOpenAI so that a stalled
		// primary URL does not eat the fallback URL's whole budget.
		text, u, err = callOpenAI(context.Background(), to, be, instructions, content, estIn)
	default:
		ctx, cancel := context.WithTimeout(context.Background(), to)
		defer cancel()
		switch be.Kind {
		case "claude":
			text, u, err = callClaudeCLI(ctx, be, instructions, content, estIn)
		case "codex":
			text, u, err = callCodexCLI(ctx, be, instructions, content, estIn)
		case "api":
			text, u, err = callAPI(ctx, be, instructions, content)
		default:
			text, u, err = callCmd(ctx, be, instructions, content, estIn)
		}
	}
	if err != nil {
		return "", Usage{}, annotateTimeout(err, to)
	}
	return text, u, nil
}

// annotateTimeout turns the opaque "context deadline exceeded" into actionable
// guidance, since for local backends a deadline almost always means the model
// is simply too slow for the configured budget rather than anything being
// broken.
func annotateTimeout(err error, to time.Duration) error {
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "deadline exceeded") {
		return fmt.Errorf("model did not respond within %s; raise the budget with "+
			"AURSCAN_TIMEOUT=<seconds> or switch to a smaller/faster model "+
			"(underlying: %v)", to, err)
	}
	return err
}

func callClaudeCLI(ctx context.Context, be Backend, instructions, content string, estIn int) (string, Usage, error) {
	_ = be // the Claude Code CLI takes no model flag today; be.Model/APIKey are a future hook
	run := func(args ...string) (string, error) {
		dbg("claude CLI args=%v", args)
		dbgBlock("claude stdin (untrusted package content)", content)
		c := exec.CommandContext(ctx, "claude", args...)
		c.Stdin = strings.NewReader(content)
		var out, errb bytes.Buffer
		c.Stdout, c.Stderr = &out, &errb
		if err := c.Run(); err != nil {
			dbgBlock("claude stderr", errb.String())
			return "", fmt.Errorf("claude CLI failed: %s", firstN(errb.String(), 300))
		}
		dbgBlock("claude raw stdout", out.String())
		return out.String(), nil
	}
	// JSON envelope mode yields exact usage and total_cost_usd.
	raw, err := run("-p", "--output-format", "json", instructions)
	if err == nil {
		if text, u, ok := parseClaudeEnvelope(raw, estIn); ok {
			return text, u, nil
		}
		// Envelope not understood: treat stdout as the model text, estimate.
		dbg("claude --output-format json envelope not understood; using raw stdout as model text (issue #17 territory)")
		return raw, Usage{In: estIn, Out: estimateTokens(raw), Estimated: true}, nil
	}
	// Older CLI without --output-format support: plain print mode.
	if raw2, err2 := run("-p", instructions); err2 == nil {
		return raw2, Usage{In: estIn, Out: estimateTokens(raw2), Estimated: true}, nil
	}
	return "", Usage{}, err
}

// claudeEnvelope is one record from the Claude Code CLI's JSON output. The CLI
// emits EITHER a single object (older/compact mode) OR an array of these
// records (newer/streaming mode, e.g. v2.1.x), where the final "result" record
// carries the model text, usage and cost. We accept both shapes (issue #17).
type claudeEnvelope struct {
	Type    string  `json:"type"`
	Subtype string  `json:"subtype"`
	IsError bool    `json:"is_error"`
	Error   string  `json:"error"`
	Status  int     `json:"error_status"`
	Result  string  `json:"result"`
	Cost    float64 `json:"total_cost_usd"`
	Usage   struct {
		In       int `json:"input_tokens"`
		Out      int `json:"output_tokens"`
		CacheCre int `json:"cache_creation_input_tokens"`
		CacheRd  int `json:"cache_read_input_tokens"`
	} `json:"usage"`
}

func (e claudeEnvelope) toUsage() Usage {
	return Usage{
		In:       e.Usage.In + e.Usage.CacheCre + e.Usage.CacheRd,
		Out:      e.Usage.Out,
		CostUSD:  e.Cost,
		HaveCost: true,
	}
}

// parseClaudeEnvelope extracts the model text + usage from either CLI output
// shape. ok is false when the output is neither recognised shape (caller then
// falls back to treating stdout as raw text).
func parseClaudeEnvelope(raw string, estIn int) (string, Usage, bool) {
	trimmed := strings.TrimSpace(raw)

	// Shape A: a single JSON object.
	if strings.HasPrefix(trimmed, "{") {
		var e claudeEnvelope
		if json.Unmarshal([]byte(trimmed), &e) == nil && e.Result != "" {
			return e.Result, e.toUsage(), true
		}
		return "", Usage{}, false
	}

	// Shape B: an array of records (streaming transcript). Take the last
	// "result" record; surface an authentication/error record under --debug.
	if strings.HasPrefix(trimmed, "[") {
		var recs []claudeEnvelope
		if json.Unmarshal([]byte(trimmed), &recs) != nil {
			return "", Usage{}, false
		}
		var resultRec *claudeEnvelope
		for i := range recs {
			r := recs[i]
			if r.Type == "result" && r.Result != "" {
				resultRec = &recs[i]
			}
			if r.Status == 401 || r.Error == "authentication_failed" {
				dbg("claude CLI reported authentication failure (status=%d %q) — "+
					"the subscription/credentials were not accepted", r.Status, r.Error)
			}
		}
		if resultRec != nil && !resultRec.IsError {
			return resultRec.Result, resultRec.toUsage(), true
		}
	}
	return "", Usage{}, false
}

func callCodexCLI(ctx context.Context, be Backend, instructions, content string, estIn int) (string, Usage, error) {
	args := []string{
		"exec",
		"--skip-git-repo-check",
		"--ephemeral",
		"--ignore-rules",
		"--sandbox", "read-only",
		"--color", "never",
	}
	model := nz(be.Model, os.Getenv("AURSCAN_CODEX_MODEL"))
	if model != "" {
		args = append(args, "--model", model)
	}
	// NOTE (discussion #56): `codex exec` exposes no temperature/seed knob and
	// drives a reasoning model, so this backend cannot be made reproducible the
	// way the api/openai backends can. Pin --model for at least model stability;
	// for reproducible verdicts prefer the api backend (temperature 0) or a
	// local openai model with a fixed seed. The verdict cache still gives
	// same-input/same-output on re-runs regardless of backend.
	args = append(args, instructions)

	c := exec.CommandContext(ctx, "codex", args...)
	c.Stdin = strings.NewReader(content)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return "", Usage{}, fmt.Errorf("codex CLI failed: %s", firstN(errb.String(), 300))
	}
	// The Codex CLI exposes neither token counts nor cost on stdout, so both
	// are estimates. When the model is known (per-backend model= or
	// AURSCAN_CODEX_MODEL) — or AURSCAN_PRICE_IN/OUT is set — an estimated
	// API-equivalent cost is shown as "~$…"; otherwise "cost n/a" (issue #52).
	text := out.String()
	u := priceUsage(Usage{In: estIn, Out: estimateTokens(text), Estimated: true}, model)
	return text, u, nil
}

func callAPI(ctx context.Context, be Backend, instructions, content string) (string, Usage, error) {
	model := nz(be.Model, DefaultModel())
	maxTok := maxOutTokens
	if be.MaxTokens > 0 {
		maxTok = be.MaxTokens
	}
	// The system prompt is ~4,200 tokens and byte-identical on every call, while
	// the user message is a different package each time. Sending the system
	// prompt as a cacheable block turns roughly 70% of the input into cache
	// reads at a tenth of the price.
	//
	// This uses an EXPLICIT breakpoint on the system block rather than
	// request-level automatic caching, and the distinction matters: automatic
	// caching places the breakpoint on the last cacheable block, which here is
	// the package files. Those differ every request, so the prefix hash would
	// never match — a fresh cache write every time and not one read. It is the
	// documented trap, and this prompt has exactly the shape that falls into it.
	//
	// Not free in every case: a cache write costs 25% more than plain input, so
	// a single isolated scan with nothing following it within the 5-minute TTL
	// is marginally more expensive. Break-even is about one hit per four writes,
	// and both real usage patterns — a sweep, or a yay session covering several
	// packages — clear that comfortably.
	sysBlock := map[string]any{"type": "text", "text": instructions}
	if promptCacheEnabled() {
		sysBlock["cache_control"] = promptCacheControl()
	}
	body, _ := json.Marshal(map[string]any{
		"model":       model,
		"max_tokens":  maxTok,
		"temperature": resolveTemperature(be), // 0 by default — reproducible auditing (#56)
		"system":      []map[string]any{sysBlock},
		"messages":    []map[string]string{{"role": "user", "content": content}},
	})
	dbgBlock("anthropic API request body", string(body))
	req, _ := http.NewRequestWithContext(ctx, "POST", nz(be.URL, apiURL), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", nz(be.APIKey, os.Getenv("ANTHROPIC_API_KEY")))
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		dbg("anthropic API transport error: %v", err)
		return "", Usage{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	dbg("anthropic API HTTP %d", resp.StatusCode)
	dbgBlock("anthropic API raw response", string(raw))
	if resp.StatusCode != 200 {
		return "", Usage{}, fmt.Errorf("API HTTP %d: %s", resp.StatusCode, firstN(string(raw), 300))
	}
	var out struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			In        int `json:"input_tokens"`
			Out       int `json:"output_tokens"`
			CacheRead int `json:"cache_read_input_tokens"`
			CacheWrit int `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", Usage{}, err
	}
	var sb strings.Builder
	for _, b := range out.Content {
		sb.WriteString(b.Text)
	}
	// input_tokens counts only what follows the last cache breakpoint, so the
	// cached prefix has to be added back to get the real total.
	u := priceUsage(Usage{
		In:         out.Usage.In,
		Out:        out.Usage.Out,
		CacheRead:  out.Usage.CacheRead,
		CacheWrite: out.Usage.CacheWrit,
	}, model)
	return sb.String(), u, nil
}

// promptCacheControl builds the cache_control block for the system prompt. The
// 5-minute default is refreshed free on every hit, which suits a sweep or an
// interactive session where scans follow one another closely.
// AURSCAN_PROMPT_CACHE_TTL=1h buys an hour at twice the write price, worth it
// only when scans are minutes apart. AURSCAN_PROMPT_CACHE=0 disables caching
// for anyone whose usage is genuinely one isolated scan at a time, where a
// write that is never read costs 25% more than plain input.
func promptCacheControl() map[string]string {
	cc := map[string]string{"type": "ephemeral"}
	if os.Getenv("AURSCAN_PROMPT_CACHE_TTL") == "1h" {
		cc["ttl"] = "1h"
	}
	return cc
}

// promptCacheEnabled reports whether to send a cache breakpoint at all.
func promptCacheEnabled() bool { return os.Getenv("AURSCAN_PROMPT_CACHE") != "0" }

// resolveTemperature picks the sampling temperature for auditing, lowest wins:
// an explicit per-backend value (llmN.conf temperature=), then the backend-
// agnostic AURSCAN_TEMPERATURE, then the openai-specific AURSCAN_OPENAI_TEMPERATURE
// (kept for compatibility), then defaultTemperature (0). Reasoning models such
// as Gemma may need 1.0; raise it there.
func resolveTemperature(be Backend) float64 {
	if be.Temperature != nil {
		return *be.Temperature
	}
	for _, key := range []string{"AURSCAN_TEMPERATURE", "AURSCAN_OPENAI_TEMPERATURE"} {
		if v := os.Getenv(key); v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f
			}
			dbg("ignoring invalid %s=%q", key, v)
		}
	}
	return defaultTemperature
}

// resolveMaxTokens picks the output-token budget: per-backend (llmN.conf
// max_tokens=) wins, then AURSCAN_OPENAI_MAX_TOKENS, then maxOutTokens. Reasoning
// models spend the budget on hidden reasoning before the answer, so the default
// cap can be exhausted before any content is produced — raise it for them.
func resolveMaxTokens(be Backend) int {
	if be.MaxTokens > 0 {
		return be.MaxTokens
	}
	if v := os.Getenv("AURSCAN_OPENAI_MAX_TOKENS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		dbg("ignoring invalid AURSCAN_OPENAI_MAX_TOKENS=%q", v)
	}
	return maxOutTokens
}

// callOpenAI talks to an OpenAI-compatible /chat/completions endpoint
// (llama.cpp, Ollama, vLLM, LocalAI, …). It tries AURSCAN_OPENAI_URL first and
// AURSCAN_OPENAI_URL_FALLBACK second, so a primary GPU host can fall back to a
// local CPU instance — generalising the community connector from issue #1.
// Each URL gets its own full timeout budget. Tokens are taken from the server's
// usage block when present, else estimated. Cost is computed via ModelPrice
// when the model is priced (routed cloud models, or AURSCAN_PRICE_IN/OUT for
// anything else, e.g. amortised local hardware); otherwise it stays n/a
// (issue #52).
func callOpenAI(parent context.Context, to time.Duration, be Backend, instructions, content string, estIn int) (string, Usage, error) {
	// A spec URL fully overrides the environment; the env primary/fallback pair
	// is used only when the spec leaves URL empty (the env-derived backend).
	var urls []string
	if be.URL != "" {
		urls = append(urls, be.URL)
	} else if u := os.Getenv("AURSCAN_OPENAI_URL"); u != "" {
		urls = append(urls, u)
	}
	if be.Fallback != "" {
		urls = append(urls, be.Fallback)
	} else if be.URL == "" {
		if fb := os.Getenv("AURSCAN_OPENAI_URL_FALLBACK"); fb != "" {
			urls = append(urls, fb)
		}
	}
	apiKey := nz(be.APIKey, openAIKey())
	// The model is sent only when AURSCAN_OPENAI_MODEL is set. Leaving it out
	// lets a routing proxy (LiteLLM and similar) select the model itself, so you
	// can switch models at the proxy without touching this env var or restarting.
	// Set AURSCAN_OPENAI_MODEL for servers that require an explicit model.
	maxTok := resolveMaxTokens(be)
	payload := map[string]any{
		"temperature":     resolveTemperature(be),
		"max_tokens":      maxTok,
		"response_format": map[string]string{"type": "json_object"},
		"messages": []map[string]string{
			{"role": "system", "content": instructions},
			{"role": "user", "content": content},
		},
	}
	model := nz(be.Model, os.Getenv("AURSCAN_OPENAI_MODEL"))
	if model != "" {
		payload["model"] = model
	}
	body, _ := json.Marshal(payload)

	dbgBlock("openai request body", string(body))
	var lastErr error
	for _, u := range urls {
		dbg("openai POST %s", u)
		text, usage, err := func() (string, Usage, error) {
			ctx, cancel := context.WithTimeout(parent, to)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if apiKey != "" {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return "", Usage{}, err
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			dbg("openai %s HTTP %d", u, resp.StatusCode)
			dbgBlock("openai raw response", string(raw))
			if resp.StatusCode != 200 {
				return "", Usage{}, fmt.Errorf("openai HTTP %d: %s", resp.StatusCode, firstN(string(raw), 200))
			}
			var out struct {
				Choices []struct {
					FinishReason string `json:"finish_reason"`
					Message      struct {
						Content          string `json:"content"`
						ReasoningContent string `json:"reasoning_content"`
					} `json:"message"`
				} `json:"choices"`
				Usage struct {
					In  int `json:"prompt_tokens"`
					Out int `json:"completion_tokens"`
				} `json:"usage"`
			}
			if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
				return "", Usage{}, fmt.Errorf("openai: unparseable response from %s", u)
			}
			text := out.Choices[0].Message.Content
			if strings.TrimSpace(text) == "" {
				// A reasoning model can spend the whole budget on hidden
				// reasoning and emit no content (finish_reason=length, with the
				// reasoning in reasoning_content). Make that actionable instead
				// of returning a silent empty verdict.
				fr := out.Choices[0].FinishReason
				if fr == "length" || out.Choices[0].Message.ReasoningContent != "" {
					return "", Usage{}, fmt.Errorf(
						"openai: model emitted no content (finish_reason=%q) — a reasoning model likely "+
							"exhausted max_tokens=%d before answering. Raise it (llmN.conf max_tokens= or "+
							"AURSCAN_OPENAI_MAX_TOKENS) and, for Gemma, set temperature=1.0", fr, maxTok)
				}
				return "", Usage{}, fmt.Errorf("openai: empty content from %s (finish_reason=%q)", u, fr)
			}
			usage := Usage{In: out.Usage.In, Out: out.Usage.Out}
			if usage.In == 0 && usage.Out == 0 {
				usage = Usage{In: estIn, Out: estimateTokens(text), Estimated: true}
			}
			// Mirror callAPI: price the usage when the model is known
			// (routed cloud models) or AURSCAN_PRICE_IN/OUT is set. Local
			// models with no price keep "cost n/a" (issue #52). When a
			// proxy picked the model itself (no model sent), only the env
			// override can price it.
			return text, priceUsage(usage, model), nil
		}()
		if err != nil {
			lastErr = err
			continue
		}
		return text, usage, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("openai: no AURSCAN_OPENAI_URL configured")
	}
	return "", Usage{}, lastErr
}

func callCmd(ctx context.Context, be Backend, instructions, content string, estIn int) (string, Usage, error) {
	cmd := be.Cmd
	payload := instructions + "\n\n" + content
	dbg("cmd backend: %s", cmd)
	dbgBlock("cmd stdin", payload)
	c := exec.CommandContext(ctx, cmd)
	c.Stdin = strings.NewReader(payload)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		dbgBlock("cmd stderr", errb.String())
		return "", Usage{}, fmt.Errorf("backend %s failed: %s", cmd, firstN(errb.String(), 300))
	}
	dbgBlock("cmd raw stdout", out.String())
	return out.String(), Usage{In: estIn, Out: estimateTokens(out.String()), Estimated: true}, nil
}

func firstN(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
