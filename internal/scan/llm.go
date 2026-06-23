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
	if model := nz(be.Model, os.Getenv("AURSCAN_CODEX_MODEL")); model != "" {
		args = append(args, "--model", model)
	}
	args = append(args, instructions)

	c := exec.CommandContext(ctx, "codex", args...)
	c.Stdin = strings.NewReader(content)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return "", Usage{}, fmt.Errorf("codex CLI failed: %s", firstN(errb.String(), 300))
	}
	text := out.String()
	return text, Usage{In: estIn, Out: estimateTokens(text), Estimated: true}, nil
}

func callAPI(ctx context.Context, be Backend, instructions, content string) (string, Usage, error) {
	model := nz(be.Model, DefaultModel())
	body, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": maxOutTokens,
		"system":     instructions,
		"messages":   []map[string]string{{"role": "user", "content": content}},
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
			In  int `json:"input_tokens"`
			Out int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", Usage{}, err
	}
	var sb strings.Builder
	for _, b := range out.Content {
		sb.WriteString(b.Text)
	}
	u := Usage{In: out.Usage.In, Out: out.Usage.Out}
	if pin, pout, ok := ModelPrice(model); ok {
		u.CostUSD = float64(u.In)/1e6*pin + float64(u.Out)/1e6*pout
		u.HaveCost = true
	}
	return sb.String(), u, nil
}

// callOpenAI talks to an OpenAI-compatible /chat/completions endpoint
// (llama.cpp, Ollama, vLLM, LocalAI, …). It tries AURSCAN_OPENAI_URL first and
// AURSCAN_OPENAI_URL_FALLBACK second, so a primary GPU host can fall back to a
// local CPU instance — generalising the community connector from issue #1.
// Each URL gets its own full timeout budget. Tokens are taken from the server's
// usage block when present, else estimated; cost is n/a for local models.
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
	payload := map[string]any{
		"temperature":     0.1,
		"max_tokens":      maxOutTokens,
		"response_format": map[string]string{"type": "json_object"},
		"messages": []map[string]string{
			{"role": "system", "content": instructions},
			{"role": "user", "content": content},
		},
	}
	if model := nz(be.Model, os.Getenv("AURSCAN_OPENAI_MODEL")); model != "" {
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
					Message struct {
						Content string `json:"content"`
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
			usage := Usage{In: out.Usage.In, Out: out.Usage.Out}
			if usage.In == 0 && usage.Out == 0 {
				usage = Usage{In: estIn, Out: estimateTokens(text), Estimated: true}
			}
			return text, usage, nil
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
