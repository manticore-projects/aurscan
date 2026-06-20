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

// Backend describes the resolved LLM backend.
type Backend struct {
	Kind string // "claude", "codex", "api", "openai", or "cmd"
	Cmd  string // executable path when Kind == "cmd"
}

// PickBackend auto-detects an available backend, honoring AURSCAN_BACKEND.
// Recognised values: "claude", "codex", "api", "openai" (OpenAI-compatible
// local server such as llama.cpp/Ollama/vLLM), or a path to a custom executable.
func PickBackend() (Backend, error) {
	switch b := os.Getenv("AURSCAN_BACKEND"); {
	case b == "claude" || b == "codex" || b == "api" || b == "openai":
		return Backend{Kind: b}, nil
	case b != "":
		return Backend{Kind: "cmd", Cmd: b}, nil
	}
	if _, err := exec.LookPath("claude"); err == nil {
		return Backend{Kind: "claude"}, nil
	}
	if _, err := exec.LookPath("codex"); err == nil {
		return Backend{Kind: "codex"}, nil
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return Backend{Kind: "api"}, nil
	}
	if os.Getenv("AURSCAN_OPENAI_URL") != "" {
		return Backend{Kind: "openai"}, nil
	}
	return Backend{}, fmt.Errorf("no backend: install Claude Code (`claude`) or Codex CLI (`codex`) and log in, " +
		"set ANTHROPIC_API_KEY, set AURSCAN_OPENAI_URL for a local model, " +
		"or AURSCAN_BACKEND=/path/to/cmd")
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
	dbg("backend=%s cmd=%q", be.Kind, be.Cmd)
	to := llmTimeout()
	estIn := estimateTokens(instructions + content)

	var (
		text string
		u    Usage
	)
	switch be.Kind {
	case "openai":
		// Per-attempt deadlines live inside callOpenAI so that a stalled
		// primary URL does not eat the fallback URL's whole budget.
		text, u, err = callOpenAI(context.Background(), to, instructions, content, estIn)
	default:
		var ctx context.Context
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), to)
		defer cancel()
		switch be.Kind {
		case "claude":
			text, u, err = callClaudeCLI(ctx, instructions, content, estIn)
		case "codex":
			text, u, err = callCodexCLI(ctx, instructions, content, estIn)
		case "api":
			text, u, err = callAPI(ctx, instructions, content)
		default:
			text, u, err = callCmd(ctx, be.Cmd, instructions, content, estIn)
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

func callClaudeCLI(ctx context.Context, instructions, content string, estIn int) (string, Usage, error) {
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

func callCodexCLI(ctx context.Context, instructions, content string, estIn int) (string, Usage, error) {
	args := []string{
		"exec",
		"--skip-git-repo-check",
		"--ephemeral",
		"--ignore-rules",
		"--sandbox", "read-only",
		"--color", "never",
	}
	if model := os.Getenv("AURSCAN_CODEX_MODEL"); model != "" {
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

func callAPI(ctx context.Context, instructions, content string) (string, Usage, error) {
	model := DefaultModel()
	body, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": maxOutTokens,
		"system":     instructions,
		"messages":   []map[string]string{{"role": "user", "content": content}},
	})
	dbgBlock("anthropic API request body", string(body))
	req, _ := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", os.Getenv("ANTHROPIC_API_KEY"))
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
func callOpenAI(parent context.Context, to time.Duration, instructions, content string, estIn int) (string, Usage, error) {
	urls := []string{os.Getenv("AURSCAN_OPENAI_URL")}
	if fb := os.Getenv("AURSCAN_OPENAI_URL_FALLBACK"); fb != "" {
		urls = append(urls, fb)
	}
	model := os.Getenv("AURSCAN_OPENAI_MODEL")
	if model == "" {
		model = "default-model"
	}
	apiKey := openAIKey()
	body, _ := json.Marshal(map[string]any{
		"model":           model,
		"temperature":     0.1,
		"max_tokens":      maxOutTokens,
		"response_format": map[string]string{"type": "json_object"},
		"messages": []map[string]string{
			{"role": "system", "content": instructions},
			{"role": "user", "content": content},
		},
	})

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

func callCmd(ctx context.Context, cmd, instructions, content string, estIn int) (string, Usage, error) {
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
