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
	Kind string // "claude", "api", or "cmd"
	Cmd  string // executable path when Kind == "cmd"
}

// PickBackend auto-detects an available backend, honoring AURSCAN_BACKEND.
// Recognised values: "claude", "api", "openai" (OpenAI-compatible local server
// such as llama.cpp/Ollama/vLLM), or a path to a custom executable.
func PickBackend() (Backend, error) {
	switch b := os.Getenv("AURSCAN_BACKEND"); {
	case b == "claude" || b == "api" || b == "openai":
		return Backend{Kind: b}, nil
	case b != "":
		return Backend{Kind: "cmd", Cmd: b}, nil
	}
	if _, err := exec.LookPath("claude"); err == nil {
		return Backend{Kind: "claude"}, nil
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return Backend{Kind: "api"}, nil
	}
	if os.Getenv("AURSCAN_OPENAI_URL") != "" {
		return Backend{Kind: "openai"}, nil
	}
	return Backend{}, fmt.Errorf("no backend: install Claude Code (`claude` CLI) and log in, " +
		"set ANTHROPIC_API_KEY, set AURSCAN_OPENAI_URL for a local model, " +
		"or AURSCAN_BACKEND=/path/to/cmd")
}

func estimateTokens(s string) int { return len(s) / 4 }

// Call sends instructions + content to the selected backend and returns the
// raw model text plus usage. The Claude Code backend reports exact cost; the
// API backend reports exact tokens (cost computed from ModelPrice); the custom
// command backend can only estimate.
func Call(instructions, content string) (string, Usage, error) {
	be, err := PickBackend()
	if err != nil {
		return "", Usage{}, err
	}
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
		c := exec.CommandContext(ctx, "claude", args...)
		c.Stdin = strings.NewReader(content)
		var out, errb bytes.Buffer
		c.Stdout, c.Stderr = &out, &errb
		if err := c.Run(); err != nil {
			return "", fmt.Errorf("claude CLI failed: %s", firstN(errb.String(), 300))
		}
		return out.String(), nil
	}
	// JSON envelope mode yields exact usage and total_cost_usd.
	raw, err := run("-p", "--output-format", "json", instructions)
	if err == nil {
		var env struct {
			Result string  `json:"result"`
			Cost   float64 `json:"total_cost_usd"`
			Usage  struct {
				In       int `json:"input_tokens"`
				Out      int `json:"output_tokens"`
				CacheCre int `json:"cache_creation_input_tokens"`
				CacheRd  int `json:"cache_read_input_tokens"`
			} `json:"usage"`
		}
		if jerr := json.Unmarshal([]byte(raw), &env); jerr == nil && env.Result != "" {
			return env.Result, Usage{
				In:       env.Usage.In + env.Usage.CacheCre + env.Usage.CacheRd,
				Out:      env.Usage.Out,
				CostUSD:  env.Cost,
				HaveCost: true,
			}, nil
		}
		// Envelope not understood: treat stdout as the model text, estimate.
		return raw, Usage{In: estIn, Out: estimateTokens(raw), Estimated: true}, nil
	}
	// Older CLI without --output-format support: plain print mode.
	if raw2, err2 := run("-p", instructions); err2 == nil {
		return raw2, Usage{In: estIn, Out: estimateTokens(raw2), Estimated: true}, nil
	}
	return "", Usage{}, err
}

func callAPI(ctx context.Context, instructions, content string) (string, Usage, error) {
	model := DefaultModel()
	body, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": maxOutTokens,
		"system":     instructions,
		"messages":   []map[string]string{{"role": "user", "content": content}},
	})
	req, _ := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", os.Getenv("ANTHROPIC_API_KEY"))
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", Usage{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
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

	var lastErr error
	for _, u := range urls {
		text, usage, err := func() (string, Usage, error) {
			ctx, cancel := context.WithTimeout(parent, to)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if key := os.Getenv("AURSCAN_OPENAI_API_KEY"); key != "" {
				req.Header.Set("Authorization", "Bearer "+key)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return "", Usage{}, err
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
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
	c := exec.CommandContext(ctx, cmd)
	c.Stdin = strings.NewReader(instructions + "\n\n" + content)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return "", Usage{}, fmt.Errorf("backend %s failed: %s", cmd, firstN(errb.String(), 300))
	}
	return out.String(), Usage{In: estIn, Out: estimateTokens(out.String()), Estimated: true}, nil
}

func firstN(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
