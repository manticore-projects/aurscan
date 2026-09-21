package scan

// Verdict cache (discussion #56).
//
// The reputation problem is that re-scanning the *same* PKGBUILD can flip the
// verdict, because a hosted LLM is never fully deterministic. Temperature 0
// tightens the model's distribution but cannot freeze it. This cache removes
// the observable inconsistency entirely: a genuine verdict is stored keyed by a
// hash of everything that determines it — the full instructions, the built
// prompt (which already contains the package files, static-rule hits and
// reputation signals) and the resolved model id — so an identical input returns
// the identical stored verdict without calling the model again.
//
// A change to any input (package bytes, prompt, instructions, or model) changes
// the key and misses the cache, so the cache can never serve a verdict for
// different content or a different model. Fallback (degraded) and failed scans
// are never cached. All cache I/O is best-effort: any error is logged and the
// scan proceeds as if the cache were absent, so the cache can never cause a
// scan to fail or fail-closed.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// cacheVersion is bumped when the stored schema or keying scheme changes, so an
// upgraded aurscan ignores entries written by an incompatible older one.
// v2: Tier-2 checklist verdict derivation (discussion #56). The prompt and the
// verdict policy changed, so v1 entries must not be replayed under v2 rules.
const cacheVersion = "v11" // v11: content-aware editor rc (editor_rc_inert), makepkg artifacts section

// defaultCacheTTL bounds how long a stored verdict is served. The key already
// captures package/prompt/instructions/model, so a shorter-lived opinion is not
// required for correctness — this is a staleness backstop and keeps the cache
// from serving indefinitely old judgements. Override with AURSCAN_CACHE_TTL
// (whole days); 0 disables expiry.
const defaultCacheTTL = 30 * 24 * time.Hour

// CacheBypass, when true, skips the cache *read* but still writes a fresh
// verdict (so `--refresh` updates the stored entry). Set by the --refresh flag.
var CacheBypass bool

// cacheDisabled reports a fully disabled cache (no read, no write) via
// AURSCAN_NO_CACHE=1 — for CI or privacy-sensitive runs.
func cacheDisabled() bool { return os.Getenv("AURSCAN_NO_CACHE") == "1" }

// cacheEntry is the on-disk record. Model and Time are metadata; Verdict is the
// payload replayed on a hit.
type cacheEntry struct {
	Version string    `json:"version"`
	Model   string    `json:"model"`
	Time    time.Time `json:"time"`
	Verdict Verdict   `json:"verdict"`
}

// cacheDir resolves the verdict cache directory, honouring AURSCAN_CACHE_DIR,
// then XDG_CACHE_HOME, then ~/.cache. Returns "" if none can be determined
// (caching then silently no-ops).
func cacheDir() string {
	if d := os.Getenv("AURSCAN_CACHE_DIR"); d != "" {
		return d
	}
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return ""
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "aurscan", "verdicts")
}

// cacheTTL returns the configured TTL (0 = no expiry).
func cacheTTL() time.Duration {
	if s := strings.TrimSpace(os.Getenv("AURSCAN_CACHE_TTL")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			return time.Duration(n) * 24 * time.Hour
		}
		dbg("ignoring invalid AURSCAN_CACHE_TTL=%q", s)
	}
	return defaultCacheTTL
}

// cacheKey hashes the full determinants of a verdict into a stable hex id.
func cacheKey(instr, prompt, model string) string {
	h := sha256.New()
	// NUL separators so no field boundary can be forged by content.
	io.WriteString(h, cacheVersion)
	io.WriteString(h, "\x00model\x00"+model)
	io.WriteString(h, "\x00instr\x00"+instr)
	io.WriteString(h, "\x00prompt\x00"+prompt)
	return hex.EncodeToString(h.Sum(nil))
}

// cacheLoad returns a stored verdict for key when present, schema-compatible and
// not expired. The bool is false on any miss/error (never fatal).
func cacheLoad(key string) (Verdict, string, bool) {
	if cacheDisabled() {
		return Verdict{}, "", false
	}
	dir := cacheDir()
	if dir == "" {
		return Verdict{}, "", false
	}
	data, err := os.ReadFile(filepath.Join(dir, key+".json"))
	if err != nil {
		return Verdict{}, "", false // includes the common not-found case
	}
	var e cacheEntry
	if json.Unmarshal(data, &e) != nil || e.Version != cacheVersion {
		return Verdict{}, "", false
	}
	if ttl := cacheTTL(); ttl > 0 && !e.Time.IsZero() && time.Since(e.Time) > ttl {
		dbg("cache: entry %s expired (age %s > ttl %s)", key[:12], time.Since(e.Time).Round(time.Hour), ttl)
		return Verdict{}, "", false
	}
	dbg("cache: hit %s (model=%s, age %s)", key[:12], e.Model, time.Since(e.Time).Round(time.Hour))
	return e.Verdict, e.Model, true
}

// cacheStore writes a verdict atomically (temp file + rename) so a concurrent
// reader never sees a torn file. Best-effort: errors are logged, not returned.
func cacheStore(key, model string, v Verdict) {
	if cacheDisabled() {
		return
	}
	dir := cacheDir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		dbg("cache: mkdir %s failed: %v", dir, err)
		return
	}
	data, err := json.Marshal(cacheEntry{Version: cacheVersion, Model: model, Time: time.Now(), Verdict: v})
	if err != nil {
		dbg("cache: marshal failed: %v", err)
		return
	}
	final := filepath.Join(dir, key+".json")
	tmp, err := os.CreateTemp(dir, key+".*.tmp")
	if err != nil {
		dbg("cache: create temp failed: %v", err)
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		dbg("cache: write failed: %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		dbg("cache: close failed: %v", err)
		return
	}
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		dbg("cache: rename failed: %v", err)
		return
	}
	dbg("cache: stored %s (model=%s)", key[:12], model)
}
