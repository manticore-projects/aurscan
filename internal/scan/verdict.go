package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	maxFileBytes  = 64 * 1024
	maxTotalBytes = 240 * 1024
)

// Finding is one issue the auditor reported.
type Finding struct {
	File     string `json:"file"`
	Severity string `json:"severity"` // info | warning | critical
	Quote    string `json:"quote"`
	Why      string `json:"why"`
}

// Verdict is the auditor's structured result for one package.
type Verdict struct {
	Verdict    string    `json:"verdict"` // OK | SUSPICIOUS | MALICIOUS
	Confidence float64   `json:"confidence"`
	Summary    string    `json:"summary"`
	Findings   []Finding `json:"findings"`
}

// Rank orders verdicts so callers can compute the worst across packages.
var Rank = map[string]int{"OK": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}

// Result pairs a package name with its verdict and the usage it cost.
type Result struct {
	Pkg   string
	V     Verdict
	Usage Usage
}

func failClosed(why string) Verdict {
	return Verdict{Verdict: "SUSPICIOUS", Summary: why + " (fail-closed)"}
}

// Files maps a relative filename to its text content.
type Files map[string]string

// Scan audits a set of package files. Any backend error or unparseable model
// output yields a SUSPICIOUS verdict — the scanner never fails open.
func Scan(pkg string, files Files) Result {
	raw, u, err := Call(Instructions, buildPrompt(pkg, files))
	if err != nil {
		return Result{Pkg: pkg, V: failClosed("Scan failed: " + err.Error())}
	}
	return Result{Pkg: pkg, V: parseVerdict(raw), Usage: u}
}

func buildPrompt(pkg string, files Files) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Package under review: %s\n", pkg)
	sb.WriteString("===== BEGIN UNTRUSTED PACKAGE FILES =====\n")
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&sb, "\n----- FILE: %s -----\n%s", n, files[n])
	}
	sb.WriteString("\n===== END UNTRUSTED PACKAGE FILES =====\n")
	return sb.String()
}

var jsonBlobRe = regexp.MustCompile(`(?s)\{.*\}`)

func parseVerdict(raw string) Verdict {
	blob := jsonBlobRe.FindString(raw)
	if blob == "" {
		return failClosed("Scanner returned no parseable result")
	}
	var v Verdict
	if err := json.Unmarshal([]byte(blob), &v); err != nil {
		return failClosed("Scanner returned malformed JSON")
	}
	if _, ok := Rank[v.Verdict]; !ok {
		v.Verdict = "SUSPICIOUS"
	}
	return v
}

func isTexty(b []byte) bool {
	n := len(b)
	if n > 4096 {
		n = 4096
	}
	for _, c := range b[:n] {
		if c == 0 {
			return false
		}
	}
	return true
}

// CollectDir reads the scannable text files of a local build directory.
// It skips .git, src and pkg subdirectories, binaries, and oversized files,
// and requires a PKGBUILD to be present.
func CollectDir(dir string) (Files, error) {
	files := Files{}
	total := 0
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "src", "pkg":
				if p != dir {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if info.Size() > maxFileBytes || total > maxTotalBytes {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil || !isTexty(data) {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		files[rel] = string(data)
		total += len(data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, ok := files["PKGBUILD"]; !ok {
		return nil, fmt.Errorf("no PKGBUILD found in %s", dir)
	}
	return files, nil
}
