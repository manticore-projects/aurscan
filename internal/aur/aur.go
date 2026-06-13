package aur

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/manticore-projects/aurscan/internal/scan"
)

const (
	rpcURL        = "https://aur.archlinux.org/rpc/v5/info"
	snapshotURL   = "https://aur.archlinux.org/cgit/aur.git/snapshot/%s.tar.gz"
	PkgURLFmt     = "https://aur.archlinux.org/packages/%s"
	maxFileBytes  = 64 * 1024
	maxTotalBytes = 240 * 1024
	httpTimeout   = 30 * time.Second
)

var client = &http.Client{Timeout: httpTimeout}

func httpGet(u string) ([]byte, int, error) {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "aurscan/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return b, resp.StatusCode, err
}

// Info is the subset of AUR RPC fields we use.
type Info struct {
	Name        string
	PackageBase string
}

// Lookup resolves a single package via the AUR RPC v5 info endpoint.
// Returns (nil, nil) when the package does not exist in the AUR.
func Lookup(name string) (*Info, error) {
	body, status, err := httpGet(rpcURL + "?arg[]=" + url.QueryEscape(name))
	if err != nil || status != 200 {
		return nil, fmt.Errorf("AUR RPC failed (%v, HTTP %d)", err, status)
	}
	var out struct {
		Results []Info `json:"results"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	for i := range out.Results {
		if out.Results[i].Name == name {
			return &out.Results[i], nil
		}
	}
	return nil, nil
}

// FetchSnapshot downloads and parses a package's snapshot tarball entirely in
// memory — nothing from the suspect package is ever written to disk. The bool
// is false when the package is not found (HTTP 404).
func FetchSnapshot(pkgbase string) (scan.Files, bool, error) {
	body, status, err := httpGet(fmt.Sprintf(snapshotURL, url.PathEscape(pkgbase)))
	if err != nil {
		return nil, false, err
	}
	if status == 404 {
		return nil, false, nil
	}
	if status != 200 {
		return nil, false, fmt.Errorf("snapshot HTTP %d", status)
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	tr := tar.NewReader(gz)
	files := scan.Files{}
	total := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, err
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size > maxFileBytes || total > maxTotalBytes {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxFileBytes+1))
		if err != nil || !isTexty(data) {
			continue
		}
		rel := hdr.Name
		if i := strings.Index(rel, "/"); i >= 0 {
			rel = rel[i+1:]
		}
		files[rel] = string(data)
		total += len(data)
	}
	return files, true, nil
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

var depRe = regexp.MustCompile(`(?m)^\s*(depends|makedepends|checkdepends)\s*=\s*(\S+)`)

func depsFromSrcinfo(files scan.Files) []string {
	seen := map[string]bool{}
	var deps []string
	for _, m := range depRe.FindAllStringSubmatch(files[".SRCINFO"], -1) {
		d := m[2]
		if i := strings.IndexAny(d, "<>="); i >= 0 {
			d = d[:i]
		}
		if d != "" && !seen[d] {
			seen[d] = true
			deps = append(deps, d)
		}
	}
	sort.Strings(deps)
	return deps
}

// PacmanHas reports whether a dependency is satisfiable from the official repos
// (so we don't waste a scan on a non-AUR package).
func PacmanHas(pkg string) bool {
	if _, err := exec.LookPath("pacman"); err != nil {
		return false
	}
	if exec.Command("pacman", "-Si", "--", pkg).Run() == nil {
		return true
	}
	return exec.Command("pacman", "-Ssq", "^"+regexp.QuoteMeta(pkg)+"$").Run() == nil
}

func maxPkgs() int {
	n := 25
	fmt.Sscanf(os.Getenv("AURSCAN_MAX_PKGS"), "%d", &n)
	return n
}

// ScanRecursive scans the given root packages plus their AUR dependency
// closure (official-repo deps are skipped). Progress is reported via the
// optional onScan callback before each package is sent to the model.
func ScanRecursive(roots []string, onScan func(pkg string, nfiles int)) []scan.Result {
	var results []scan.Result
	queue := append([]string(nil), roots...)
	seen := map[string]bool{}
	cap := maxPkgs()
	for len(queue) > 0 && len(seen) < cap {
		pkg := queue[0]
		queue = queue[1:]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true

		pkgbase := pkg
		if info, err := Lookup(pkg); err == nil && info != nil {
			pkgbase = info.PackageBase
		}
		files, found, err := FetchSnapshot(pkgbase)
		if err != nil {
			results = append(results, scan.Result{
				Pkg: pkg,
				V:   scan.Verdict{Verdict: "SUSPICIOUS", Summary: "Could not fetch AUR snapshot: " + err.Error() + " (fail-closed)"},
			})
			continue
		}
		if !found {
			results = append(results, scan.Result{
				Pkg: pkg,
				V:   scan.Verdict{Verdict: "OK", Summary: "not found in AUR (skipped)"},
			})
			continue
		}
		if onScan != nil {
			onScan(pkg, len(files))
		}
		results = append(results, scan.Scan(pkg, files))
		for _, dep := range depsFromSrcinfo(files) {
			if seen[dep] || PacmanHas(dep) {
				continue
			}
			if info, err := Lookup(dep); err == nil && info != nil {
				queue = append(queue, dep)
			}
		}
	}
	return results
}
