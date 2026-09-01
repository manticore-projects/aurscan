package rules

import (
	"strings"
	"testing"
)

func hasDEP001(files map[string]string) bool {
	for _, h := range Scan(files) {
		if h.Code == "DEP-001" {
			return true
		}
	}
	return false
}

func pkgbuild(body string) map[string]string {
	return map[string]string{"PKGBUILD": "pkgname=x\npkgver=1\n" + body + "\n"}
}

func TestDEP001DetectsPinnedFetches(t *testing.T) {
	pinned := map[string]string{
		"npm ci":            "build() {\n  npm ci\n}",
		"cargo locked":      "build() {\n  cargo build --release --locked\n}",
		"cargo frozen":      "build() {\n  cargo build --frozen\n}",
		"yarn frozen":       "build() {\n  yarn install --frozen-lockfile\n}",
		"yarn berry":        "build() {\n  yarn install --immutable\n}",
		"pnpm frozen":       "build() {\n  pnpm install --frozen-lockfile\n}",
		"pip hashes":        "build() {\n  pip install --require-hashes -r req.txt\n}",
		"go vendored":       "build() {\n  go build -mod=vendor ./cmd/x\n}",
		"go plain (go.sum)": "build() {\n  go build ./cmd/x\n}",
	}
	for name, body := range pinned {
		t.Run(name, func(t *testing.T) {
			if !hasDEP001(pkgbuild(body)) {
				t.Errorf("DEP-001 not raised for a pinned fetch")
			}
		})
	}
}

func TestDEP001SilentOnUnpinnedFetches(t *testing.T) {
	unpinned := map[string]string{
		"npm install":  "build() {\n  npm install\n}",
		"cargo build":  "build() {\n  cargo build --release\n}",
		"pip -r":       "build() {\n  pip install -r requirements.txt\n}",
		"yarn install": "build() {\n  yarn install\n}",
	}
	for name, body := range unpinned {
		t.Run(name, func(t *testing.T) {
			if hasDEP001(pkgbuild(body)) {
				t.Errorf("DEP-001 raised for an UNPINNED fetch — the downgrade would be unearned")
			}
		})
	}
}

// go.sum verification can be switched off, and then a plain `go build` is no
// longer pinned.
func TestDEP001RespectsDisabledSumVerification(t *testing.T) {
	for _, body := range []string{
		"build() {\n  export GOFLAGS=-mod=mod\n  go build ./cmd/x\n}",
		"build() {\n  GOSUMDB=off go build ./cmd/x\n}",
		"build() {\n  export GONOSUMDB=example.com\n  go build ./cmd/x\n}",
	} {
		if hasDEP001(pkgbuild(body)) {
			t.Errorf("DEP-001 raised despite disabled module verification:\n%s", body)
		}
	}
}

// A pinning flag with no dependency fetch to pin is not a mitigation of
// anything and must not be reported.
func TestDEP001NeedsAnActualFetch(t *testing.T) {
	if hasDEP001(pkgbuild("build() {\n  echo '--locked'\n  make\n}")) {
		t.Error("DEP-001 raised without a package-manager invocation")
	}
}

// It is an info-tier mitigation and must never move a rules-only verdict.
func TestDEP001IsInfoSeverity(t *testing.T) {
	for _, h := range Scan(pkgbuild("build() {\n  npm ci\n}")) {
		if h.Code == "DEP-001" && string(h.Severity) != "info" {
			t.Errorf("DEP-001 severity = %q, want info", h.Severity)
		}
	}
	if Floor(Scan(pkgbuild("build() {\n  npm ci\n}")), true) == "MALICIOUS" {
		t.Error("DEP-001 must never reach the floor")
	}
}

// The rule maps to a catalog id, or AllChecks would silently record it as a
// bare note and confinePinnedDeps would never see it.
func TestDEP001MapsToPinnedCheckID(t *testing.T) {
	got := ""
	for _, c := range AllChecks(Scan(pkgbuild("build() {\n  npm ci\n}"))) {
		if strings.Contains(c.Note, "DEP-001") {
			got = c.ID
		}
	}
	if got != "pkg_manager_deps_pinned" {
		t.Errorf("DEP-001 check id = %q, want pkg_manager_deps_pinned", got)
	}
}
