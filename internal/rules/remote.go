package rules

// Finding the URLs a package fetches and then RUNS.
//
// `curl … | sh` is reported by DLE-001/DLE-002 and that finding is about the
// PINNING, not the content: the script is fetched fresh at every build, is not
// in source=(), and carries no checksum, so what a reviewer reads today is not
// what runs tomorrow. Nothing retrieved from that URL can change that.
//
// What retrieval CAN do is tell a human what the URL serves right now, which is
// often the difference between "install telemetry, harmless, tell the
// maintainer to pin it" and "credential stealer, do not build". Both are useful
// and only one of them is discoverable without looking.
//
// So this exists to feed evidence to the reviewer, never to resolve the
// finding. See pipeline.fetchRemoteScripts for the asymmetry that enforces it.

import (
	"regexp"
	"strings"
)

// pipeToShellURL matches a fetch whose output is piped into a shell — the exact
// shape DLE-001/DLE-002 report. Anchored on the same verbs so the URLs offered
// for retrieval are precisely the ones already flagged, and never a wider set.
var pipeToShellURL = regexp.MustCompile(
	`(?i)\b(?:curl|wget)\b[^\n|]*?(https?://[^\s"'` + "`" + `|)]+)[^\n|]*\|\s*(?:ba|z|k|da)?sh\b`)

// maxRemoteURLs caps how many URLs one package can offer up, so a hostile
// PKGBUILD cannot turn the scanner into a request amplifier.
const maxRemoteURLs = 8

// RemoteExecURLs returns the URLs a package downloads and pipes into a shell.
//
// It deliberately does NOT return source=() entries: those are checksummed by
// makepkg, which is the whole difference. It also skips comments, so a
// commented-out example does not cause a fetch.
func RemoteExecURLs(files map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	for name, text := range files {
		if IsOmitted(text) || !isShellFile(name) {
			continue
		}
		for _, m := range pipeToShellURL.FindAllStringSubmatchIndex(text, -1) {
			if isCommentAt(text, m[0]) {
				continue
			}
			u := strings.TrimRight(text[m[2]:m[3]], `.,;:)`)
			// A URL built from a variable cannot be resolved statically, and
			// guessing at it would be a request to a host nobody named.
			if strings.ContainsAny(u, "$`") || seen[u] {
				continue
			}
			seen[u] = true
			out = append(out, u)
			if len(out) >= maxRemoteURLs {
				return out
			}
		}
	}
	return out
}
