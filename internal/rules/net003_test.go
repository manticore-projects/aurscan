package rules

import "testing"

// curl -k turns an https URL into an unauthenticated one. 1panel-stable-bin
// downloads its binary that way and then verifies it against a checksum file
// fetched from the same host, so one attacker supplies both halves.
func TestInsecureTLSFetch(t *testing.T) {
	fire := map[string]string{
		"curl-k":        `build(){ curl -LOk -o pkg.tar.gz https://example.org/pkg.tar.gz; }`,
		"curl-insecure": `build(){ curl --insecure -O https://example.org/pkg.tar.gz; }`,
		"wget-nocheck":  `build(){ wget --no-check-certificate https://example.org/pkg.tar.gz; }`,
	}
	for n, body := range fire {
		t.Run(n, func(t *testing.T) {
			got := false
			for _, h := range Scan(map[string]string{"PKGBUILD": "pkgname=x\n" + body}) {
				if h.Code == "NET-003" {
					got = true
				}
			}
			if !got {
				t.Errorf("NET-003 should fire on %q", body)
			}
		})
	}

	quiet := map[string]string{
		"plain-curl":    `build(){ curl -LO https://example.org/pkg.tar.gz; }`,
		"curl-K-config": `build(){ curl -K config.txt; }`,
		"wget-plain":    `build(){ wget https://example.org/pkg.tar.gz; }`,
	}
	for n, body := range quiet {
		t.Run(n, func(t *testing.T) {
			for _, h := range Scan(map[string]string{"PKGBUILD": "pkgname=x\n" + body}) {
				if h.Code == "NET-003" {
					t.Errorf("NET-003 false positive on %q: %q", body, h.Snippet)
				}
			}
		})
	}
}

// curl|sh is reported but no longer forces MALICIOUS: a project's own installer
// is a legitimate form, so the model gets to make the call.
func TestPipeToShellIsNotFatal(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": "pkgname=x\nbuild(){ curl -sfL https://sh.rustup.rs | sh; }",
	}
	hits := Scan(files)
	got := false
	for _, h := range hits {
		if h.Code == "DLE-001" {
			got = true
		}
	}
	if !got {
		t.Fatal("DLE-001 must still fire")
	}
	if IsFatal("DLE-001") || IsFatal("DLE-002") {
		t.Error("curl|sh must not be non-overridable: rustup and ghcup are legitimate forms")
	}
	if f := Floor(hits, false); f == "MALICIOUS" {
		t.Errorf("floor = MALICIOUS on a toolchain installer; the model should decide")
	}
}

// A static rule cannot tell whose host a URL belongs to, so its contribution
// must be the cautious classification. Mapping DLE-001/002 to pipe_to_shell —
// which is critical and means "the script's author is not the software's
// author" — put the verdict back at MALICIOUS through deriveVerdict even after
// DLE was taken out of fatalCodes: the same conclusion by a different route.
func TestPipeToShellStaticMapsToWarningTier(t *testing.T) {
	files := map[string]string{
		"PKGBUILD": "pkgname=x\nbuild(){ curl -sfL https://sh.rustup.rs | sh; }",
	}
	fcs := FloorChecks(Scan(files), false)
	for _, fc := range fcs {
		if fc.ID == "pipe_to_shell" {
			t.Errorf("a static curl|sh hit must not claim the critical id: %+v", fc)
		}
	}
	// And the floor must leave room for the model to decide either way.
	if f := Floor(Scan(files), false); f == "MALICIOUS" {
		t.Error("floor = MALICIOUS: the model can no longer classify the host")
	}
}
