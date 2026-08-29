package fetch

// Retrieving the scripts a package pipes into a shell.
//
// This is evidence-gathering, and it is off by default for four reasons worth
// stating, because each one is a way it could mislead:
//
//   - Cloaking. Fetching tells the server it is being scanned. A host that
//     serves benign content to a scanner and a payload to real builds turns
//     this feature into a machine for producing false assurance — worse than
//     not looking at all.
//   - Time of check, time of use. The finding being investigated is precisely
//     "this content is not pinned". Retrieving it once does not pin it.
//   - Offline guarantee. --rules-only is fully offline today. Fetching
//     attacker-chosen URLs is a new network surface, and across a large sweep
//     it is also a lot of unsolicited traffic to other people's hosts.
//   - Recursion. The fetched script may itself pipe something into a shell.
//
// Hence: opt-in, capped, and labelled at every point as content at fetch time
// rather than content that will run.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// maxBytes caps a single response. Install scripts are small; anything
	// larger is not something a reviewer will read anyway.
	maxBytes = 64 * 1024
	timeout  = 10 * time.Second
)

// Result is one retrieved script, or the reason it could not be retrieved.
type Result struct {
	URL     string
	Content string // empty when Err is set
	SHA256  string // of the bytes retrieved, so a later fetch can be compared
	Bytes   int
	Err     error
}

// Script retrieves one URL. Redirects are followed but only within http(s), and
// the body is truncated at maxBytes. A non-text response is discarded: the
// point is to show a reviewer what the script says, and a binary tells them
// nothing they can read.
func Script(ctx context.Context, url string) Result {
	r := Result{URL: url}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		r.Err = fmt.Errorf("refusing non-http(s) scheme")
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		r.Err = err
		return r
	}
	// Identify honestly. A host that would rather not be scanned can then block
	// us, which is their right and better than pretending to be a browser.
	req.Header.Set("User-Agent", "aurscan (+https://github.com/manticore-projects/aurscan)")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if s := req.URL.Scheme; s != "http" && s != "https" {
				return fmt.Errorf("refusing redirect to scheme %q", s)
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		r.Err = err
		return r
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.Err = fmt.Errorf("HTTP %d", resp.StatusCode)
		return r
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		r.Err = err
		return r
	}
	if len(body) > maxBytes {
		body = body[:maxBytes]
	}
	if !isTexty(body) {
		r.Err = fmt.Errorf("response is not text (%d bytes)", len(body))
		return r
	}
	sum := sha256.Sum256(body)
	r.Content = string(body)
	r.SHA256 = hex.EncodeToString(sum[:])
	r.Bytes = len(body)
	return r
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
