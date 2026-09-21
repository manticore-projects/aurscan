package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manticore-projects/aurscan/internal/rules"
)

// A yay/paru build directory for jre-jetbrains after the source was
// downloaded: the release tarball sits next to the PKGBUILD. It must not be
// described to the auditor as a repository file.
func TestCollectDirMarksDownloadedSourceAsArtifact(t *testing.T) {
	dir := t.TempDir()
	pkgbuild := `pkgname=jre-jetbrains
_v=25.0.4.1
_b=610.67
_zipname="jbr_jcef-$_v-linux-x64-b$_b.tar.gz"
source=("https://cache-redirector.jetbrains.com/intellij-jbr/${_zipname}")
`
	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("PKGBUILD", []byte(pkgbuild))
	write("jbr_jcef-25.0.4.1-linux-x64-b610.67.tar.gz", []byte("\x1f\x8b\x00\x00binary"))
	write("jre-jetbrains-25.0.4.1b610.67-2-x86_64.pkg.tar.zst", []byte("\x28\xb5\x2f\xfd\x00"))
	write("stray.bin", []byte("\x00\x01")) // committed binary: stays omitted

	files, err := CollectDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"jbr_jcef-25.0.4.1-linux-x64-b610.67.tar.gz", "jre-jetbrains-25.0.4.1b610.67-2-x86_64.pkg.tar.zst"} {
		if !rules.IsArtifact(files[n]) {
			t.Errorf("%s: not marked as a makepkg artifact", n)
		}
	}
	if files["stray.bin"] != rules.OmittedContent {
		t.Errorf("stray.bin must stay an omitted repository file")
	}

	p := buildPrompt("jre-jetbrains", files, Signals{})
	omittedSec := section(p, "FILES PRESENT BUT NOT SUPPLIED")
	if strings.Contains(omittedSec, "jbr_jcef") {
		t.Errorf("downloaded tarball listed as present-but-not-supplied:\n%s", omittedSec)
	}
	if !strings.Contains(section(p, "MAKEPKG ARTIFACTS"), "jbr_jcef-25.0.4.1-linux-x64-b610.67.tar.gz") {
		t.Errorf("artifacts section missing the tarball:\n%s", p)
	}
	if strings.Contains(p, rules.ArtifactContent) {
		t.Error("artifact marker leaked into the prompt")
	}
}

// With only artifacts and no omissions, the prompt must still say the
// repository listing is complete.
func TestPromptCompleteWhenOnlyArtifacts(t *testing.T) {
	files := Files{"PKGBUILD": "pkgname=x\n", "x-1.tar.gz": rules.ArtifactContent}
	p := buildPrompt("x", files, Signals{})
	if strings.Contains(p, "FILES PRESENT BUT NOT SUPPLIED") {
		t.Error("an artifact produced a present-but-not-supplied section")
	}
	if !strings.Contains(p, "Every file in the package is listed above") {
		t.Error("completeness statement missing")
	}
}

// section returns the prompt text from the named header to the next header.
func section(p, header string) string {
	i := strings.Index(p, header)
	if i < 0 {
		return ""
	}
	rest := p[i+len(header):]
	if j := strings.Index(rest, "\n-----"); j >= 0 {
		return rest[:j]
	}
	return rest
}
