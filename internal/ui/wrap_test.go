package ui

import (
	"strings"
	"testing"
)

func TestWrapLineWidthZero(t *testing.T) {
	long := strings.Repeat("hello world ", 20)
	got := WrapLine(long, 0, "")
	if !strings.Contains(got, "\n") {
		t.Fatalf("width 0 should clamp to minWrapWidth and wrap: %q", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if len(line) > minWrapWidth {
			t.Fatalf("width 0 line exceeds minWrapWidth %d: %q (%d)", minWrapWidth, line, len(line))
		}
	}
}

func TestWrapLineNegativeWidthDoesNotOverflow(t *testing.T) {
	long := strings.Repeat("hello world ", 20)
	got := WrapLine(long, -50, "  ")
	for _, line := range strings.Split(got, "\n") {
		if len(line) > minWrapWidth {
			t.Fatalf("negative width line exceeds minWrapWidth %d: %q (%d)", minWrapWidth, line, len(line))
		}
	}
}

func TestWrapLineShorterThanWidth(t *testing.T) {
	got := WrapLine("short", 80, "  ")
	if got != "short" {
		t.Fatalf("got %q, want %q", got, "short")
	}
}

func TestWrapLineWrapsAtWordBoundary(t *testing.T) {
	got := WrapLine("hello world this is", 12, "  ")
	want := "hello world\n  this is"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWrapLineSingleLongWordNotSplit(t *testing.T) {
	got := WrapLine("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 10, "  ")
	if strings.Contains(got, "\n") {
		t.Fatalf("long word should not be split: %q", got)
	}
}

func TestWrapLineEmpty(t *testing.T) {
	got := WrapLine("", 80, "  ")
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestWrapLineWhitespaceOnly(t *testing.T) {
	got := WrapLine("   ", 80, "  ")
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestWrapLineMultipleWraps(t *testing.T) {
	got := WrapLine("one two three four five six seven eight nine ten", 14, ">>")
	want := "one two three\n>>four five six\n>>seven eight\n>>nine ten"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWrapLineIndentPreserved(t *testing.T) {
	got := WrapLine("a bb ccc dddd eeeee ffffff ggggggg", 10, "    ")
	lines := strings.Split(got, "\n")
	for i := 1; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "    ") {
			t.Fatalf("continuation line %d missing indent: %q", i, lines[i])
		}
		if len(strings.TrimPrefix(lines[i], "    ")) > 10 {
			t.Fatalf("continuation line %d exceeds width: %q", i, lines[i])
		}
	}
}

func TestWrapLineLongWordThenShort(t *testing.T) {
	got := WrapLine("ABCDEFGHIJKLMNOPQRSTUVWXYZ short", 10, "  ")
	want := "ABCDEFGHIJKLMNOPQRSTUVWXYZ\n  short"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWrapLineExactWidth(t *testing.T) {
	got := WrapLine("1234567890", 10, "  ")
	if got != "1234567890" {
		t.Fatalf("got %q, want exact width no wrap", got)
	}
}

func TestWrapLineJustOverWidth(t *testing.T) {
	got := WrapLine("1234567890 a", 10, "  ")
	want := "1234567890\n  a"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWrapLineWidth80(t *testing.T) {
	s := "A PKGBUILD source entry labelled 'patches' points at a personal GitHub " +
		"repo unrelated to the upstream project and is executed during build."
	got := WrapLine(s, 80, "         ")
	lines := strings.Split(got, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected wrapping at width 80, got %d lines: %q", len(lines), got)
	}
	for i, line := range lines {
		content := line
		if i > 0 {
			if !strings.HasPrefix(line, "         ") {
				t.Fatalf("continuation line %d missing indent: %q", i, line)
			}
			content = strings.TrimPrefix(line, "         ")
		}
		if len(content) > 80 {
			t.Fatalf("line %d exceeds width 80: %q (%d chars)", i, line, len(content))
		}
	}
}

func TestWrapLineWidth120(t *testing.T) {
	s := "The build script downloads and executes a binary from a CDN URL that was " +
		"registered less than 24 hours ago, uses a self-signed certificate, and " +
		"obfuscates the download command with base64 decoding before piping to bash."
	got := WrapLine(s, 120, "         ")
	lines := strings.Split(got, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected wrapping at width 120, got %d lines: %q", len(lines), got)
	}
	for i, line := range lines {
		content := line
		if i > 0 {
			if !strings.HasPrefix(line, "         ") {
				t.Fatalf("continuation line %d missing indent: %q", i, line)
			}
			content = strings.TrimPrefix(line, "         ")
		}
		if len(content) > 120 {
			t.Fatalf("line %d exceeds width 120: %q (%d chars)", i, line, len(content))
		}
	}
}

func TestWrapQuotePrefix(t *testing.T) {
	s := "the file downloads and executes a remote binary from a URL that was registered less than 24 hours ago"
	const indent = "             > "
	got := WrapLine(s, 40, indent)
	lines := strings.Split(got, "\n")
	for i, line := range lines {
		if i > 0 && !strings.HasPrefix(line, indent) {
			t.Fatalf("continuation line %d missing quote indent: %q", i, line)
		}
		content := line
		if i > 0 {
			content = strings.TrimPrefix(line, indent)
		}
		if len(content) > 40 {
			t.Fatalf("line %d content exceeds width 40: %q (%d)", i, content, len(content))
		}
	}
}

func TestWrapUsageLine(t *testing.T) {
	s := "in: 500 · out: 320 · cost: $0.05  in: 600 · out: 400 · cost: $0.08"
	got := WrapLine(s, 30, "         \u21b3 ")
	lines := strings.Split(got, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected wrapping, got %q", got)
	}
	for i, line := range lines {
		if i > 0 {
			if !strings.HasPrefix(line, "         \u21b3 ") {
				t.Fatalf("continuation line %d missing usage indent: %q", i, line)
			}
		}
	}
}

func TestWrapBlockMessage(t *testing.T) {
	msg := "5 package(s) flagged MALICIOUS with multiple findings across several PKGBUILDs and install scripts"
	got := WrapLine(msg, 50, "    ")
	lines := strings.Split(got, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected wrapping, got %q", got)
	}
	for i, line := range lines {
		if i > 0 {
			if !strings.HasPrefix(line, "    ") {
				t.Fatalf("continuation line %d missing block indent: %q", i, line)
			}
			content := strings.TrimPrefix(line, "    ")
			if len(content) > 50 {
				t.Fatalf("continuation line %d exceeds width 50: %q (%d chars)", i, line, len(content))
			}
		}
	}
}

func TestWrapHookMessage(t *testing.T) {
	s := "Plain `yay` (v14) will now scan AUR packages after download, before build, with automatic malware detection enabled by default for all future runs"
	got := WrapLine(s, 70, "      ")
	lines := strings.Split(got, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected wrapping, got %q", got)
	}
	for i, line := range lines {
		if i > 0 {
			content := strings.TrimPrefix(line, "      ")
			if len(content) > 70 {
				t.Fatalf("continuation line %d exceeds width 70: %q (%d chars)", i, line, len(content))
			}
		}
	}
}

func TestWrapScannerUsage(t *testing.T) {
	s := "scanner usage: 5 call(s) \u00b7 in: 2048 \u00b7 out: 1536 \u00b7 cost: $0.10  in: 4096 \u00b7 out: 3072 \u00b7 cost: $0.20"
	got := WrapLine(s, 50, "scanner usage: ")
	lines := strings.Split(got, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected wrapping, got %q", got)
	}
	for i, line := range lines {
		if i > 0 {
			if !strings.HasPrefix(line, "scanner usage: ") {
				t.Fatalf("continuation line %d missing scanner usage indent: %q", i, line)
			}
		}
	}
}

func TestWrapReportInstructions(t *testing.T) {
	s := "Review it carefully with your security team, then email it to aurscan@manticore-projects.com for triage and upstream disclosure coordination"
	got := WrapLine(s, 50, "   ")
	lines := strings.Split(got, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected wrapping, got %q", got)
	}
	for i, line := range lines {
		if i > 0 {
			if !strings.HasPrefix(line, "   ") {
				t.Fatalf("continuation line %d missing report indent: %q", i, line)
			}
		}
	}
}
