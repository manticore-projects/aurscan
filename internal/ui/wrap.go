package ui

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var terminalWidth int

// minWrapWidth is the floor for the content width passed to WrapLine. When a
// caller's prefix is wider than the terminal (e.g. a very long filename),
// w-prefixLen goes negative; clamping here keeps the wrapped tail readable
// instead of falling back to 100 and overflowing a narrow terminal.
const minWrapWidth = 20

// Indent constants for WrapLine continuation lines. Exported so tests can
// reference the same symbols as production code, preventing drift.
const (
	// IndentBody is the 2-space indent for body text: summaries, finding text,
	// hook install messages.
	IndentBody = "  "
	// IndentBlock is the 4-space indent for block-message continuation lines.
	IndentBlock = "    "
	// IndentReport is the 5-space indent for report instructions and install-hook
	// note lines.
	IndentReport = "     "
	// IndentUsage is the indent for usage lines: 2 spaces + arrow glyph.
	IndentUsage = "  ↳ "
	// IndentQuote is the indent for quote continuation: 2 spaces + ">".
	IndentQuote = "  > "
)

// Width offsets subtracted from TerminalWidth() to get the content budget for
// WrapLine. Each pairs with a first-line prefix that WrapLine does not manage.
// The +1 margins preserve the exact widths used before this refactor.
const (
	// PrefixNote is the visible width of IndentReport + "note: " printed before
	// WrapLine in the install-hook note lines, plus a 1-char safety margin.
	PrefixNote = len(IndentReport) + len("note: ") + 1 // 5 + 6 + 1 = 12
	// prefixBlockDecide is the visible width of "!! aurscan blocked this build: ".
	prefixBlockDecide = len("!! aurscan blocked this build: ") // 31
	// prefixBlockGateVia is the visible width of "!! Build blocked: " plus a
	// 1-char safety margin.
	prefixBlockGateVia = len("!! Build blocked: ") + 1 // 18 + 1 = 19
	// prefixBlockGate is the visible width of "!! Installation blocked: ".
	prefixBlockGate = len("!! Installation blocked: ") // 25
)

// terminalWidth is a snapshot taken at startup. It does not update on terminal
// resize during a running scan — wrapping stays consistent with the initial
// viewport for the lifetime of the process.
func init() {
	terminalWidth = detectWidth()
}

func detectWidth() int {
	var ws struct {
		Row, Col       uint16
		XPixel, YPixel uint16
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdout.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 || ws.Col == 0 {
		return 100
	}
	return int(ws.Col)
}

func TerminalWidth() int {
	if terminalWidth <= 0 {
		return 100
	}
	return terminalWidth
}

// FindingPrefixLen returns the visible byte length of the literal framing around
// a finding line: "  [" + severity + "] " + file + ": " — i.e. 2 leading spaces,
// 2 brackets, 1 space after the bracket, a colon, and a space after the colon.
// Callers pass w-FindingPrefixLen(sev,file) as the content width to WrapLine so
// the wrapped finding text aligns under the text after the colon.
func FindingPrefixLen(sev, file string) int {
	return 7 + len(sev) + len(file)
}

func WrapLine(s string, width int, indent string) string {
	if width <= 0 {
		width = minWrapWidth
	}
	var b strings.Builder
	for {
		s = strings.TrimLeft(s, " ")
		if s == "" {
			break
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
			b.WriteString(indent)
		}
		if len(s) <= width {
			b.WriteString(s)
			break
		}
		// Byte-level ops: len() and LastIndexByte work on bytes, not runes.
		// This is correct for the AUR domain (ASCII English text only).
		// The guard above ensures width+1 <= len(s), so the slice is safe.
		cut := strings.LastIndexByte(s[:width+1], ' ')
		if cut < 1 {
			sp := strings.IndexByte(s, ' ')
			if sp < 0 {
				b.WriteString(s)
				break
			}
			b.WriteString(s[:sp])
			s = s[sp+1:]
			continue
		}
		b.WriteString(s[:cut])
		s = s[cut+1:]
	}
	return b.String()
}
