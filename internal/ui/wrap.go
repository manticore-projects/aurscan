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
