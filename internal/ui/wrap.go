package ui

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var terminalWidth int

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

func WrapLine(s string, width int, indent string) string {
	if width <= 0 {
		width = 100
	}
	if indent == "" {
		indent = "  "
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
