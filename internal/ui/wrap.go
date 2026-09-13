package ui

import (
	"os"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"
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
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdout.Fd(),
		uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
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

// FindingHeadPrefixLen is FindingPrefixLen for the two-line finding layout,
// where the head line carries the severity, the catalog label and the file and
// the note is wrapped underneath it. The framing is
// "  [" + severity + "] " + label + " (" + file + ")".
func FindingHeadPrefixLen(sev, label, file string) int {
	return 8 + len(sev) + len(label) + len(file)
}

// ansiRe matches ANSI/VT100 escape sequences so they can be stripped from
// input before wrapping: their bytes would otherwise consume visible-width
// budget without producing any visible output. LLM-generated findings should
// never contain these, but a leaked color code or a model that echoes terminal
// escapes would corrupt the width arithmetic.
//
// Source: github.com/acarl005/stripansi (MIT License) — the canonical
// community regex for stripping ANSI codes. Covers CSI (\x1b[ and the
// single-byte \x9b form), OSC (terminated by BEL or ST), and the full range
// of intermediate and final bytes, so it handles 256-color, cursor moves,
// title-setting, and other non-color escapes that a narrower color-only
// regex would miss. Kept verbatim rather than vendoring the package to
// avoid adding a dependency for a single regexp.
var ansiRe = regexp.MustCompile(`[\x1b\x9b][[\]()#;?]*(?:(?:(?:[a-zA-Z\d]*(?:;[a-zA-Z\d]*)*)?\x07)|(?:(?:\d{1,4}(?:;\d{0,4})*)?[\dA-PRZcf-ntqry=><~]))`)

// normalizeWrapInput strips ANSI escapes and collapses any run of whitespace
// (spaces, tabs, newlines) into a single space. LLM output may contain
// irregular whitespace (multi-space runs from a model, a literal newline
// inside what should be one sentence, tabs used as separators) which would
// otherwise produce trailing spaces, ragged lines, or orphan words after
// wrapping. strings.Fields already trims leading/trailing whitespace.
func normalizeWrapInput(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	return strings.Join(strings.Fields(s), " ")
}

func WrapLine(s string, width int, indent string) string {
	s = normalizeWrapInput(s)
	if s == "" {
		return ""
	}
	if width <= 0 {
		width = minWrapWidth
	}
	var b strings.Builder
	for {
		if b.Len() > 0 {
			b.WriteByte('\n')
			b.WriteString(indent)
		}
		// Rune-aware length: a multi-byte UTF-8 rune (e.g. an em dash, 3 bytes)
		// occupies one visible column, not three. Measuring by bytes under-fills
		// lines that contain non-ASCII punctuation.
		if utf8.RuneCountInString(s) <= width {
			b.WriteString(s)
			break
		}
		// Find the last space within the width budget (by rune offset). The
		// input is already whitespace-normalized, so every space is a single
		// byte and a single rune; byte indexing is safe here.
		cut := lastSpaceBefore(s, width)
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
		if s == "" {
			break
		}
	}
	return b.String()
}

// lastSpaceBefore returns the byte offset of the last space in s that falls
// at or before the width-th rune, or -1 if there is none. It iterates runes
// without allocating a rune slice: the input is whitespace-normalized (single
// spaces only), so every space is one byte and one rune.
func lastSpaceBefore(s string, width int) int {
	var runeIdx, lastSpaceByte int
	for byteIdx := 0; byteIdx < len(s); {
		r, size := utf8.DecodeRuneInString(s[byteIdx:])
		if runeIdx > width {
			break
		}
		if r == ' ' {
			lastSpaceByte = byteIdx
		}
		byteIdx += size
		runeIdx++
	}
	return lastSpaceByte
}
