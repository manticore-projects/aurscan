package ui

import (
	"os"
	"syscall"
	"unsafe"
)

var useColor = computeColor()

// computeColor decides colour at startup: NO_COLOR always wins (disable);
// FORCE_COLOR forces colour on even when stdout is not a terminal (the
// conventional escape hatch, useful when output is piped through a pager or a
// hook that redirects stdout); otherwise colour follows whether stdout is a TTY.
func computeColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if v := os.Getenv("FORCE_COLOR"); v != "" && v != "0" {
		return true
	}
	return IsTTY(os.Stdout)
}

// EnableColorForTTY turns colour on when f is a real terminal and the user has
// not opted out via NO_COLOR. The paru PreBuildCommand hook calls this because
// paru runs the hook with stdout redirected to a pipe: the startup check sees a
// non-TTY stdout and disables colour even though the user is watching a
// colour-capable terminal, so hook output (and the codex backend, which is only
// ever used via such a hook here) came out uncoloured (issue #34).
func EnableColorForTTY(f *os.File) {
	if os.Getenv("NO_COLOR") != "" {
		return
	}
	if f != nil && IsTTY(f) {
		useColor = true
	}
}

func color(code, s string) string {
	if !useColor {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func Red(s string) string    { return color("1;31", s) }
func Yellow(s string) string { return color("1;33", s) }
func Green(s string) string  { return color("1;32", s) }
func White(s string) string  { return color("1;37", s) }
func Bold(s string) string   { return color("1", s) }
func Dim(s string) string    { return color("2", s) }

// IsTTY reports whether f is a terminal (Linux TCGETS ioctl). Unlike checking
// os.ModeCharDevice, this correctly returns false for /dev/null, so scripted
// and hook invocations never block on a prompt.
func IsTTY(f *os.File) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(),
		syscall.TCGETS, uintptr(unsafe.Pointer(&t)), 0, 0, 0)
	return errno == 0
}

// tcflsh is the Linux TCFLSH ioctl; tciflush selects the input queue.
const (
	tcflsh   = 0x540B
	tciflush = 0x0
)

// DrainInput discards any keystrokes already buffered on f's terminal input
// queue. It is called immediately before a security prompt so that input typed
// earlier — e.g. ENTER mashed through yay/paru's own prompts while the scan was
// still running — cannot pre-answer aurscan's confirmation. This mirrors the
// input-flush that sudo performs before reading a password. No-op when f is not
// a terminal.
func DrainInput(f *os.File) {
	if f == nil || !IsTTY(f) {
		return
	}
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tcflsh), uintptr(tciflush))
}
