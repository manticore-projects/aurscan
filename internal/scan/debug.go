package scan

import (
	"fmt"
	"os"
)

// Debug, when true, makes the scanner print diagnostics to stderr: the selected
// backend, the request payload sent to the model, the raw response received,
// and the reason any LLM communication or JSON parse failed (issue #17).
// Wired from the CLI's --debug flag.
var Debug bool

func dbg(format string, args ...any) {
	if !Debug {
		return
	}
	fmt.Fprintf(os.Stderr, "\033[2m[debug] "+format+"\033[0m\n", args...)
}

// dbgBlock prints a labelled multi-line block (request/response bodies).
func dbgBlock(label, body string) {
	if !Debug {
		return
	}
	fmt.Fprintf(os.Stderr, "\033[2m[debug] ----- %s (%d bytes) -----\n%s\n[debug] ----- end %s -----\033[0m\n",
		label, len(body), body, label)
}
