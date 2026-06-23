package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

// runAllowExit1 runs a command and treats exit code 1 with no stderr output as
// success with empty output — the "no results" sentinel used by yay -Qua.
// Exit code 1 with stderr content is a real error (AUR RPC down, db lock,
// etc.) and is returned as an error to avoid a silent false negative.
func runAllowExit1(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			if stderr := strings.TrimSpace(string(exitErr.Stderr)); stderr != "" {
				return "", fmt.Errorf("%s", stderr)
			}
			return string(out), nil
		}
		return string(out), err
	}
	return string(out), nil
}

func splitLines(s string) []string { return strings.Split(s, "\n") }
func fields(s string) []string     { return strings.Fields(s) }
