package main

import (
	"os/exec"
	"strings"
)

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

// runAllowExit1 runs a command and treats exit code 1 as success with empty
// output. Used for commands like "yay -Qua" that exit 1 to signal "no results".
func runAllowExit1(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return string(out), nil
		}
		return string(out), err
	}
	return string(out), nil
}

func splitLines(s string) []string { return strings.Split(s, "\n") }
func fields(s string) []string     { return strings.Fields(s) }
