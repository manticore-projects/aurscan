package main

import (
	"os/exec"
	"strings"
)

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

func splitLines(s string) []string { return strings.Split(s, "\n") }
func fields(s string) []string     { return strings.Fields(s) }
