package main

import "testing"

func TestIsValidPkgName(t *testing.T) {
	valid := []string{
		"yay",
		"paru",
		"my-package",
		"my_package",
		"pkg.name",
		"pkg+extra",
		"pkg123",
		"a",
		"0pkg",
		"pkg@local",
	}
	for _, name := range valid {
		if !isValidPkgName(name) {
			t.Errorf("isValidPkgName(%q) = false, want true", name)
		}
	}

	invalid := []string{
		"-flag",
		"--install-yay-hook",
		"-Qua",
		".hidden",
		"",
		"-",
		"--",
		"BAD",
		"Bad_Pkg",
		"has space",
		"bad/name",
	}
	for _, name := range invalid {
		if isValidPkgName(name) {
			t.Errorf("isValidPkgName(%q) = true, want false", name)
		}
	}
}
