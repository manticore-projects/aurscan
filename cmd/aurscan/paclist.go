package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"
)

const (
	paclistFile   = "aurscan.paclist"
	paclistFormat = "aurscan-paclist-v1"
)

var packageNameRe = regexp.MustCompile(`^[A-Za-z0-9@._+-]+$`)

type paclist struct {
	Format      string           `json:"format"`
	GeneratedAt string           `json:"generated_at"`
	Host        string           `json:"host"`
	Source      string           `json:"source"`
	Packages    []paclistPackage `json:"packages"`
}

type paclistPackage struct {
	Name      string `json:"name"`
	Current   string `json:"current,omitempty"`
	Available string `json:"available,omitempty"`
	Raw       string `json:"raw"`
}

func writePaclistFromYay() (int, error) {
	out, err := run("yay", "-Qua")
	if err != nil {
		return 0, fmt.Errorf("yay -Qua failed: %w", err)
	}
	list, err := newPaclist(out)
	if err != nil {
		return 0, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(list); err != nil {
		return 0, err
	}
	if err := os.WriteFile(paclistFile, buf.Bytes(), 0o644); err != nil {
		return 0, err
	}
	return len(list.Packages), nil
}

func readPaclistPackages() ([]string, error) {
	b, err := os.ReadFile(paclistFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s not found in the current directory", paclistFile)
		}
		return nil, err
	}
	var list paclist
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", paclistFile, err)
	}
	if list.Format != paclistFormat {
		return nil, fmt.Errorf("%s has unsupported format %q", paclistFile, list.Format)
	}
	names := make([]string, 0, len(list.Packages))
	seen := map[string]bool{}
	for _, p := range list.Packages {
		if err := validatePackageName(p.Name); err != nil {
			return nil, fmt.Errorf("%s contains invalid package name %q: %w", paclistFile, p.Name, err)
		}
		if !seen[p.Name] {
			seen[p.Name] = true
			names = append(names, p.Name)
		}
	}
	return names, nil
}

func newPaclist(yayOutput string) (paclist, error) {
	host, _ := os.Hostname()
	list := paclist{
		Format:      paclistFormat,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Host:        host,
		Source:      "yay -Qua",
		Packages:    []paclistPackage{},
	}
	for _, line := range splitLines(yayOutput) {
		pkg, ok := parseYayUpdateLine(line)
		if !ok {
			continue
		}
		if err := validatePackageName(pkg.Name); err != nil {
			return paclist{}, fmt.Errorf("yay returned invalid package name %q: %w", pkg.Name, err)
		}
		list.Packages = append(list.Packages, pkg)
	}
	return list, nil
}

func parseYayUpdateLine(line string) (paclistPackage, bool) {
	f := fields(line)
	if len(f) == 0 {
		return paclistPackage{}, false
	}
	name := f[0]
	for i, c := range name {
		if c == '/' {
			name = name[i+1:]
			break
		}
	}
	pkg := paclistPackage{Name: name, Raw: line}
	if len(f) > 1 {
		pkg.Current = f[1]
	}
	for i := 2; i+1 < len(f); i++ {
		if f[i] == "->" {
			pkg.Available = f[i+1]
			break
		}
	}
	return pkg, true
}

func validatePackageName(name string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	if !packageNameRe.MatchString(name) {
		return fmt.Errorf("allowed characters are letters, numbers, @, dot, underscore, plus, and hyphen")
	}
	return nil
}
