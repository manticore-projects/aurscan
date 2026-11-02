package scan

import (
	"strings"
	"testing"
)

// Observed on network-monitor-bin: the install scriptlet runs
// setcap cap_bpf,cap_net_admin,cap_perfmon=eip on the package's own eBPF
// network monitor — the documented install step of this package class — and
// the model's only vocabulary for it was privilege_persistence, which blocked
// the build as MALICIOUS at 90% confidence. The legitimate form must exist at
// warning tier: a system-wide caps grant to an unreviewed prebuilt binary
// warrants review, not an accusation.
const setcapEv = `setcap cap_bpf,cap_net_admin,cap_perfmon=eip usr/bin/network-monitor`

func TestSetcapForOwnBinaryDoesNotBlock(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "setcap_for_own_binary", Triggered: true,
			File: "network-monitor.install", Evidence: setcapEv,
			Note: "caps match the eBPF monitor's documented requirements; '=eip' is broader than upstream's '=ep'"},
	})
	if v.Verdict != "SUSPICIOUS" {
		t.Errorf("verdict = %q, want SUSPICIOUS: a documented caps grant must surface for review, not block", v.Verdict)
	}
	for _, f := range v.Findings {
		if f.Severity != "warning" {
			t.Errorf("severity = %q, want warning: %+v", f.Severity, f)
		}
	}
}

// A model that reports both ids for the same setcap line has hedged; the
// warning is the more specific claim (it asserts the caps fit the package's
// function) and is the one that stands.
func TestSetcapHedgeResolvesToWarning(t *testing.T) {
	v := VerdictFromChecks([]Check{
		{ID: "privilege_persistence", Triggered: true,
			File: "network-monitor.install", Evidence: setcapEv,
			Note: "grants capabilities system-wide, though they match the tool's purpose"},
		{ID: "setcap_for_own_binary", Triggered: true,
			File: "network-monitor.install", Evidence: setcapEv,
			Note: "caps match the eBPF monitor's documented requirements"},
	})
	if v.Verdict != "SUSPICIOUS" {
		t.Errorf("verdict = %q, want SUSPICIOUS: the hedge must resolve to the specific claim", v.Verdict)
	}
	if len(v.Findings) != 1 {
		t.Errorf("expected 1 finding after resolving the hedge, got %d", len(v.Findings))
	}
}

// Both siblings of privilege_persistence must resolve independently: a
// sudoers hedge on one line and a setcap hedge on another in the same package.
func TestBothPrivilegeSiblingsResolve(t *testing.T) {
	const sudoersEv = `install -m440 monitord-sudoers /etc/sudoers.d/monitord`
	v := VerdictFromChecks([]Check{
		{ID: "privilege_persistence", Triggered: true, File: "x.install", Evidence: setcapEv},
		{ID: "setcap_for_own_binary", Triggered: true, File: "x.install", Evidence: setcapEv},
		{ID: "privilege_persistence", Triggered: true, File: "x.install", Evidence: sudoersEv},
		{ID: "sudoers_for_own_service", Triggered: true, File: "x.install", Evidence: sudoersEv},
	})
	if v.Verdict != "SUSPICIOUS" {
		t.Errorf("verdict = %q, want SUSPICIOUS", v.Verdict)
	}
	for _, f := range v.Findings {
		if f.Severity == "critical" {
			t.Errorf("a hedged critical survived: %+v", f)
		}
	}
	if len(v.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(v.Findings))
	}
}

// The genuine escalations privilege_persistence exists for must still block:
// setuid, and a caps grant no function of the package explains.
func TestGenuinePrivilegeEscalationStillBlocks(t *testing.T) {
	for _, ev := range []string{
		`chmod u+s usr/bin/helper`,
		`setcap cap_setuid,cap_dac_override=ep usr/bin/markdown-editor`,
	} {
		v := VerdictFromChecks([]Check{
			{ID: "privilege_persistence", Triggered: true, File: "x.install", Evidence: ev},
		})
		if v.Verdict != "MALICIOUS" {
			t.Errorf("verdict = %q, want MALICIOUS for %q", v.Verdict, ev)
		}
	}
}

// The prompt must carry the flag-semantics correction: the model reported the
// 'i' flag as letting "child processes inherit" the caps, which file
// capabilities do not do on their own. The guidance exists so the note states
// the semantics correctly instead of escalating on them.
func TestPromptCorrectsInheritableFlagSemantics(t *testing.T) {
	for _, want := range []string{
		"setcap_for_own_binary",
		"does NOT propagate the capability to child processes",
		"ambient",
	} {
		if !strings.Contains(Instructions, want) {
			t.Errorf("the auditor instructions do not mention %q", want)
		}
	}
}
