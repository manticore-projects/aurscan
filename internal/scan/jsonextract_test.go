package scan

import "testing"

// The model reasons in prose and quotes shell back at us, and shell is full of
// braces. A greedy `\{.*\}` therefore matched from the first brace in the prose
// — usually inside a ${srcdir} — to the last brace in the reply, and handed the
// unmarshaller garbage. Two packages in a twenty-package sample failed this way,
// and in both the model's answer was a perfectly valid clean verdict that was
// thrown away as SUSPICIOUS.
func TestExtractJSONObjectFromProse(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{
			name: "braces in prose before a fenced answer",
			raw: "Looking at this package carefully:\n" +
				"- `--cache \"${srcdir}/npm-cache\"` — cache goes into $srcdir\n" +
				"- `--prefix \"${pkgdir}/usr\"` — installs into fakeroot $pkgdir\n" +
				"This is the standard pattern. **False positive.**\n" +
				"```json\n{\"checks\": []}\n```\n",
			want: `{"checks": []}`,
		},
		{
			name: "bare object after prose, no fence",
			raw:  "The ${pkgdir} reference is fine.\n{\"checks\": []}",
			want: `{"checks": []}`,
		},
		{
			name: "nested check objects must not be mistaken for the reply",
			raw:  `{"checks":[{"id":"prompt_injection","triggered":true,"file":"PKGBUILD","evidence":"x"}]}`,
			want: `{"checks":[{"id":"prompt_injection","triggered":true,"file":"PKGBUILD","evidence":"x"}]}`,
		},
		{
			name: "legacy verdict shape",
			raw:  "Here is my analysis: {\"verdict\":\"OK\",\"confidence\":90,\"findings\":[]}",
			want: `{"verdict":"OK","confidence":90,"findings":[]}`,
		},
		{
			name: "a brace inside an evidence string does not end the object",
			raw:  `{"checks":[{"id":"other_warning","triggered":true,"evidence":"cd ${srcdir}/x"}]}`,
			want: `{"checks":[{"id":"other_warning","triggered":true,"evidence":"cd ${srcdir}/x"}]}`,
		},
		{
			name: "trailing prose after the object",
			raw:  "{\"checks\": []}\nLet me know if you want ${more} detail.",
			want: `{"checks": []}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractJSONObject(c.raw); got != c.want {
				t.Errorf("extractJSONObject:\n got %q\nwant %q", got, c.want)
			}
		})
	}
}

// End to end: a prose-wrapped clean checklist must parse as a genuine OK, not
// fail closed.
func TestProseWrappedChecklistParsesAsGenuine(t *testing.T) {
	raw := "The `${srcdir}` and `${pkgdir}` uses are correct.\n```json\n{\"checks\": []}\n```"
	v, genuine := parseVerdictResult(raw)
	if !genuine {
		t.Fatal("a clean checklist wrapped in prose must be genuine, not fail-closed")
	}
	if v.Verdict != "OK" {
		t.Errorf("verdict = %q, want OK", v.Verdict)
	}
}

func TestBalancedObject(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"a":1}`, `{"a":1}`},
		{`{"a":{"b":2}} trailing`, `{"a":{"b":2}}`},
		{`{"a":"}"}`, `{"a":"}"}`},
		{`{"a":"\""}`, `{"a":"\""}`},
		{`{"a":1`, ``},
		{`not an object`, ``},
	}
	for _, c := range cases {
		if got := balancedObject(c.in); got != c.want {
			t.Errorf("balancedObject(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
