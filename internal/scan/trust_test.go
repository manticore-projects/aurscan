package scan

import "testing"

func TestTrustScoreBands(t *testing.T) {
	cases := []struct {
		verdict string
		conf    float64
		lo, hi  int
	}{
		{"OK", 100, 100, 100},
		{"OK", 0, 67, 67},
		{"SUSPICIOUS", 0, 66, 66},
		{"SUSPICIOUS", 100, 34, 34},
		{"MALICIOUS", 100, 0, 0},
		{"MALICIOUS", 0, 33, 33},
	}
	for _, c := range cases {
		got := TrustScore(Verdict{Verdict: c.verdict, Confidence: c.conf})
		if got < c.lo || got > c.hi {
			t.Errorf("TrustScore(%s,%.0f)=%d, want in [%d,%d]", c.verdict, c.conf, got, c.lo, c.hi)
		}
	}
	// Bands must not overlap and must be ordered MAL < SUSP < OK.
	mal := TrustScore(Verdict{Verdict: "MALICIOUS", Confidence: 0})
	susp := TrustScore(Verdict{Verdict: "SUSPICIOUS", Confidence: 0})
	ok := TrustScore(Verdict{Verdict: "OK", Confidence: 0})
	if !(mal < susp && susp < ok) {
		t.Errorf("bands not ordered: mal=%d susp=%d ok=%d", mal, susp, ok)
	}
}

func TestCollectStdinAndFile(t *testing.T) {
	f, err := CollectStdin(stringsReader("pkgname=x\nbuild(){ :; }\n"))
	if err != nil || f["PKGBUILD"] == "" {
		t.Fatalf("CollectStdin: %v %v", f, err)
	}
	if _, err := CollectStdin(stringsReader("")); err == nil {
		t.Error("CollectStdin should error on empty input")
	}
}
