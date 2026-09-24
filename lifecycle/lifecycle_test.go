package lifecycle

import (
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	today := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		product, version string
		eol              bool
		cycle            string
	}{
		{"Node.js", "12.22.0", true, "12"},
		{"Node.js", "22.1.0", false, ""},
		{"Python", "3.7.9", true, "3.7"},
		{"Python", "3.12", false, ""},
		{"Go", "1.19", true, "1.19"},
		{"jQuery", "1.12.4", true, "1"},
		{"jQuery", "3.7.1", false, ""},
		{".NET", "net6.0", true, "net6.0"},
		{"Unknown", "1", false, ""},
	} {
		st, ok := Check(c.product, c.version, today)
		if ok != c.eol || (ok && st.Cycle != c.cycle) {
			t.Errorf("%s %s: eol=%v %+v", c.product, c.version, ok, st)
		}
	}
	if st, _ := Check("Node.js", ">=12", today); st == nil || st.Exact {
		t.Error("ranges must be reported as inexact")
	}
	if AsOf() == "" {
		t.Error("missing as_of")
	}
}
