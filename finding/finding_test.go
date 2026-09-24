package finding

import "testing"

func TestComputeIDStableAcrossLineShifts(t *testing.T) {
	a := Finding{Category: "secret", Source: Source{Capability: "secrets"}, Rule: &Rule{ID: "aws"},
		Evidence: []Evidence{{Location: Location{Path: "a.env", StartLine: 3}, Snippet: "AKIA****"}}}
	b := a
	b.Evidence = []Evidence{{Location: Location{Path: "a.env", StartLine: 30}, Snippet: "AKIA****"}}
	if a.ComputeID() != b.ComputeID() {
		t.Fatal("ID should ignore line numbers when a snippet is present")
	}
	c := a
	c.Evidence = []Evidence{{Location: Location{Path: "b.env", StartLine: 3}, Snippet: "AKIA****"}}
	if a.ComputeID() == c.ComputeID() {
		t.Fatal("different paths must give different IDs")
	}
}

func TestSortAndCounts(t *testing.T) {
	fs := []Finding{
		{Title: "b", Severity: Low, Confidence: ConfidenceHigh},
		{Title: "a", Severity: Critical, Confidence: ConfidenceLow},
		{Title: "c", Severity: Critical, Confidence: ConfidenceHigh},
	}
	Sort(fs)
	if fs[0].Title != "c" || fs[1].Title != "a" || fs[2].Title != "b" {
		t.Fatalf("order: %s %s %s", fs[0].Title, fs[1].Title, fs[2].Title)
	}
	if c := Counts(fs); c[Critical] != 2 || c[Low] != 1 || c[High] != 0 {
		t.Fatalf("counts: %v", c)
	}
}

func TestParseSeverityAndRedact(t *testing.T) {
	if s, err := ParseSeverity(" HIGH "); err != nil || s != High {
		t.Fatalf("ParseSeverity: %v %v", s, err)
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Fatal("expected error")
	}
	if got := Redact("AKIAIOSFODNN7EXAMPLE"); got != "AKIA****************" {
		t.Fatalf("Redact = %q", got)
	}
	if got := Redact("short"); got != "*****" {
		t.Fatalf("Redact short = %q", got)
	}
}
