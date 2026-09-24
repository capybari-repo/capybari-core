package engine_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/capybari/capybari-core/analyzer"
	"github.com/capybari/capybari-core/engine"
	"github.com/capybari/capybari-core/finding"
	"github.com/capybari/capybari-core/report"
	"github.com/capybari/capybari-schemas"
)

// TestReportMatchesSchema keeps the Go types and capybari-schemas in sync.
func TestReportMatchesSchema(t *testing.T) {
	a := &fake{c: capOf("a", provides("x"), scores(finding.DimSecurity)), run: func(*analyzer.Input) (*analyzer.Result, error) {
		return &analyzer.Result{
			Evidence: map[string]any{"x": map[string]int{"n": 1}},
			Findings: []finding.Finding{{Dimension: finding.DimSecurity, Category: "secret", Title: "key", Severity: finding.High, Confidence: finding.ConfidenceHigh,
				Evidence:    []finding.Evidence{{Location: finding.Location{Path: "a.env", StartLine: 1}, Snippet: "AKIA****"}},
				Rule:        &finding.Rule{ID: "aws"},
				Remediation: &finding.Remediation{Summary: "Rotate."}}},
			Artifacts: []analyzer.Artifact{{Name: "x.json", MediaType: "application/json", Data: []byte("{}")}},
		}, nil
	}}
	b := &fake{c: capOf("b", func(c *analyzer.Capability) {
		c.Execution.Network = analyzer.RequireRequired
		c.Execution.NetworkHosts = []string{"api.example.com"}
		c.Engines = []analyzer.Engine{{Name: "E", License: "MIT"}}
	})}
	for _, offline := range []bool{true, false} {
		e := newEngine(t, engine.Config{Offline: offline}, a, b)
		r, _, err := e.Analyze(context.Background(), repo, engine.Selection{}, analyzer.Options{analyzer.OptionQuestion: "is it safe?"})
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := report.WriteJSON(&buf, r); err != nil {
			t.Fatal(err)
		}
		if err := schemas.Validate("report.schema.json", buf.Bytes()); err != nil {
			t.Fatalf("offline=%v: report does not match schema: %v\n%s", offline, err, buf.String())
		}
	}
	empty := newEngine(t, engine.Config{})
	r, _, _ := empty.Analyze(context.Background(), repo, engine.Selection{}, nil)
	if err := schemas.ValidateValue("report.schema.json", r); err != nil {
		t.Fatalf("empty report does not match schema: %v", err)
	}
}
