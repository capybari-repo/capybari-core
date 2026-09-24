package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/report"
)

func sample() *report.Report {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return &report.Report{
		SchemaVersion: report.SchemaVersion,
		Tool:          report.Tool{Name: "capybari", Version: "0.1.0"},
		Scan: report.Scan{ID: "scn_1", Target: analyzer.Target{Kind: analyzer.TargetRepository, Input: ".", Display: "demo <b>"},
			StartedAt: t0, FinishedAt: t0.Add(time.Second), DurationMS: 1000},
		Summary: report.Summary{Headline: "demo: 1 critical/high finding(s)", Counts: map[finding.Severity]int{finding.High: 1}},
		Scores:  []report.Score{{ID: "security", Name: "Security", Value: 70, Rating: "fair", Confidence: finding.ConfidenceHigh, Summary: "1 high"}},
		Findings: []finding.Finding{{
			ID: "CSI-1", Dimension: "security", Category: "secret", Title: "AWS key <script>", Severity: finding.High, Confidence: finding.ConfidenceHigh,
			Evidence:    []finding.Evidence{{Location: finding.Location{Path: "config/app.env", StartLine: 4}, Snippet: "AKIA****"}},
			Source:      finding.Source{Capability: "secrets", Version: "0.1.0"},
			Rule:        &finding.Rule{ID: "aws-access-token"},
			Remediation: &finding.Remediation{Summary: "Rotate the key."},
			DetectedAt:  t0, BaselineState: finding.BaselineNew,
		}},
		Facts:        map[string]json.RawMessage{},
		Capabilities: []report.CapabilityRun{{ID: "secrets", Name: "Secret Scanner", Version: "0.1.0", Status: "ok", Findings: 1}},
		DataBoundary: report.DataBoundary{Statement: "No network requests were made."},
	}
}

func TestAllFormatsRender(t *testing.T) {
	r := sample()
	for _, f := range report.Formats {
		var buf bytes.Buffer
		if err := report.Write(&buf, r, f); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if buf.Len() == 0 {
			t.Fatalf("%s: empty output", f)
		}
		out := buf.String()
		switch f {
		case "html":
			if strings.Contains(out, "<script>") {
				t.Fatal("html output is not escaped")
			}
			if !strings.Contains(out, "AWS key &lt;script&gt;") {
				t.Fatal("finding title missing from html")
			}
		case "md":
			if !strings.Contains(out, "config/app.env:4") || !strings.Contains(out, "What to do") && !strings.Contains(out, "Remediation") {
				t.Fatal("markdown missing location or remediation")
			}
		case "sarif":
			var s map[string]any
			if err := json.Unmarshal(buf.Bytes(), &s); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out, `"ruleId": "secrets/aws-access-token"`) || !strings.Contains(out, `"baselineState": "new"`) {
				t.Fatalf("sarif content unexpected: %s", out)
			}
		case "json":
			back, err := report.Read(&buf)
			if err != nil || back.Findings[0].ID != "CSI-1" {
				t.Fatalf("json round trip failed: %v", err)
			}
		}
	}
	if err := report.Write(&bytes.Buffer{}, r, "pdf"); err == nil {
		t.Fatal("expected unknown format error")
	}
}

func TestBaseline(t *testing.T) {
	cur, base := sample(), sample()
	cur.Findings = append(cur.Findings, finding.Finding{ID: "CSI-2", Title: "new one", Severity: finding.Low})
	cur.ApplyBaseline(base)
	if cur.Findings[0].BaselineState != finding.BaselineExisting || cur.Findings[1].BaselineState != finding.BaselineNew {
		t.Fatalf("baseline states: %v %v", cur.Findings[0].BaselineState, cur.Findings[1].BaselineState)
	}
}
