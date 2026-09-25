package engine_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/engine"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/report"
	"github.com/capybari-repo/capybari-schemas"
)

func fnd(cat string, sev finding.Severity, conf finding.Confidence) finding.Finding {
	return finding.Finding{Category: cat, Title: cat + string(sev), Severity: sev, Confidence: conf, Dimension: finding.DimAISignals}
}

func slopOf(r *report.Report) *report.Score {
	for i := range r.Scores {
		if r.Scores[i].ID == engine.AISlopID {
			return &r.Scores[i]
		}
	}
	return nil
}

func TestAISlopComposite(t *testing.T) {
	ai := &fake{c: capOf("ai-signals"), run: func(*analyzer.Input) (*analyzer.Result, error) {
		return &analyzer.Result{Summary: "Checked 1 page", Findings: []finding.Finding{
			fnd("placeholder-content", finding.High, finding.ConfidenceHigh), // 12
			fnd("scaffold-code", finding.Medium, finding.ConfidenceMedium),   // 2.8
		}}, nil
	}}
	sec := &fake{c: capOf("secrets"), run: func(*analyzer.Input) (*analyzer.Result, error) {
		fs := []finding.Finding{}
		for i := range 5 { // 5 × 30 = 150 points, capped at 30
			f := fnd("secret", finding.Critical, finding.ConfidenceHigh)
			f.Title += string(rune('a' + i))
			fs = append(fs, f)
		}
		return &analyzer.Result{Findings: fs}, nil
	}}
	e := newEngine(t, engine.Config{}, ai, sec)
	r, _, err := e.Analyze(context.Background(), repo, engine.Selection{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := slopOf(r)
	if s == nil {
		t.Fatal("no AI Slop Score")
	}
	// placeholders 12×2 = 24; scaffold 2.8×1.5 = 4.2; secrets 150 capped at 30
	// total 58.2 -> 100*58.2/98.2 = 59
	if s.Value != 59 || s.Label != "High unfinished risk" || s.Rating != "poor" || !s.IsHigherWorse() {
		t.Fatalf("slop = %+v", s)
	}
	byID := map[string]report.ScoreComponent{}
	for _, c := range s.Components {
		byID[c.ID] = c
	}
	if byID["security"].Points != 30 || byID["security"].Findings != 5 || byID["ai-generation"].Points != 24 {
		t.Fatalf("components: %+v", s.Components)
	}
	// Repository groups whose capabilities did not run are not assessed.
	if byID["organization"].Assessed || byID["dependencies"].Assessed || s.Confidence != finding.ConfidenceLow {
		t.Fatalf("not-assessed handling: %+v conf=%s", s.Components, s.Confidence)
	}
	if !strings.Contains(strings.Join(s.Basis, "|"), "Not assessed (run the full scan): Dependency hygiene, Organization & tests") {
		t.Fatalf("basis: %v", s.Basis)
	}
	var buf bytes.Buffer
	report.WriteJSON(&buf, r)
	if err := schemas.Validate("report.schema.json", buf.Bytes()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	for _, f := range []string{"md", "html"} {
		buf.Reset()
		report.Write(&buf, r, f)
		if !strings.Contains(buf.String(), "higher = riskier") {
			t.Fatalf("%s report does not explain the slop direction", f)
		}
	}
}

func TestAISlopCleanAndNotAssessable(t *testing.T) {
	ai := &fake{c: capOf("ai-signals")}
	r, _, _ := newEngine(t, engine.Config{}, ai).Analyze(context.Background(), repo, engine.Selection{}, nil)
	if s := slopOf(r); s == nil || s.Value != 0 || s.Label != "Low unfinished risk" || s.Rating != "good" {
		t.Fatalf("clean: %+v", s)
	}
	declines := applicableFake{&fake{c: capOf("ai-signals"), applies: func(*analyzer.Input) (bool, string) { return false, "not enough content" }}}
	r, _, _ = newEngine(t, engine.Config{}, declines).Analyze(context.Background(), repo, engine.Selection{}, nil)
	if s := slopOf(r); s != nil {
		t.Fatalf("slop must not be scored when ai-signals is not assessable: %+v", s)
	}
}

func TestBuildDepthComposite(t *testing.T) {
	ai := &fake{c: capOf("ai-signals", func(c *analyzer.Capability) { c.Provides = []string{facts.KeySiteDepth} }),
		run: func(*analyzer.Input) (*analyzer.Result, error) {
			return &analyzer.Result{Evidence: map[string]any{facts.KeySiteDepth: facts.SiteDepth{Pages: 3, Words: 900, Checks: []facts.DepthCheck{
				{ID: "content-pages", Group: "breadth", Name: "content pages", Earned: 12, Max: 15},
				{ID: "title", Group: "finish", Name: "real page titles", Earned: 4, Max: 4},
				{ID: "description", Group: "finish", Name: "meta description", Earned: 0, Max: 4},
				{ID: "privacy", Group: "trust", Name: "privacy or terms page", Earned: 4, Max: 4},
			}}}}, nil
		}}
	r, _, err := newEngine(t, engine.Config{}, ai).Analyze(context.Background(), repo, engine.Selection{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var d *report.Score
	for i := range r.Scores {
		if r.Scores[i].ID == engine.BuildDepthID {
			d = &r.Scores[i]
		}
	}
	if d == nil || d.Value != 20 || d.Label != "Thin build" || d.IsHigherWorse() || len(d.Components) != 3 {
		t.Fatalf("build depth: %+v", d)
	}
	if c := d.Components[1]; c.ID != "finish" || c.Points != 4 || c.Max != 8 {
		t.Fatalf("finish component: %+v", c)
	}
	if !strings.Contains(strings.Join(d.Basis, "|"), "Finishing touches 4/8: has real page titles; missing or partial: meta description") {
		t.Fatalf("basis: %v", d.Basis)
	}
	var buf bytes.Buffer
	report.WriteJSON(&buf, r)
	if err := schemas.Validate("report.schema.json", buf.Bytes()); err != nil {
		t.Fatalf("schema: %v", err)
	}
}
