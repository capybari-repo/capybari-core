package engine_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/engine"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/report"
	"github.com/capybari-repo/capybari-schemas"
)

func secFnd(cat string, sev finding.Severity) finding.Finding {
	return finding.Finding{Category: cat, Title: cat + " " + string(sev), Severity: sev, Confidence: finding.ConfidenceHigh, Dimension: finding.DimSecurity}
}

func TestBuyerImpact(t *testing.T) {
	cases := []struct {
		f    finding.Finding
		want string
	}{
		{secFnd("security-header", finding.Medium), finding.BuyerCosmetic},
		{secFnd("disclosure", finding.Low), finding.BuyerCosmetic},
		{secFnd("https", finding.High), finding.BuyerBlocks},
		{secFnd("https", finding.Medium), finding.BuyerSupportCost},
		{secFnd("secret", finding.High), finding.BuyerBlocks},
		{secFnd("secret", finding.Low), finding.BuyerSupportCost}, // test fixture key
		{secFnd("vulnerable-library", finding.Critical), finding.BuyerBlocks},
		{secFnd("vulnerable-library", finding.High), finding.BuyerSupportCost},
		{secFnd("vulnerability", finding.High), finding.BuyerBlocks},
		{secFnd("vulnerability", finding.Low), finding.BuyerCosmetic},
		{fnd("placeholder-content", finding.High, finding.ConfidenceHigh), finding.BuyerSupportCost},
		{fnd("ai-builder", finding.Info, finding.ConfidenceHigh), finding.BuyerCosmetic},
		{finding.Finding{Category: "coming-soon", Severity: finding.Medium, Impact: &finding.Impact{Buyer: finding.BuyerBlocks}}, finding.BuyerBlocks},
	}
	for _, c := range cases {
		if got := engine.BuyerImpact(c.f); got != c.want {
			t.Errorf("%s/%s: %s, want %s", c.f.Category, c.f.Severity, got, c.want)
		}
	}
}

func TestVerdict(t *testing.T) {
	web := func(c *analyzer.Capability) { c.Targets = []analyzer.TargetKind{analyzer.TargetWebsite} }
	sec := &fake{c: capOf("web-security", web), run: func(*analyzer.Input) (*analyzer.Result, error) {
		return &analyzer.Result{Findings: []finding.Finding{secFnd("security-header", finding.Medium), secFnd("https", finding.High)}}, nil
	}}
	tech := &fake{c: capOf("web-tech", web)}
	ai := &fake{c: capOf("ai-signals", web), run: func(*analyzer.Input) (*analyzer.Result, error) {
		return &analyzer.Result{Findings: []finding.Finding{{Category: "placeholder-content", Title: "Placeholder content is live", Severity: finding.High, Confidence: finding.ConfidenceHigh, Dimension: finding.DimAISignals,
			Evidence: []finding.Evidence{{Location: finding.Location{URL: "https://x.test/about"}, Detail: `"your company name" ×2`}}}}}, nil
	}}
	r, _, err := newEngine(t, engine.Config{}, sec, tech, ai).Analyze(context.Background(), analyzer.Target{Kind: analyzer.TargetWebsite, Input: "https://x.test", Display: "x.test"}, engine.Selection{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v := r.Verdict
	if v == nil || len(v.Axes) != 3 {
		t.Fatalf("verdict: %+v", v)
	}
	trust, _ := v.Axis(report.AxisTrust)
	finish, _ := v.Axis(report.AxisFinish)
	risk, _ := v.Axis(report.AxisRisk)
	if trust.Rating != "poor" || trust.Reasons[0].Impact != finding.BuyerBlocks || trust.Reasons[0].FindingID == "" {
		t.Fatalf("no HTTPS must block trust, listed first: %+v", trust)
	}
	for _, rs := range trust.Reasons {
		if strings.Contains(rs.Text, "security-header") {
			t.Fatalf("cosmetic findings are not buyer reasons: %+v", trust.Reasons)
		}
	}
	if finish.Label != "Unfinished" || !strings.Contains(finish.Reasons[0].Text, `Placeholder text still on the site: "your company name" (/about)`) {
		t.Fatalf("finish: %+v", finish)
	}
	if risk.Label != "Low regret risk" || v.Headline != "Trust blockers found · Unfinished · Low regret risk" {
		t.Fatalf("risk/headline: %+v %q", risk, v.Headline)
	}
	if v.Impact[finding.BuyerBlocks] != 1 || v.Impact[finding.BuyerCosmetic] != 1 || !strings.Contains(strings.Join(v.NotChecked, "|"), "peer benchmarks") {
		t.Fatalf("impact/not checked: %+v %v", v.Impact, v.NotChecked)
	}
	var buf bytes.Buffer
	report.WriteJSON(&buf, r)
	if err := schemas.Validate("report.schema.json", buf.Bytes()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	brief := report.Brief(r, "https://scan.test/scan/1")
	for _, want := range []string{"## Buyer brief: x.test", "**Trust: Trust blockers found**", "⛔", "Not checked:", "https://scan.test/scan/1", "not a recommendation"} {
		if !strings.Contains(brief, want) {
			t.Fatalf("brief lacks %q:\n%s", want, brief)
		}
	}
	for _, f := range []string{"md", "html"} {
		buf.Reset()
		report.Write(&buf, r, f)
		if i, j := strings.Index(buf.String(), "Verdict: Trust blockers found"), strings.Index(buf.String(), "Scores"); i < 0 || i > j {
			t.Fatalf("%s: verdict must come before scores", f)
		}
	}
}
