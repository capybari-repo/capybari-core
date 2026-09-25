package engine_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/engine"
	"github.com/capybari-repo/capybari-core/facts"
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

func TestVerdictRepositoryRisk(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lg := &fake{c: capOf("longevity", func(c *analyzer.Capability) { c.Provides = []string{facts.KeyLongevity} }),
		run: func(*analyzer.Input) (*analyzer.Result, error) {
			return &analyzer.Result{
				Evidence: map[string]any{facts.KeyLongevity: facts.Longevity{CommitsLastYear: 120, ActiveMonths: 11, BusFactor: 3,
					LatestRelease: "v2.1.0", LatestReleaseDate: now.Add(-20 * 24 * time.Hour), License: "MIT", LicenseClass: "permissive"}},
				Findings: []finding.Finding{{Category: "license-restriction", Title: "License does not allow commercial use", Severity: finding.High,
					Confidence: finding.ConfidenceMedium, Dimension: finding.DimOperability, Impact: &finding.Impact{Buyer: finding.BuyerBlocks}}},
			}, nil
		}}
	r, _, err := newEngine(t, engine.Config{Now: func() time.Time { return now }}, lg).Analyze(context.Background(), repo, engine.Selection{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, _ := r.Verdict.Axis(report.AxisRisk)
	if risk.Label != "High regret risk" || risk.Reasons[0].Text != "License does not allow commercial use" {
		t.Fatalf("a non-commercial license must make the risk high: %+v", risk)
	}
	var texts []string
	for _, rs := range risk.Reasons {
		texts = append(texts, rs.Text)
	}
	joined := strings.Join(texts, "|")
	for _, want := range []string{"Active: 120 commits in 11 of the last 12 months", "Shared maintenance: 3 people", "Latest release v2.1.0, 2 weeks ago"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %v", want, texts)
		}
	}
}

// The Indraft acceptance case: a young, selling site with spoofable email
// and no ops trail must not read "Low regret risk", and its summary must
// lead with the buyer's fear, not with security headers.
func TestVerdictYoungProductWithoutOpsTrail(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	web := func(c *analyzer.Capability) { c.Targets = []analyzer.TargetKind{analyzer.TargetWebsite} }
	provides := func(k string) func(*analyzer.Capability) { return func(c *analyzer.Capability) { c.Provides = []string{k} } }
	find := func(cat, title string, sev finding.Severity, dim string) finding.Finding {
		return finding.Finding{Category: cat, Title: title, Severity: sev, Confidence: finding.ConfidenceHigh, Dimension: dim}
	}
	sec := &fake{c: capOf("web-security", web), run: func(*analyzer.Input) (*analyzer.Result, error) {
		return &analyzer.Result{Findings: []finding.Finding{find("security-header", "Content-Security-Policy header missing", finding.Medium, finding.DimSecurity),
			find("security-header", "Strict-Transport-Security (HSTS) header missing", finding.Medium, finding.DimSecurity)}}, nil
	}}
	tech := &fake{c: capOf("web-tech", web)}
	id := &fake{c: capOf("identity", web, provides(facts.KeyIdentity)), run: func(*analyzer.Input) (*analyzer.Result, error) {
		return &analyzer.Result{Evidence: map[string]any{facts.KeyIdentity: facts.Identity{Domain: "indraft.pub", Registered: time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)}},
			Findings: []finding.Finding{
				find("domain-new", "Domain only about 3 months old (registered Oct 2025)", finding.Medium, finding.DimTrust),
				find("email-spoofable", "Email in Indraft's name can be faked (DMARC policy is p=none (monitor only))", finding.Low, finding.DimTrust)}}, nil
	}}
	comp := &fake{c: capOf("completeness", web), run: func(*analyzer.Input) (*analyzer.Result, error) {
		return &analyzer.Result{Findings: []finding.Finding{find("no-ops-trail", "No public ops trail: no changelog, status page or community", finding.Medium, finding.DimEvolution)}}, nil
	}}
	target := analyzer.Target{Kind: analyzer.TargetWebsite, Input: "https://indraft.pub", Display: "indraft.pub"}
	r, _, err := newEngine(t, engine.Config{Now: func() time.Time { return now }}, sec, tech, id, comp).Analyze(context.Background(), target, engine.Selection{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, _ := r.Verdict.Axis(report.AxisRisk)
	if risk.Rating == "good" || risk.Label != "Young domain · thin ops trail" || !strings.HasPrefix(risk.Reasons[0].Text, "Domain only 3 months old") {
		t.Fatalf("risk must bite and lead with domain age: %+v", risk)
	}
	if !strings.HasPrefix(r.Summary.Headline, "indraft.pub: buyer concern: email in Indraft's name can be faked; domain only about 3 months old.") ||
		!strings.HasSuffix(r.Summary.Headline, "Owner homework: 2 header and configuration gap(s).") {
		t.Fatalf("summary: %q", r.Summary.Headline)
	}
	for _, id := range r.Summary.TopFindings {
		for _, f := range r.Findings {
			if f.ID == id && f.Category == "security-header" {
				t.Fatal("security headers are owner homework, never top findings")
			}
		}
	}
	if last := r.Findings[len(r.Findings)-1]; last.Category != "security-header" {
		t.Fatalf("owner homework is listed last: %+v", last)
	}
}
