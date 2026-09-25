package engine_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/engine"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/report"
)

func trustOf(r *report.Report) *report.Score {
	for i := range r.Scores {
		if r.Scores[i].ID == engine.TrustScoreID {
			return &r.Scores[i]
		}
	}
	return nil
}

// runWebsite runs fakes on a website target whose snapshot "ran".
func runWebsite(t *testing.T, fs []finding.Finding, id *facts.Identity) *report.Report {
	t.Helper()
	web := func(c *analyzer.Capability) { c.Targets = []analyzer.TargetKind{analyzer.TargetWebsite} }
	snap := &fake{c: capOf("web-snapshot", web)}
	checks := &fake{c: capOf("web-security", web), run: func(*analyzer.Input) (*analyzer.Result, error) {
		return &analyzer.Result{Findings: fs}, nil
	}}
	as := []analyzer.Analyzer{snap, checks}
	if id != nil {
		as = append(as, &fake{c: capOf("identity", web, func(c *analyzer.Capability) { c.Provides = []string{facts.KeyIdentity} }),
			run: func(*analyzer.Input) (*analyzer.Result, error) {
				return &analyzer.Result{Evidence: map[string]any{facts.KeyIdentity: *id}}, nil
			}})
	}
	r, _, err := newEngine(t, engine.Config{}, as...).Analyze(context.Background(), analyzer.Target{Kind: analyzer.TargetWebsite, Input: "https://x.test", Display: "x.test"}, engine.Selection{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func hdr(title string, sev finding.Severity) finding.Finding {
	return finding.Finding{Category: "security-header", Title: title, Severity: sev, Confidence: finding.ConfidenceHigh, Dimension: finding.DimSecurity}
}

// Deductions add up with no cap per area.
func TestTrustScoreDeductionsAddUp(t *testing.T) {
	var fs []finding.Finding
	for _, h := range []string{"CSP", "HSTS", "XFO", "nosniff", "Referrer", "Permissions", "COOP", "CORP"} {
		fs = append(fs, hdr(h+" missing", finding.Medium))
	}
	ts := trustOf(runWebsite(t, fs, nil))
	if ts == nil {
		t.Fatal("no Trust Score")
	}
	var headers int
	for _, d := range ts.Deductions {
		if strings.HasPrefix(d.Text, "8 security headers") {
			headers = d.Points
		}
	}
	if headers != 24 { // 8 × 3, uncapped
		t.Fatalf("8 medium header gaps must cost 24: %+v", ts.Deductions)
	}
	if len(ts.Ceilings) != 0 || ts.Value > 76 {
		t.Fatalf("value = 100 − deductions: %+v", ts)
	}
}

// A ten-day-old domain can never score above 10, however clean the rest.
func TestTrustScoreYoungDomainCeiling(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) // the test engine's clock
	ts := trustOf(runWebsite(t, nil, &facts.Identity{Domain: "x.test", Registered: now.Add(-10 * 24 * time.Hour)}))
	if ts.Value != 10 || ts.Grade != "F" || ts.Ceilings[0].Max != 10 || !strings.Contains(ts.Ceilings[0].Reason, "10 days old") {
		t.Fatalf("young domain ceiling: %+v", ts)
	}
	if !strings.Contains(ts.Summary, "held at 10") {
		t.Fatalf("summary names the ceiling: %q", ts.Summary)
	}
}

// No HTTPS holds the score at 20; the lowest ceiling applies.
func TestTrustScoreLowestCeilingWins(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	https := finding.Finding{Category: "https", Title: "Site is served without HTTPS", Severity: finding.High, Confidence: finding.ConfidenceHigh, Dimension: finding.DimSecurity}
	ts := trustOf(runWebsite(t, []finding.Finding{https}, &facts.Identity{Domain: "x.test", Registered: now.Add(-60 * 24 * time.Hour)}))
	if ts.Value != 20 || ts.Ceilings[0].Max != 20 || ts.Ceilings[1].Max != 30 {
		t.Fatalf("no HTTPS (20) beats a 2-month domain (30): %+v", ts)
	}
}
