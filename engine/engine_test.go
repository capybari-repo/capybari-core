package engine_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/capybari/capybari-core/analyzer"
	"github.com/capybari/capybari-core/engine"
	"github.com/capybari/capybari-core/finding"
	"github.com/capybari/capybari-core/report"
)

// fake is a configurable test analyzer.
type fake struct {
	c       analyzer.Capability
	run     func(in *analyzer.Input) (*analyzer.Result, error)
	applies func(in *analyzer.Input) (bool, string)
	mu      sync.Mutex
	calls   int
}

func (f *fake) Capability() analyzer.Capability { return f.c }
func (f *fake) Analyze(_ context.Context, in *analyzer.Input) (*analyzer.Result, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.run == nil {
		return &analyzer.Result{}, nil
	}
	return f.run(in)
}

type applicableFake struct{ *fake }

func (a applicableFake) Applies(in *analyzer.Input) (bool, string) { return a.applies(in) }

func capOf(id string, mut ...func(*analyzer.Capability)) analyzer.Capability {
	c := analyzer.Capability{
		ID: id, Name: strings.ToUpper(id), Version: "1.0.0", Category: "test", Summary: "Test capability " + id,
		Stability: analyzer.StabilityStable, CoreAPI: analyzer.APIVersion,
		Targets: []analyzer.TargetKind{analyzer.TargetRepository}, Cost: analyzer.CostLow,
		Execution: analyzer.Execution{Local: true, Network: analyzer.RequireNone, AI: analyzer.RequireNone},
		Privacy:   "Nothing leaves the machine.",
	}
	for _, m := range mut {
		m(&c)
	}
	return c
}

func requires(keys ...string) func(*analyzer.Capability) {
	return func(c *analyzer.Capability) { c.Requires = keys }
}
func provides(keys ...string) func(*analyzer.Capability) {
	return func(c *analyzer.Capability) { c.Provides = keys }
}
func scores(d ...string) func(*analyzer.Capability) {
	return func(c *analyzer.Capability) { c.Scores = d }
}

var repo = analyzer.Target{Kind: analyzer.TargetRepository, Input: ".", Root: ".", Display: "fixture"}

func newEngine(t *testing.T, cfg engine.Config, as ...analyzer.Analyzer) *engine.Engine {
	t.Helper()
	reg := engine.NewRegistry()
	if err := reg.Register(as...); err != nil {
		t.Fatal(err)
	}
	cfg.Registry = reg
	cfg.Tool = report.Tool{Name: "test", Version: "0.0.0"}
	cfg.Now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	return engine.New(cfg)
}

func TestPlanOrdersByEvidence(t *testing.T) {
	a := &fake{c: capOf("a", provides("x"))}
	b := &fake{c: capOf("b", requires("x"), provides("y"))}
	c := &fake{c: capOf("c", requires("y"))}
	d := &fake{c: capOf("d")}
	e := newEngine(t, engine.Config{}, c, b, a, d)

	levels, err := e.Plan(analyzer.TargetRepository, engine.Selection{})
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(levels)
	if got != "[[a d] [b] [c]]" {
		t.Fatalf("levels = %s", got)
	}

	levels, err = e.Plan(analyzer.TargetRepository, engine.Selection{Only: []string{"c"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(levels); got != "[[a] [b] [c]]" {
		t.Fatalf("only c: levels = %s", got)
	}
	if _, err := e.Plan(analyzer.TargetRepository, engine.Selection{Only: []string{"nope"}}); err == nil {
		t.Fatal("expected unknown capability error")
	}
}

func TestPlanDetectsCycles(t *testing.T) {
	a := &fake{c: capOf("a", requires("y"), provides("x"))}
	b := &fake{c: capOf("b", requires("x"), provides("y"))}
	e := newEngine(t, engine.Config{}, a, b)
	if _, err := e.Plan(analyzer.TargetRepository, engine.Selection{}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle error, got %v", err)
	}
}

func TestRunStatusesAndEvidenceFlow(t *testing.T) {
	type X struct{ N int }
	prod := &fake{c: capOf("prod", provides("x")), run: func(*analyzer.Input) (*analyzer.Result, error) {
		return &analyzer.Result{Evidence: map[string]any{"x": X{N: 42}, "undeclared": 1}, Summary: "made x"}, nil
	}}
	var seen int
	cons := &fake{c: capOf("cons", requires("x"), scores(finding.DimSecurity)), run: func(in *analyzer.Input) (*analyzer.Result, error) {
		var x X
		ok, err := in.Evidence.Get("x", &x)
		if !ok || err != nil {
			return nil, errors.New("no x")
		}
		seen = x.N
		if in.Evidence.Has("undeclared") {
			return nil, errors.New("undeclared evidence leaked")
		}
		return &analyzer.Result{Findings: []finding.Finding{
			{Category: "c1", Title: "one", Severity: finding.High, Confidence: finding.ConfidenceHigh, Evidence: []finding.Evidence{{Location: finding.Location{Path: "a.go", StartLine: 3}}}},
			{Category: "c1", Title: "one", Severity: finding.High, Confidence: finding.ConfidenceHigh, Evidence: []finding.Evidence{{Location: finding.Location{Path: "a.go", StartLine: 3}}}},
		}}, nil
	}}
	boom := &fake{c: capOf("boom"), run: func(*analyzer.Input) (*analyzer.Result, error) { panic("kaboom") }}
	fail := &fake{c: capOf("fail"), run: func(*analyzer.Input) (*analyzer.Result, error) { return nil, errors.New("broken") }}
	needNet := &fake{c: capOf("netcap", func(c *analyzer.Capability) {
		c.Execution.Network = analyzer.RequireRequired
		c.Execution.NetworkHosts = []string{"api.example.com"}
	})}
	orphan := &fake{c: capOf("orphan", requires("missing"))}
	declines := applicableFake{&fake{c: capOf("declines"), applies: func(*analyzer.Input) (bool, string) { return false, "nothing to do" }}}

	e := newEngine(t, engine.Config{Offline: true}, prod, cons, boom, fail, needNet, orphan, declines)
	r, _, err := e.Analyze(context.Background(), repo, engine.Selection{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if seen != 42 {
		t.Fatalf("consumer saw %d", seen)
	}
	want := map[string]string{"prod": "ok", "cons": "ok", "boom": "failed", "fail": "failed", "netcap": "skipped", "orphan": "skipped", "declines": "not-applicable"}
	for id, status := range want {
		run, ok := r.Capability(id)
		if !ok || run.Status != status {
			t.Errorf("%s: status %q (%s), want %q", id, run.Status, run.Reason, status)
		}
	}
	if len(r.Findings) != 1 {
		t.Fatalf("duplicate findings not merged: %d", len(r.Findings))
	}
	f := r.Findings[0]
	if f.Source.Capability != "cons" || f.ID == "" || f.DetectedAt.IsZero() || len(f.Evidence) != 2 {
		t.Fatalf("finding not normalised: %+v", f)
	}
	if len(r.Scores) != 1 || r.Scores[0].ID != finding.DimSecurity || r.Scores[0].Value > 79 {
		t.Fatalf("scores = %+v", r.Scores)
	}
	if r.DataBoundary.LeftMachine {
		t.Fatal("offline scan reported network use")
	}
	var netRec bool
	for _, rec := range r.Recommendations {
		if rec.Kind == report.RecNetwork && rec.Capability == "netcap" {
			netRec = true
		}
	}
	if !netRec {
		t.Fatalf("missing network recommendation: %+v", r.Recommendations)
	}
}

func TestExpandReusesCompletedWork(t *testing.T) {
	a := &fake{c: capOf("a", provides("x")), run: func(*analyzer.Input) (*analyzer.Result, error) {
		return &analyzer.Result{Evidence: map[string]any{"x": 1}}, nil
	}}
	b := &fake{c: capOf("b", requires("x"))}
	c := &fake{c: capOf("c")}
	e := newEngine(t, engine.Config{}, a, b, c)
	st := e.NewState(repo, nil)
	if err := e.Run(context.Background(), st, engine.Selection{Only: []string{"b"}}); err != nil {
		t.Fatal(err)
	}
	r := e.Report(st)
	var sawC bool
	for _, rec := range r.Recommendations {
		if rec.Capability == "c" && rec.Runnable {
			sawC = true
		}
	}
	if !sawC {
		t.Fatalf("focused scan should recommend c: %+v", r.Recommendations)
	}
	if err := e.Run(context.Background(), st, engine.Selection{}); err != nil {
		t.Fatal(err)
	}
	if a.calls != 1 || b.calls != 1 || c.calls != 1 {
		t.Fatalf("calls a=%d b=%d c=%d, want 1 each", a.calls, b.calls, c.calls)
	}
}

type memCache struct{ m map[string]*engine.RunRecord }

func (c *memCache) Get(k string) (*engine.RunRecord, bool) { r, ok := c.m[k]; return r, ok }
func (c *memCache) Put(k string, r *engine.RunRecord) error { c.m[k] = r; return nil }

func TestCacheReusesResults(t *testing.T) {
	dir := t.TempDir()
	target := analyzer.Target{Kind: analyzer.TargetRepository, Input: dir, Root: dir, Display: "x"}
	a := &fake{c: capOf("a"), run: func(*analyzer.Input) (*analyzer.Result, error) {
		return &analyzer.Result{Summary: "done", Findings: []finding.Finding{{Category: "k", Title: "t", Severity: finding.Low, Confidence: finding.ConfidenceLow}}}, nil
	}}
	mc := &memCache{m: map[string]*engine.RunRecord{}}
	e := newEngine(t, engine.Config{Cache: mc}, a)
	r1, _, _ := e.Analyze(context.Background(), target, engine.Selection{}, nil)
	r2, _, _ := e.Analyze(context.Background(), target, engine.Selection{}, nil)
	if a.calls != 1 {
		t.Fatalf("analyzer ran %d times, want 1", a.calls)
	}
	run, _ := r2.Capability("a")
	if !run.Cached || len(r2.Findings) != 1 || r2.Findings[0].ID != r1.Findings[0].ID || run.Summary != "done" {
		t.Fatalf("cached run wrong: %+v findings=%d", run, len(r2.Findings))
	}
}

func TestRegistryRejectsBadMetadata(t *testing.T) {
	reg := engine.NewRegistry()
	bad := &fake{c: capOf("Bad_ID")}
	if err := reg.Register(bad); err == nil {
		t.Fatal("expected invalid id error")
	}
	old := &fake{c: capOf("old", func(c *analyzer.Capability) { c.CoreAPI = "v9" })}
	if err := reg.Register(old); err == nil {
		t.Fatal("expected core API mismatch error")
	}
	ok := &fake{c: capOf("ok")}
	if err := reg.Register(ok, ok); err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestScoreCapsAndConfidence(t *testing.T) {
	crit := &fake{c: capOf("crit", scores(finding.DimSecurity)), run: func(*analyzer.Input) (*analyzer.Result, error) {
		return &analyzer.Result{Findings: []finding.Finding{{Category: "secret", Title: "key", Severity: finding.Critical, Confidence: finding.ConfidenceHigh}}}, nil
	}}
	exp := &fake{c: capOf("exp", scores(finding.DimAISignals), func(c *analyzer.Capability) { c.Stability = analyzer.StabilityExperimental })}
	e := newEngine(t, engine.Config{}, crit, exp)
	r, _, _ := e.Analyze(context.Background(), repo, engine.Selection{}, nil)
	byID := map[string]report.Score{}
	for _, s := range r.Scores {
		byID[s.ID] = s
	}
	if s := byID[finding.DimSecurity]; s.Value > 49 || s.Rating != "poor" {
		t.Fatalf("critical finding must cap security score: %+v", s)
	}
	if s := byID[finding.DimAISignals]; s.Value != 100 || s.Confidence != finding.ConfidenceLow {
		t.Fatalf("experimental score must be low confidence: %+v", s)
	}
	if !strings.Contains(r.Summary.Headline, "critical/high") {
		t.Fatalf("headline = %q", r.Summary.Headline)
	}
}
