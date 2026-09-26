package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/netguard"
	"github.com/capybari-repo/capybari-core/report"
)

// Cache stores capability results keyed by capability version, target
// content and input evidence. Only capabilities that make no network calls
// are cached, because remote data (advisories, websites) changes.
type Cache interface {
	Get(key string) (*RunRecord, bool)
	Put(key string, rec *RunRecord) error
}

// Event reports progress to user interfaces.
type Event struct {
	Type       string // "start" or "finish"
	Capability string
	Name       string
	Status     string
	Reason     string
	// Summary says what a finished capability looked at.
	Summary  string
	Findings int
	Cached   bool
	Duration time.Duration
}

// Config configures an Engine.
type Config struct {
	Registry *Registry
	Tool     report.Tool
	// Offline forbids all network access. Capabilities that require the
	// network are skipped and reported as such.
	Offline bool
	// Hosted marks scans executed on Capybari infrastructure. Hosted scans
	// always deny private-network destinations.
	Hosted bool
	// DenyPrivateNetworks blocks connections to non-public addresses.
	DenyPrivateNetworks bool
	// AllowPrivateNetworks lifts the hosted-mode block (tests only).
	AllowPrivateNetworks bool
	Concurrency          int
	CapabilityTimeout    time.Duration
	Cache                Cache
	// CacheSalt is mixed into every cache key. Set it to something that
	// changes with the analyzer code (e.g. a hash of the executable) so a
	// rebuilt binary never reuses stale results.
	CacheSalt string
	UserAgent string
	Log       *slog.Logger
	Now       func() time.Time
	Progress  func(Event)
}

// Selection chooses capabilities. Empty Only means "every applicable capability".
type Selection struct {
	Only []string
	Skip []string
}

// Engine runs capabilities against scan state.
type Engine struct {
	cfg Config
}

// New returns an engine.
func New(cfg Config) *Engine {
	if cfg.Registry == nil {
		cfg.Registry = NewRegistry()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.CapabilityTimeout <= 0 {
		cfg.CapabilityTimeout = 10 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "capybari-source-intelligence/" + cfg.Tool.Version + " (+https://github.com/capybari-repo/capybari-cli)"
	}
	if cfg.Hosted && !cfg.AllowPrivateNetworks {
		cfg.DenyPrivateNetworks = true
	}
	return &Engine{cfg: cfg}
}

// Registry returns the engine's registry.
func (e *Engine) Registry() *Registry { return e.cfg.Registry }

// NewState creates scan state for a target with the engine's clock and mode.
func (e *Engine) NewState(t analyzer.Target, opts analyzer.Options) *State {
	st := NewState(t, e.cfg.Now())
	st.Options = opts
	st.Mode = report.Mode{Offline: e.cfg.Offline, Active: opts.Bool(analyzer.OptionActive), Hosted: e.cfg.Hosted}
	return st
}

// Plan returns capability IDs grouped into execution levels: every
// capability in a level depends only on evidence from earlier levels.
func (e *Engine) Plan(kind analyzer.TargetKind, sel Selection) ([][]string, error) {
	reg := e.cfg.Registry
	for _, id := range append(slices.Clone(sel.Only), sel.Skip...) {
		if _, ok := reg.Get(id); !ok {
			return nil, fmt.Errorf("unknown capability %q (see `capybari capabilities`)", id)
		}
	}
	wanted := map[string]bool{}
	if len(sel.Only) == 0 {
		for _, a := range reg.All() {
			if a.Capability().Supports(kind) {
				wanted[a.Capability().ID] = true
			}
		}
	} else {
		var add func(id string, stack []string) error
		add = func(id string, stack []string) error {
			if slices.Contains(stack, id) {
				return fmt.Errorf("capability dependency cycle: %s", strings.Join(append(stack, id), " -> "))
			}
			if wanted[id] {
				return nil
			}
			a, _ := reg.Get(id)
			c := a.Capability()
			if !c.Supports(kind) {
				return fmt.Errorf("capability %q does not support %s targets", id, kind)
			}
			wanted[id] = true
			// Optional evidence providers are included too: a focused run
			// should be as good as the same capability in a full scan.
			for _, key := range append(slices.Clone(c.Requires), c.Optional...) {
				for _, p := range reg.providers(key, kind) {
					if err := add(p, append(stack, id)); err != nil {
						return err
					}
				}
			}
			return nil
		}
		for _, id := range sel.Only {
			if err := add(id, nil); err != nil {
				return nil, err
			}
		}
	}
	for _, id := range sel.Skip {
		delete(wanted, id)
	}

	// Kahn's algorithm over evidence edges (required and optional).
	deps := map[string]map[string]bool{}
	for id := range wanted {
		a, _ := reg.Get(id)
		c := a.Capability()
		deps[id] = map[string]bool{}
		for _, key := range append(slices.Clone(c.Requires), c.Optional...) {
			for _, p := range reg.providers(key, kind) {
				if p != id && wanted[p] {
					deps[id][p] = true
				}
			}
		}
	}
	var levels [][]string
	done := map[string]bool{}
	for len(done) < len(wanted) {
		var level []string
		for id := range wanted {
			if done[id] {
				continue
			}
			ready := true
			for d := range deps[id] {
				if !done[d] {
					ready = false
					break
				}
			}
			if ready {
				level = append(level, id)
			}
		}
		if len(level) == 0 {
			var rest []string
			for id := range wanted {
				if !done[id] {
					rest = append(rest, id)
				}
			}
			sort.Strings(rest)
			return nil, fmt.Errorf("capability dependency cycle among: %s", strings.Join(rest, ", "))
		}
		sort.Slice(level, func(i, j int) bool {
			ci, _ := reg.Get(level[i])
			cj, _ := reg.Get(level[j])
			ri, rj := costRank(ci.Capability().Cost), costRank(cj.Capability().Cost)
			if ri != rj {
				return ri < rj
			}
			return level[i] < level[j]
		})
		for _, id := range level {
			done[id] = true
		}
		levels = append(levels, level)
	}
	return levels, nil
}

func costRank(c string) int {
	switch c {
	case analyzer.CostLow:
		return 0
	case analyzer.CostMedium:
		return 1
	}
	return 2
}

// Analyze is the one-call convenience: plan, run and report.
func (e *Engine) Analyze(ctx context.Context, t analyzer.Target, sel Selection, opts analyzer.Options) (*report.Report, *State, error) {
	st := e.NewState(t, opts)
	if err := e.Run(ctx, st, sel); err != nil {
		return nil, st, err
	}
	return e.Report(st), st, nil
}

// Run executes the selected capabilities that have not already run
// successfully in st. It can be called repeatedly to expand a scan.
func (e *Engine) Run(ctx context.Context, st *State, sel Selection) error {
	levels, err := e.Plan(st.Target.Kind, sel)
	if err != nil {
		return err
	}
	rec := netguard.NewRecorder()
	defer func() {
		st.mergeCalls(rec.Calls())
		st.UpdatedAt = e.cfg.Now()
	}()

	var digest string
	var digestOnce sync.Once
	targetDigest := func() string {
		digestOnce.Do(func() { digest = TargetDigest(st.Target) })
		return digest
	}

	for _, level := range levels {
		if err := ctx.Err(); err != nil {
			return err
		}
		sem := make(chan struct{}, e.cfg.Concurrency)
		var wg sync.WaitGroup
		for _, id := range level {
			if prev, ok := st.run(id); ok && prev.Run.Status == report.StatusOK {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(id string) {
				defer wg.Done()
				defer func() { <-sem }()
				a, _ := e.cfg.Registry.Get(id)
				r := e.runOne(ctx, st, a, rec, targetDigest)
				st.record(id, r)
			}(id)
		}
		wg.Wait()
	}
	return ctx.Err()
}

func (e *Engine) emit(ev Event) {
	if e.cfg.Progress != nil {
		e.cfg.Progress(ev)
	}
}

func (e *Engine) runOne(ctx context.Context, st *State, a analyzer.Analyzer, rec *netguard.Recorder, targetDigest func() string) *RunRecord {
	c := a.Capability()
	start := e.cfg.Now()
	out := &RunRecord{Run: report.CapabilityRun{
		ID: c.ID, Name: c.Name, Version: c.Version, Category: c.Category,
		Experimental: c.Experimental(), Execution: c.Execution, Engines: c.Engines,
	}}
	finish := func(status, reason string) *RunRecord {
		out.Run.Status = status
		out.Run.Reason = reason
		out.Run.DurationMS = e.cfg.Now().Sub(start).Milliseconds()
		out.Run.Findings = len(out.Findings)
		e.emit(Event{Type: "finish", Capability: c.ID, Name: c.Name, Status: status, Reason: reason, Summary: out.Run.Summary,
			Findings: len(out.Findings), Cached: out.Run.Cached, Duration: e.cfg.Now().Sub(start)})
		return out
	}
	e.emit(Event{Type: "start", Capability: c.ID, Name: c.Name})

	if c.Execution.Network == analyzer.RequireRequired && e.cfg.Offline {
		return finish(report.StatusSkipped, "needs network access (scan ran offline)")
	}
	if c.Execution.AI == analyzer.RequireRequired {
		return finish(report.StatusSkipped, "needs an AI provider, and none is configured")
	}
	for _, key := range c.Requires {
		if !st.Has(key) {
			if e.providersNotApplicable(st, key) {
				return finish(report.StatusNotApplicable, fmt.Sprintf("no %s to analyse", key))
			}
			return finish(report.StatusSkipped, fmt.Sprintf("needs %q evidence, which no earlier capability produced", key))
		}
	}

	in := &analyzer.Input{
		Target:   st.Target,
		Evidence: st,
		Options:  st.Options,
		Log:      e.cfg.Log.With("capability", c.ID),
		Now:      e.cfg.Now,
	}
	usesNet := c.Execution.Network != analyzer.RequireNone && !e.cfg.Offline
	if usesNet {
		hosts := make([]string, 0, len(c.Execution.NetworkHosts))
		for _, h := range c.Execution.NetworkHosts {
			if h == analyzer.TargetHost {
				h = st.Target.Host()
			}
			if h != "" {
				hosts = append(hosts, h)
			}
		}
		in.HTTP = netguard.NewClient(netguard.Policy{
			Capability: c.ID, AllowedHosts: hosts, DenyPrivate: e.cfg.DenyPrivateNetworks,
			UserAgent: e.cfg.UserAgent, Recorder: rec,
		})
	}

	if ap, ok := a.(analyzer.Applicable); ok {
		if ok, reason := ap.Applies(in); !ok {
			return finish(report.StatusNotApplicable, reason)
		}
	}

	var cacheKey string
	if e.cfg.Cache != nil && !usesNet && st.Target.Kind == analyzer.TargetRepository {
		cacheKey = e.cacheKey(st, c, targetDigest())
		if cached, ok := e.cfg.Cache.Get(cacheKey); ok {
			out.Findings = cached.Findings
			out.Artifacts = cached.Artifacts
			out.Evidence = cached.Evidence
			out.Run.Summary = cached.Run.Summary
			out.Run.Limitations = cached.Run.Limitations
			out.Run.Cached = true
			return finish(report.StatusOK, "")
		}
	}

	res, err := e.invoke(ctx, a, in)
	if err != nil {
		return finish(report.StatusFailed, err.Error())
	}
	if res == nil {
		res = &analyzer.Result{}
	}
	now := e.cfg.Now().UTC()
	out.Findings = normalize(c, res.Findings, now)
	out.Run.Summary = res.Summary
	out.Run.Limitations = res.Limitations
	out.Evidence = map[string]json.RawMessage{}
	for k, v := range res.Evidence {
		if !slices.Contains(c.Provides, k) {
			e.cfg.Log.Warn("capability published undeclared evidence; ignored", "capability", c.ID, "key", k)
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return finish(report.StatusFailed, fmt.Sprintf("encode evidence %q: %v", k, err))
		}
		out.Evidence[k] = raw
	}
	for _, art := range res.Artifacts {
		out.Artifacts = append(out.Artifacts, StoredArtifact{Name: art.Name, MediaType: art.MediaType, Data: art.Data})
	}
	if cacheKey != "" {
		stored := *out
		stored.Run.Summary = res.Summary
		if err := e.cfg.Cache.Put(cacheKey, &stored); err != nil {
			e.cfg.Log.Warn("cache write failed", "capability", c.ID, "err", err)
		}
	}
	return finish(report.StatusOK, "")
}

// providersNotApplicable reports whether every capability that could have
// provided key ran and found nothing to analyse.
func (e *Engine) providersNotApplicable(st *State, key string) bool {
	ids := e.cfg.Registry.providers(key, st.Target.Kind)
	if len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		rec, ok := st.run(id)
		if !ok || rec.Run.Status != report.StatusNotApplicable {
			return false
		}
	}
	return true
}

func (e *Engine) invoke(ctx context.Context, a analyzer.Analyzer, in *analyzer.Input) (res *analyzer.Result, err error) {
	ctx, cancel := context.WithTimeout(ctx, e.cfg.CapabilityTimeout)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			e.cfg.Log.Error("capability panicked", "capability", a.Capability().ID, "panic", p, "stack", string(debug.Stack()))
			err = fmt.Errorf("internal error in capability: %v", p)
		}
	}()
	res, err = a.Analyze(ctx, in)
	if errors.Is(err, context.DeadlineExceeded) {
		err = fmt.Errorf("timed out after %s", e.cfg.CapabilityTimeout)
	}
	return res, err
}

func (e *Engine) cacheKey(st *State, c analyzer.Capability, targetDigest string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s@%s\x00%s\x00%s\x00%s\x00", c.ID, c.Version, e.cfg.Tool.Version, e.cfg.CacheSalt, targetDigest)
	keys := append(slices.Clone(c.Requires), c.Optional...)
	sort.Strings(keys)
	for _, k := range keys {
		if raw, ok := st.evidenceRaw(k); ok {
			sum := sha256.Sum256(raw)
			fmt.Fprintf(h, "%s=%x\x00", k, sum)
		}
	}
	opts := make([]string, 0, len(st.Options))
	for k, v := range st.Options {
		opts = append(opts, k+"="+v)
	}
	sort.Strings(opts)
	fmt.Fprint(h, strings.Join(opts, "&"))
	return hex.EncodeToString(h.Sum(nil))
}

// normalize fills provenance, timestamps, defaults and stable IDs, and merges
// duplicate findings produced by one capability.
func normalize(c analyzer.Capability, in []finding.Finding, now time.Time) []finding.Finding {
	byID := map[string]int{}
	var out []finding.Finding
	for _, f := range in {
		f.Source.Capability = c.ID
		f.Source.Version = c.Version
		if f.Source.Engine == "" && len(c.Engines) == 1 {
			f.Source.Engine = c.Engines[0].Name
			f.Source.EngineVersion = c.Engines[0].Version
		}
		if f.Severity.Rank() == 0 {
			f.Severity = finding.Info
		}
		if f.Confidence.Weight() == 0.7 && f.Confidence != finding.ConfidenceMedium {
			f.Confidence = finding.ConfidenceMedium
		}
		if f.Dimension == "" {
			f.Dimension = finding.DimSecurity
		}
		if c.Experimental() && !slices.Contains(f.Tags, "experimental") {
			f.Tags = append(f.Tags, "experimental")
		}
		if f.DetectedAt.IsZero() {
			f.DetectedAt = now
		}
		if f.ID == "" {
			f.ID = f.ComputeID()
		}
		if i, dup := byID[f.ID]; dup {
			out[i].Evidence = append(out[i].Evidence, f.Evidence...)
			continue
		}
		byID[f.ID] = len(out)
		out = append(out, f)
	}
	return out
}
