package engine

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/report"
)

// recommend derives "What else can we tell you?" from evidence: follow-up
// rules declared by capabilities that ran, capabilities skipped because the
// scan was offline, and additional access that would unlock more analysis.
// It never recommends something irrelevant to the target (Cross-Tool
// Intelligence, Section 10).
func (e *Engine) recommend(st *State, fs []finding.Finding) []report.Recommendation {
	categories := map[string]bool{}
	for _, f := range fs {
		categories[f.Category] = true
	}
	var techs []string
	var t facts.Technologies
	if raw, ok := st.Evidence[facts.KeyTechnologies]; ok {
		if err := json.Unmarshal(raw, &t); err == nil {
			for _, n := range t.Names() {
				techs = append(techs, strings.ToLower(n))
			}
		}
	}
	matches := func(c analyzer.Condition) (bool, string) {
		if c.Empty() {
			return true, ""
		}
		for _, fc := range c.FindingCategories {
			if categories[fc] {
				return true, "finding:" + fc
			}
		}
		for _, tn := range c.Technologies {
			if slices.Contains(techs, strings.ToLower(tn)) {
				return true, "technology:" + tn
			}
		}
		for _, k := range c.Evidence {
			if _, ok := st.Evidence[k]; ok {
				return true, "evidence:" + k
			}
		}
		return false, ""
	}

	recs := map[string]report.Recommendation{}
	put := func(r report.Recommendation) {
		key := r.Kind + ":" + r.Capability + ":" + r.Title
		if old, ok := recs[key]; ok && old.Priority <= r.Priority {
			return
		}
		recs[key] = r
	}

	reg := e.cfg.Registry
	// 1. Evidence-based follow-ups from capabilities that ran.
	for id, rec := range st.Runs {
		if rec.Run.Status != report.StatusOK {
			continue
		}
		a, ok := reg.Get(id)
		if !ok {
			continue
		}
		for _, fu := range a.Capability().FollowUps {
			target, ok := reg.Get(fu.Capability)
			if !ok || !target.Capability().Supports(st.Target.Kind) {
				continue
			}
			// Anything that already ran (or was offline-skipped, handled
			// below) is not recommended again.
			if _, ran := st.Runs[fu.Capability]; ran {
				continue
			}
			ok, why := matches(fu.When)
			if !ok {
				continue
			}
			prio := 2
			if why != "" {
				prio = 1
			}
			tc := target.Capability()
			put(e.runRec(tc, fu.Reason, prio, st))
		}
	}
	// 2. Applicable capabilities that have not run at all (focused scans).
	for _, a := range reg.All() {
		c := a.Capability()
		if !c.Supports(st.Target.Kind) {
			continue
		}
		if _, ran := st.Runs[c.ID]; ran {
			continue
		}
		put(e.runRec(c, c.Summary, 3, st))
	}
	// 3. Capabilities skipped because the scan was offline.
	for id, rec := range st.Runs {
		if rec.Run.Status == report.StatusSkipped && strings.Contains(rec.Run.Reason, "offline") {
			put(report.Recommendation{
				Kind: report.RecNetwork, Capability: id, Title: "Run " + rec.Run.Name + " online",
				Reason: "This capability needs network access and was skipped because the scan ran offline.", Runnable: false, Priority: 2,
			})
		}
	}
	// 4. Access that would unlock more analysis (Unified Agent, Section 5).
	switch st.Target.Kind {
	case analyzer.TargetWebsite:
		put(report.Recommendation{Kind: report.RecAccess, Title: "Connect the source repository",
			Reason: "A URL shows only the public surface. The repository enables dependency, vulnerability, secret, code-health and architecture analysis.", Priority: 4})
	case analyzer.TargetRepository:
		put(report.Recommendation{Kind: report.RecAccess, Title: "Add the deployed URL",
			Reason: "The repository shows the code. The deployed URL adds external exposure, TLS and security-header checks of what users actually reach.", Priority: 5})
	}

	out := make([]report.Recommendation, 0, len(recs))
	for _, r := range recs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].Title < out[j].Title
	})
	return out
}

func (e *Engine) runRec(c analyzer.Capability, reason string, prio int, st *State) report.Recommendation {
	r := report.Recommendation{Kind: report.RecRun, Capability: c.ID, Title: "Run " + c.Name, Reason: reason, Runnable: true, Priority: prio}
	if c.Execution.Network == analyzer.RequireRequired && st.Mode.Offline {
		r.Kind = report.RecNetwork
		r.Runnable = false
		r.Reason = fmt.Sprintf("%s (needs network access)", reason)
	}
	if c.Experimental() {
		r.Title += " (experimental)"
	}
	return r
}
