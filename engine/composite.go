package engine

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/report"
)

// The Unfinished Risk score (formerly the AI Slop Score; the ID stays
// "ai-slop") answers one question: does this look like AI-generated
// software (or content) that nobody properly reviewed? It is a composite of
// evidence produced by several capabilities, grouped so that no single area
// dominates. It is a meter: 0 = clean, 100 = pure slop.
//
// Documented in capybari-docs/methodology/scoring.md#ai-slop. Changing the
// groups, weights or caps is a methodology change.

// AISlopID is the score ID of the Unfinished Risk score.
const AISlopID = "ai-slop"

// slopHalfPoint is the total penalty at which the meter reads 50.
const slopHalfPoint = 40.0

type slopGroup struct {
	id, name string
	// cap bounds the group's penalty points so no single area dominates.
	cap float64
	// weights per finding category (multiplies severity points × confidence).
	// AI-specific evidence weighs more than generic quality issues, which
	// mature human-written code has too.
	weights map[string]float64
	// capabilities that assess the group, per target kind.
	covers map[analyzer.TargetKind][]string
}

var slopGroups = []slopGroup{
	{
		id: "ai-generation", name: "AI-generation signs", cap: 40,
		weights: map[string]float64{"ai-boilerplate": 2, "placeholder-content": 2, "template-leftover": 1.5, "ai-builder": 1},
		covers: map[analyzer.TargetKind][]string{
			analyzer.TargetWebsite: {"ai-signals"}, analyzer.TargetRepository: {"ai-signals"},
		},
	},
	{
		id: "unfinished", name: "Unfinished code", cap: 40,
		weights: map[string]float64{"scaffold-code": 1.5, "placeholder-config": 1.5, "swallowed-errors": 1, "work-markers": 0.5},
		covers:  map[analyzer.TargetKind][]string{analyzer.TargetRepository: {"ai-signals", "code-health"}},
	},
	{
		id: "security", name: "Security shortcuts", cap: 30,
		weights: map[string]float64{
			"secret": 1, "committed-env-file": 1, "exposure": 1, "malicious-package": 1,
			"https": 0.5, "tls": 0.5, "mixed-content": 0.5,
			"vulnerable-library": 0.3, "cookie": 0.3, "vulnerability": 0.15, "security-header": 0.05, "sri": 0.1,
		},
		covers: map[analyzer.TargetKind][]string{
			analyzer.TargetWebsite: {"web-security", "web-tech"}, analyzer.TargetRepository: {"secrets", "vulns"},
		},
	},
	{
		id: "dependencies", name: "Dependency hygiene", cap: 20,
		weights: map[string]float64{"unknown-package": 1.5, "non-registry-dependency": 0.5, "unpinned-dependency": 0.3, "missing-lockfile": 0.3},
		covers:  map[analyzer.TargetKind][]string{analyzer.TargetRepository: {"dependencies", "vulns", "fingerprint"}},
	},
	{
		id: "organization", name: "Organization & tests", cap: 20,
		weights: map[string]float64{
			"missing-tests": 0.5, "missing-ci": 0.25,
			"duplication": 0.15, "complexity": 0.15, "dependency-cycle": 0.15,
			"large-file": 0.1, "long-function": 0.1, "deep-nesting": 0.1, "layer-violation": 0.1, "hotspot": 0.1,
		},
		covers: map[analyzer.TargetKind][]string{analyzer.TargetRepository: {"fingerprint", "code-health", "architecture"}},
	},
}

// SlopLabel converts a slop value to a label and a reader-oriented rating.
func SlopLabel(v int) (label, rating string) {
	switch {
	case v < 20:
		return "Low unfinished risk", "good"
	case v < 50:
		return "Moderate unfinished risk", "fair"
	}
	return "High unfinished risk", "poor"
}

// aiSlop computes the composite, or nil when it cannot be assessed: the
// ai-signals capability must have run successfully (a site with too little
// text, for example, is not assessable).
func (e *Engine) aiSlop(st *State, fs []finding.Finding) *report.Score {
	if rec, ok := st.Runs["ai-signals"]; !ok || rec.Run.Status != report.StatusOK {
		return nil
	}
	kind := st.Target.Kind
	ran := func(id string) bool {
		rec, ok := st.Runs[id]
		return ok && rec.Run.Status == report.StatusOK
	}
	var comps []report.ScoreComponent
	var basis, notAssessed []string
	var total float64
	counts := finding.Counts(nil)
	contributors := map[string]bool{"ai-signals": true}
	for _, g := range slopGroups {
		caps, applies := g.covers[kind]
		if !applies {
			continue
		}
		assessed := false
		for _, c := range caps {
			if ran(c) {
				assessed = true
				contributors[c] = true
			}
		}
		comp := report.ScoreComponent{ID: g.id, Name: g.name, Assessed: assessed}
		var pts float64
		for _, f := range fs {
			w, ok := g.weights[f.Category]
			if !ok {
				continue
			}
			comp.Findings++
			comp.FindingIDs = append(comp.FindingIDs, f.ID)
			counts[f.Severity]++
			contributors[f.Source.Capability] = true
			pts += severityPenalty[f.Severity] * f.Confidence.Weight() * w
		}
		comp.Points = math.Round(math.Min(pts, g.cap)*10) / 10
		total += comp.Points
		comps = append(comps, comp)
		switch {
		case !assessed:
			notAssessed = append(notAssessed, g.name)
		case comp.Findings == 0:
			basis = append(basis, g.name+": none found")
		default:
			basis = append(basis, fmt.Sprintf("%s: %d finding(s), %.1f points", g.name, comp.Findings, comp.Points))
		}
	}
	value := int(math.Round(100 * total / (total + slopHalfPoint)))
	label, rating := SlopLabel(value)
	conf := finding.ConfidenceMedium
	if len(notAssessed) > 0 {
		conf = finding.ConfidenceLow
		basis = append(basis, "Not assessed (run the full scan): "+strings.Join(notAssessed, ", "))
	}
	if sum := st.Runs["ai-signals"].Run.Summary; sum != "" {
		basis = append(basis, "AI-Generation Signals: "+sum)
	}
	ids := make([]string, 0, len(contributors))
	for id := range contributors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	summary := fmt.Sprintf("%s: indicators of unreviewed AI-generated work across %d group(s)", label, len(comps)-len(notAssessed))
	return &report.Score{
		ID: AISlopID, Name: "Unfinished Risk", Value: value, Rating: rating, Label: label,
		Direction: report.HigherIsWorse, Confidence: conf, Summary: summary, Counts: counts,
		Capabilities: ids, Basis: basis, Components: comps,
		Methodology: MethodologyBase + "#ai-slop",
	}
}
