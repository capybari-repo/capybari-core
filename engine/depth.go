package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/report"
)

// The Looks Shipped score (ID "build-depth") is the counterpart of
// Unfinished Risk: instead of
// counting what is wrong, it credits signs of effort (several real pages,
// specific facts, finished metadata, trust pages, extra craft). AI use is
// not penalised; a carefully built AI-assisted site scores high, a site
// generated in a few prompts scores low. 0 = shallow, 100 = deep.
//
// Documented in capybari-docs/methodology/scoring.md#build-depth.

// BuildDepthID is the score ID of the Looks Shipped score.
const BuildDepthID = "build-depth"

// depthGroups lists the groups in display order with their names.
var depthGroups = []struct{ id, name string }{
	{"breadth", "Content breadth"},
	{"specificity", "Specific content"},
	{"originality", "Original copy"},
	{"finish", "Finishing touches"},
	{"trust", "Trust pages"},
	{"craft", "Extra craft"},
}

// DepthLabel converts a Looks Shipped value to a label and rating.
func DepthLabel(v int) (label, rating string) {
	switch {
	case v < 35:
		return "Thin build", "poor"
	case v < 65:
		return "Partly shipped", "fair"
	}
	return "Looks shipped", "good"
}

func (e *Engine) buildDepth(st *State) *report.Score {
	if rec, ok := st.Runs["ai-signals"]; !ok || rec.Run.Status != report.StatusOK {
		return nil
	}
	raw, ok := st.Evidence[facts.KeySiteDepth]
	if !ok {
		return nil
	}
	var d facts.SiteDepth
	if json.Unmarshal(raw, &d) != nil || len(d.Checks) == 0 {
		return nil
	}
	var comps []report.ScoreComponent
	var basis []string
	var total float64
	for _, g := range depthGroups {
		comp := report.ScoreComponent{ID: g.id, Name: g.name, Assessed: true}
		var met, missing []string
		for _, c := range d.Checks {
			if c.Group != g.id {
				continue
			}
			comp.Points += c.Earned
			comp.Max += c.Max
			item := c.Name
			if c.Detail != "" {
				item += " (" + c.Detail + ")"
			}
			if c.Earned >= c.Max {
				met = append(met, item)
			} else {
				missing = append(missing, item)
			}
		}
		if comp.Max == 0 {
			continue
		}
		comp.Points = math.Round(comp.Points*10) / 10
		total += comp.Points
		comps = append(comps, comp)
		line := fmt.Sprintf("%s %.0f/%.0f", g.name, comp.Points, comp.Max)
		if len(met) > 0 {
			line += ": has " + strings.Join(met, ", ")
		}
		if len(missing) > 0 {
			line += "; missing or partial: " + strings.Join(missing, ", ")
		}
		basis = append(basis, line)
	}
	value := int(math.Round(math.Min(100, total)))
	label, rating := DepthLabel(value)
	return &report.Score{
		ID: BuildDepthID, Name: "Looks Shipped", Value: value, Rating: rating, Label: label,
		Direction: report.HigherIsBetter, Confidence: finding.ConfidenceLow,
		Summary:      fmt.Sprintf("%s: signs of effort across %d page(s) and %d words; AI use itself is not penalised", label, d.Pages, d.Words),
		Counts:       finding.Counts(nil),
		Capabilities: []string{"ai-signals", "web-snapshot"},
		Basis:        basis, Components: comps,
		Caveat:      fmt.Sprintf("Based on %d public page(s) only", d.Pages),
		Methodology: MethodologyBase + "#build-depth",
	}
}
