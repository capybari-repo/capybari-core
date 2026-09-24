package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/report"
)

// MethodologyBase is where scoring methodology is published.
const MethodologyBase = "https://github.com/capybari-repo/capybari-docs/blob/main/methodology/scoring.md"

// Severity penalty points used by score aggregation. Documented in
// capybari-docs/methodology/scoring.md; changing them is a methodology change.
var severityPenalty = map[finding.Severity]float64{
	finding.Critical: 30, finding.High: 12, finding.Medium: 4, finding.Low: 1, finding.Info: 0,
}

// scoreHalfPoint is the penalty total at which a dimension scores 50.
const scoreHalfPoint = 40.0

var dimensionNames = map[string]string{
	finding.DimIdentity:        "Identity",
	finding.DimStructure:       "Structure",
	finding.DimDependencies:    "Dependency Hygiene",
	finding.DimSecurity:        "Security",
	finding.DimChangeRisk:      "Change Safety",
	finding.DimMaintainability: "Maintainability",
	finding.DimData:            "Data Protection",
	finding.DimInterfaces:      "Interfaces",
	finding.DimOperability:     "Operability",
	finding.DimEvolution:       "Technology Currency",
	finding.DimAISignals:       "AI Dependability",
}

// DimensionName returns the display name of a scored dimension.
func DimensionName(d string) string {
	if n, ok := dimensionNames[d]; ok {
		return n
	}
	return d
}

// Report renders the current state as a unified report.
func (e *Engine) Report(st *State) *report.Report {
	st.mu.RLock()
	defer st.mu.RUnlock()

	now := e.cfg.Now().UTC()
	r := &report.Report{
		SchemaVersion: report.SchemaVersion,
		Tool:          e.cfg.Tool,
		Scan: report.Scan{
			ID: st.ScanID, Target: st.Target, StartedAt: st.StartedAt.UTC(), FinishedAt: now,
			DurationMS: now.Sub(st.StartedAt).Milliseconds(), Mode: st.Mode,
			Question: st.Options[analyzer.OptionQuestion],
		},
		Facts:           map[string]json.RawMessage{},
		Findings:        []finding.Finding{},
		Scores:          []report.Score{},
		Recommendations: []report.Recommendation{},
		Capabilities:    []report.CapabilityRun{},
	}

	ids := make([]string, 0, len(st.Runs))
	for id := range st.Runs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rec := st.Runs[id]
		r.Capabilities = append(r.Capabilities, rec.Run)
		r.Findings = append(r.Findings, rec.Findings...)
		for _, a := range rec.Artifacts {
			r.Artifacts = append(r.Artifacts, report.ArtifactRef{Name: a.Name, Capability: id, MediaType: a.MediaType, Bytes: len(a.Data)})
		}
		for _, l := range rec.Run.Limitations {
			r.Limitations = append(r.Limitations, fmt.Sprintf("%s: %s", rec.Run.Name, l))
		}
	}
	finding.Sort(r.Findings)

	for k, raw := range st.Evidence {
		r.Facts[k] = publicFact(k, raw)
	}

	r.Scores = e.scores(st, r.Findings)
	r.Recommendations = e.recommend(st, r.Findings)
	r.Summary = summarize(st, r)
	r.DataBoundary = e.dataBoundary(st)
	r.Limitations = append(r.Limitations,
		"Automated analysis reports what its analyzers can detect. It does not certify software as secure or defect-free.")
	return r
}

// publicFact strips bulky internals (file lists, page bodies) from evidence
// before it is placed in the report.
func publicFact(key string, raw json.RawMessage) json.RawMessage {
	switch key {
	case facts.KeyInventory:
		var inv facts.Inventory
		if json.Unmarshal(raw, &inv) == nil {
			inv.Files = nil
			if b, err := json.Marshal(inv); err == nil {
				return b
			}
		}
	case facts.KeyWebSnapshot:
		var ws facts.WebSnapshot
		if json.Unmarshal(raw, &ws) == nil {
			ws.Body = ""
			ws.Links = nil
			for i := range ws.Pages {
				ws.Pages[i].HTML, ws.Pages[i].Text = "", ""
			}
			if b, err := json.Marshal(ws); err == nil {
				return b
			}
		}
	}
	return raw
}

func (e *Engine) scores(st *State, fs []finding.Finding) []report.Score {
	type dimInfo struct {
		ran, missing []string
		experimental bool
	}
	dims := map[string]*dimInfo{}
	for _, a := range e.cfg.Registry.All() {
		c := a.Capability()
		if !c.Supports(st.Target.Kind) {
			continue
		}
		rec, ran := st.Runs[c.ID]
		for _, d := range c.Scores {
			di := dims[d]
			if di == nil {
				di = &dimInfo{}
				dims[d] = di
			}
			if ran && rec.Run.Status == report.StatusOK {
				di.ran = append(di.ran, c.ID)
				di.experimental = di.experimental || c.Experimental()
			} else if ran && rec.Run.Status != report.StatusNotApplicable {
				di.missing = append(di.missing, c.ID)
			}
		}
	}
	out := []report.Score{}
	for d, di := range dims {
		if len(di.ran) == 0 {
			continue
		}
		var penalty float64
		var dimFindings []finding.Finding
		capOf := 100.0
		for _, f := range fs {
			// Every finding in the dimension counts, whichever capability
			// produced it; declared scores only decide whether the
			// dimension was assessed at all.
			if f.Dimension != d {
				continue
			}
			dimFindings = append(dimFindings, f)
			penalty += severityPenalty[f.Severity] * f.Confidence.Weight()
			if f.Confidence == finding.ConfidenceHigh {
				switch f.Severity {
				case finding.Critical:
					capOf = math.Min(capOf, 49)
				case finding.High:
					capOf = math.Min(capOf, 79)
				}
			}
		}
		value := int(math.Round(math.Min(capOf, 100/(1+penalty/scoreHalfPoint))))
		// Credit every capability that assessed or contributed to the dimension.
		contributors := slices.Clone(di.ran)
		for _, f := range dimFindings {
			if !slices.Contains(contributors, f.Source.Capability) {
				contributors = append(contributors, f.Source.Capability)
			}
		}
		sort.Strings(contributors)
		var basis []string
		for _, id := range contributors {
			if rec, ok := st.Runs[id]; ok && rec.Run.Status == report.StatusOK && rec.Run.Summary != "" {
				basis = append(basis, rec.Run.Name+": "+rec.Run.Summary)
			}
		}
		conf := finding.ConfidenceHigh
		if len(di.missing) > 0 {
			conf = finding.ConfidenceMedium
		}
		if di.experimental {
			conf = finding.ConfidenceLow
		}
		counts := finding.Counts(dimFindings)
		out = append(out, report.Score{
			ID: d, Name: DimensionName(d), Value: value, Rating: report.Rating(value), Confidence: conf,
			Summary: scoreSummary(counts, contributors, di.missing), Counts: counts, Capabilities: contributors, Basis: basis,
			Methodology: MethodologyBase + "#" + d,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func scoreSummary(counts map[finding.Severity]int, ran, missing []string) string {
	var parts []string
	for _, s := range finding.Severities {
		if counts[s] > 0 && s != finding.Info {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	msg := "No issues found"
	if len(parts) > 0 {
		msg = strings.Join(parts, ", ") + " finding(s)"
	}
	msg += " by " + strings.Join(ran, ", ")
	if len(missing) > 0 {
		msg += "; not assessed: " + strings.Join(missing, ", ")
	}
	return msg + "."
}

func summarize(st *State, r *report.Report) report.Summary {
	counts := finding.Counts(r.Findings)
	s := report.Summary{Counts: counts}
	for i, f := range r.Findings {
		if i == 5 || f.Severity.Rank() < finding.Medium.Rank() {
			break
		}
		s.TopFindings = append(s.TopFindings, f.ID)
	}
	ok := 0
	for _, c := range r.Capabilities {
		if c.Status == report.StatusOK {
			ok++
		}
	}
	serious := counts[finding.Critical] + counts[finding.High]
	switch {
	case serious > 0:
		dims := map[string]bool{}
		for _, f := range r.Findings {
			if f.Severity.Rank() >= finding.High.Rank() {
				dims[DimensionName(f.Dimension)] = true
			}
		}
		names := make([]string, 0, len(dims))
		for d := range dims {
			names = append(names, d)
		}
		sort.Strings(names)
		s.Headline = fmt.Sprintf("%s: %d critical/high finding(s) in %s. Start there.", st.Target.Display, serious, strings.Join(names, ", "))
	case counts[finding.Medium] > 0:
		s.Headline = fmt.Sprintf("%s: no critical or high findings; %d medium finding(s) worth reviewing.", st.Target.Display, counts[finding.Medium])
	default:
		s.Headline = fmt.Sprintf("%s: no significant issues found by %d capabilities.", st.Target.Display, ok)
	}
	return s
}

func (e *Engine) dataBoundary(st *State) report.DataBoundary {
	db := report.DataBoundary{Calls: slices.Clone(st.Calls)}
	used := map[string]bool{}
	for _, c := range st.Calls {
		if c.Count > 0 {
			db.LeftMachine = true
			used[c.Capability] = true
		}
	}
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if a, ok := e.cfg.Registry.Get(id); ok {
			db.Disclosures = append(db.Disclosures, report.Disclosure{Capability: id, Statement: a.Capability().Privacy})
		}
		if rec, ok := st.Runs[id]; ok && rec.Run.Execution.AI != analyzer.RequireNone && rec.Run.Status == report.StatusOK {
			db.AIUsed = db.AIUsed || rec.Run.Execution.AI == analyzer.RequireRequired
		}
	}
	switch {
	case st.Mode.Hosted:
		db.Statement = "This scan ran on Capybari hosted infrastructure. External requests made during the scan are listed below."
	case !db.LeftMachine:
		db.Statement = "No network requests were made. Nothing left this machine."
	default:
		hosts := map[string]bool{}
		for _, c := range st.Calls {
			if c.Count > 0 {
				hosts[c.Host] = true
			}
		}
		hs := make([]string, 0, len(hosts))
		for h := range hosts {
			hs = append(hs, h)
		}
		sort.Strings(hs)
		db.Statement = fmt.Sprintf("Network requests were made to %s by %s.", strings.Join(hs, ", "), strings.Join(ids, ", "))
		if !db.AIUsed && st.Target.Kind == analyzer.TargetRepository {
			db.Statement += " Source files were not uploaded; each disclosure states exactly what was sent."
		}
	}
	return db
}
