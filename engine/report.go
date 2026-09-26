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
	finding.DimTrust:           "Trust & Commerce",
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

	tagBuyerImpact(r.Findings)
	sortForBuyers(r.Findings)
	r.Scores = e.scores(st, r.Findings)
	r.Verdict = e.verdict(st, r.Findings, r.Scores)
	r.Recommendations = e.recommend(st, r.Findings)
	r.Summary = summarize(st, r)
	// The Trust Score leads the summary when there is one.
	for _, sc := range r.Scores {
		if sc.ID == TrustScoreID {
			lead := fmt.Sprintf("%s: Trust Score %d/100 (%s, %s)", st.Target.Display, sc.Value, sc.Grade, sc.Label)
			if len(sc.Ceilings) > 0 && sc.Ceilings[0].Max == sc.Value {
				lead += fmt.Sprintf(", held at %d: %s", sc.Value, lowerFirst(report.ShortTitle(sc.Ceilings[0].Reason)))
			}
			var top []string
			for i, d := range sc.Deductions {
				if i == 3 {
					break
				}
				top = append(top, fmt.Sprintf("%s (−%d)", lowerFirst(report.ShortTitle(d.Text)), d.Points))
			}
			if len(top) > 0 {
				lead += ". Biggest negative impacts: " + strings.Join(top, "; ")
			}
			r.Summary.Headline = lead + "."
		}
	}
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
	caveats(st, out)
	if depth := e.buildDepth(st); depth != nil {
		out = append([]report.Score{*depth}, out...)
	}
	if slop := e.aiSlop(st, fs); slop != nil {
		out = append([]report.Score{*slop}, out...)
	}
	if ts := e.trustScore(st, fs, out); ts != nil {
		out = append([]report.Score{*ts}, out...)
	}
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
	// Top findings are what matters to a buyer; owner homework (security
	// headers and the like) never leads, however many there are.
	var buyer []string
	for _, f := range r.Findings {
		if f.Impact != nil && f.Impact.Buyer == finding.BuyerCosmetic {
			if f.Severity != finding.Info {
				s.OwnerHomework++
			}
			continue
		}
		if len(s.TopFindings) < 5 {
			s.TopFindings = append(s.TopFindings, f.ID)
		}
		if len(buyer) < 2 {
			buyer = append(buyer, lowerFirst(report.ShortTitle(f.Title)))
		}
	}
	owner := ""
	if s.OwnerHomework > 0 {
		owner = fmt.Sprintf(" Owner homework: %d header and configuration gap(s).", s.OwnerHomework)
	}
	if len(buyer) > 0 {
		lead := "buyer concern"
		if f := r.Findings[0]; f.Impact != nil && f.Impact.Buyer == finding.BuyerBlocks {
			lead = "purchase blocker"
		}
		s.Headline = fmt.Sprintf("%s: %s: %s.%s", st.Target.Display, lead, strings.Join(buyer, "; "), owner)
		return s
	}
	ok := 0
	for _, c := range r.Capabilities {
		if c.Status == report.StatusOK {
			ok++
		}
	}
	if s.OwnerHomework > 0 {
		s.Headline = fmt.Sprintf("%s: no buyer concerns found by %d capabilities.%s", st.Target.Display, ok, owner)
		return s
	}
	s.Headline = fmt.Sprintf("%s: no significant issues found by %d capabilities.", st.Target.Display, ok)
	return s
}

// lowerFirst lowercases an ordinary first word ("Email in…" → "email
// in…") but keeps acronyms and names ("HTTPS", "jQuery") as they are.
func lowerFirst(s string) string {
	if len(s) > 1 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'a' && s[1] <= 'z' {
		return strings.ToLower(s[:1]) + s[1:]
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

// caveats stamps scores whose evidence is thin, so that a high number with
// little behind it is never shown bare.
func caveats(st *State, scores []report.Score) {
	for i := range scores {
		sc := &scores[i]
		if sc.ID == finding.DimEvolution && st.Target.Kind == analyzer.TargetWebsite {
			if t := fact[facts.Technologies](st, facts.KeyTechnologies); t != nil {
				high := 0
				for _, it := range t.Items {
					if it.Confidence == "high" {
						high++
					}
				}
				if high < 3 {
					sc.Caveat = fmt.Sprintf("Limited fingerprint: only %d technolog%s identified with confidence", high, map[bool]string{true: "y", false: "ies"}[high == 1])
					sc.Confidence = finding.ConfidenceLow
				}
			}
		}
		if sc.Caveat == "" && sc.Value >= 90 && sc.Confidence == finding.ConfidenceLow {
			sc.Caveat = "Low confidence: limited evidence behind this score"
		}
	}
}
