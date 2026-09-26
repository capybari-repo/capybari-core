package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/report"
	"github.com/capybari-repo/capybari-core/webtext"
)

// The Trust Score is the one number a report leads with: how much a
// visitor or buyer can trust what was scanned, 0-100 (higher is better).
//
//	score = min(100 − every deduction added up, the lowest ceiling hit)
//
// Every deficiency costs points and they all add up, whatever else is fine:
// missing configuration, a young domain, unreviewed AI output, missing
// legal or operational pages, ageing components, too little evidence to
// judge. Critical conditions are also ceilings the score can never exceed:
// a domain registered ten days ago has no track record, so no combination
// of other signals can make it trustworthy yet. Every point is itemised.
//
// Documented in capybari-docs/methodology/trust-score.md.

// TrustScoreID is the score ID of the Trust Score.
const TrustScoreID = "trust-score"

type tsGroup struct{ id, name string }

// tsGroups only organise the receipt; they do not cap anything.
var tsGroups = []tsGroup{
	{"security", "Security & configuration"},
	{"identity", "Identity & track record"},
	{"ai", "AI & unfinished work"},
	{"completeness", "Completeness & operations"},
	{"maintenance", "Maintenance & longevity"},
	{"coverage", "Evidence coverage"},
}

// TrustGrade converts a Trust Score to a letter, label and rating.
func TrustGrade(v int) (grade, label, rating string) {
	switch {
	case v >= 85:
		return "A", "High trust", "good"
	case v >= 70:
		return "B", "Good trust", "good"
	case v >= 55:
		return "C", "Doubts", "fair"
	case v >= 40:
		return "D", "Low trust", "poor"
	}
	return "F", "Very low trust", "poor"
}

// sev picks points by severity from critical, high, medium, low.
func sev(f finding.Finding, crit, high, med, low float64) float64 {
	switch f.Severity {
	case finding.Critical:
		return crit
	case finding.High:
		return high
	case finding.Medium:
		return med
	case finding.Low:
		return low
	}
	return 0
}

// aggregate categories are listed as one receipt line ("5 security headers
// missing"); the text is used when more than one finding contributes.
var aggregate = map[string]string{
	"security-header":         "%d security headers or settings missing",
	"disclosure":              "%d minor information disclosures",
	"cookie":                  "%d cookies without safe flags",
	"sri":                     "%d third-party scripts without integrity checks",
	"vulnerable-library":      "%d front-end libraries with known vulnerabilities",
	"vulnerability":           "%d dependencies with known vulnerabilities",
	"end-of-life":             "%d end-of-life components",
	"deprecated-library":      "%d deprecated libraries",
	"deprecated-package":      "%d deprecated dependencies",
	"unknown-package":         "%d dependencies not found in their public registry",
	"secret":                  "%d committed credentials",
	"code-health":             "%d code-health issues (complexity, duplication, size)",
	"architecture":            "%d structural issues (dependency cycles, layering)",
	"unpinned-dependency":     "%d unpinned dependencies",
	"ai-boilerplate":          "%d stock-copy findings",
	"template-leftover":       "%d template or generator leftovers",
	"scaffold-code":           "%d scaffolding leftovers in code",
	"swallowed-errors":        "%d places that silently swallow errors",
	"placeholder-config":      "%d placeholder configuration values",
	"linked-repo-inactive":    "%d inactive linked repositories",
	"unmaintained-dependency": "%d groups of unmaintained dependencies",
}

var codeHealth = map[string]bool{"complexity": true, "duplication": true, "long-function": true, "large-file": true,
	"deep-nesting": true, "many-parameters": true, "hotspot": true, "work-markers": true, "work-marker": true}

var architecture = map[string]bool{"dependency-cycle": true, "layer-violation": true, "high-coupling": true}

// findingCost says which group a finding costs points in, how many, and
// under which receipt key ("" = its own line).
func findingCost(f finding.Finding) (group string, pts float64, key string) {
	c := f.Category
	switch {
	case c == "ai-builder" || c == "ai-assistant-config" || c == "domain-new" || f.Severity == finding.Info && c != "disclosure" && c != "security-header":
		return "", 0, "" // AI use is not a deficiency; domain age is costed from the registration date
	case c == "security-header":
		if f.Severity == finding.Info {
			return "security", 1, c
		}
		return "security", sev(f, 4, 4, 3, 2), c
	case c == "disclosure":
		return "security", 1, c
	case c == "https":
		return "security", sev(f, 30, 30, 10, 5), ""
	case c == "tls":
		return "security", sev(f, 25, 20, 5, 2), ""
	case c == "mixed-content":
		return "security", sev(f, 15, 15, 5, 2), ""
	case c == "insecure-credentials":
		return "security", 30, ""
	case c == "secret":
		return "security", sev(f, 25, 20, 10, 3), c
	case c == "committed-env-file":
		return "security", 15, ""
	case c == "exposure":
		return "security", 20, ""
	case c == "malicious-package":
		return "security", 30, ""
	case c == "unknown-package":
		return "security", sev(f, 12, 12, 6, 3), c
	case c == "vulnerable-library" || c == "vulnerability":
		return "security", sev(f, 15, 10, 5, 2), c
	case c == "cookie" || c == "sri":
		return "security", sev(f, 3, 3, 3, 1), c
	case c == "email-spoofable":
		return "security", 6, ""
	case c == "domain-expiring":
		return "identity", 5, ""
	case c == "brand-mismatch":
		return "identity", 6, ""
	case c == "app-no-track-record":
		return "identity", 4, ""
	case c == "brand-inconsistent":
		return "identity", 3, ""
	case c == "linked-app-stale":
		return "maintenance", sev(f, 6, 6, 6, 3), ""
	case c == "placeholder-content":
		return "ai", 15, ""
	case c == "demo-names":
		return "ai", 3, ""
	case c == "ai-boilerplate" || c == "template-leftover" || c == "scaffold-code" || c == "swallowed-errors" || c == "placeholder-config":
		return "ai", sev(f, 15, 10, 6, 3), c
	case c == "coming-soon":
		return "completeness", 15, ""
	case c == "missing-legal":
		if f.Impact != nil && f.Impact.Buyer == finding.BuyerBlocks {
			return "completeness", 10, ""
		}
		return "completeness", 6, ""
	case c == "missing-contact":
		return "completeness", sev(f, 5, 5, 5, 3), ""
	case c == "no-ops-trail":
		return "completeness", 6, ""
	case c == "missing-refund" || c == "missing-docs" || c == "pricing-stub":
		return "completeness", 3, ""
	case c == "purchase-path-unverified" || c == "broken-link" || c == "dead-cta":
		return "completeness", sev(f, 6, 6, 6, 3), ""
	case c == "end-of-life" || c == "deprecated-library" || c == "runtime":
		return "maintenance", sev(f, 10, 10, 6, 3), c
	case c == "maintenance-signal":
		return "maintenance", 3, ""
	case c == "stale-content":
		return "maintenance", sev(f, 8, 8, 8, 4), ""
	case c == "inactive-repository":
		return "maintenance", sev(f, 15, 15, 8, 4), ""
	case c == "single-maintainer":
		return "maintenance", 5, ""
	case c == "license-restriction":
		return "maintenance", sev(f, 20, 20, 8, 4), ""
	case c == "unmaintained-dependency":
		return "maintenance", sev(f, 6, 6, 6, 3), c
	case c == "deprecated-package":
		return "maintenance", 4, c
	case c == "linked-repo-inactive" || c == "linked-repo-archived":
		return "maintenance", sev(f, 6, 6, 6, 3), c
	case c == "missing-tests":
		return "maintenance", 8, c
	case c == "missing-ci":
		return "maintenance", 4, c
	case c == "missing-license":
		return "maintenance", 4, ""
	case c == "missing-readme" || c == "missing-lockfile":
		return "maintenance", 3, ""
	case c == "unpinned-dependency":
		return "maintenance", 1, c
	case codeHealth[c]:
		return "maintenance", sev(f, 3, 2, 1, 0.5), "code-health"
	case architecture[c]:
		return "maintenance", sev(f, 3, 2, 2, 1), "architecture"
	}
	// Anything else costs by severity in the group of its buyer question.
	pts = sev(f, 20, 10, 5, 2)
	switch axisOf(f) {
	case report.AxisTrust:
		return "security", pts, ""
	case report.AxisFinish:
		return "completeness", pts, ""
	}
	return "maintenance", pts, ""
}

type tsLine struct {
	group, key, text string
	raw              float64
	ids              []string
	n                int
}

func (e *Engine) trustScore(st *State, fs []finding.Finding, scores []report.Score) *report.Score {
	kind := st.Target.Kind
	ran := func(id string) bool {
		rec, ok := st.Runs[id]
		return ok && rec.Run.Status == report.StatusOK
	}
	if kind == analyzer.TargetWebsite && !ran("web-snapshot") || kind == analyzer.TargetRepository && !ran("inventory") {
		return nil // nothing was read, so there is nothing to score
	}
	now := e.cfg.Now().UTC()
	var lines []*tsLine
	byKey := map[string]*tsLine{}
	add := func(group, key, text string, pts float64, id string) {
		if pts <= 0 {
			return
		}
		if key != "" {
			if l, ok := byKey[group+"/"+key]; ok {
				l.raw += pts
				l.n++
				if id != "" {
					l.ids = append(l.ids, id)
				}
				return
			}
		}
		l := &tsLine{group: group, key: key, text: text, raw: pts, n: 1}
		if id != "" {
			l.ids = []string{id}
		}
		lines = append(lines, l)
		if key != "" {
			byKey[group+"/"+key] = l
		}
	}

	// 1. Every finding that is a deficiency.
	domainFinding := ""
	for _, f := range fs {
		if f.Category == "domain-new" {
			domainFinding = f.ID
		}
		group, pts, key := findingCost(f)
		if group == "" {
			continue
		}
		add(group, key, report.ShortTitle(f.Title), pts, f.ID)
	}
	// A shipped application without tests or CI is worse than a library
	// or script without them: people depend on it running.
	if fp := fact[facts.Fingerprint](st, facts.KeyFingerprint); fp != nil && shippedProduct(fp) {
		for _, k := range []string{"maintenance/missing-tests", "maintenance/missing-ci"} {
			if l, ok := byKey[k]; ok {
				l.raw *= 1.5
				l.text += " (in a shipped application)"
			}
		}
	}

	// Code-health issues scale with a codebase's size, so they count with
	// diminishing weight: 4 issues cost 2 points, 100 cost 10.
	if l, ok := byKey["maintenance/code-health"]; ok {
		l.raw = math.Round(math.Sqrt(float64(l.n)))
	}

	// Ceilings: critical conditions hold the score down however good the
	// rest is. The lowest one applies.
	var ceilings []report.Ceiling
	ceil := func(maxScore int, reason, id string) {
		ceilings = append(ceilings, report.Ceiling{Max: maxScore, Reason: reason, FindingID: id})
	}
	for _, f := range fs {
		t := report.ShortTitle(f.Title)
		switch c := f.Category; {
		case c == "insecure-credentials":
			ceil(10, t, f.ID)
		case c == "https" && f.Severity.Rank() >= finding.High.Rank(),
			c == "tls" && f.Severity.Rank() >= finding.High.Rank(),
			(c == "secret" || c == "exposure" || c == "committed-env-file") && f.Severity.Rank() >= finding.High.Rank(),
			c == "malicious-package":
			ceil(20, t, f.ID)
		case c == "coming-soon":
			ceil(25, t, f.ID)
		case (c == "vulnerability" || c == "vulnerable-library") && f.Severity == finding.Critical,
			c == "license-restriction" && f.Severity.Rank() >= finding.High.Rank():
			ceil(30, t, f.ID)
		case c == "placeholder-content",
			c == "inactive-repository" && f.Severity.Rank() >= finding.High.Rank():
			ceil(40, t, f.ID)
		}
	}
	for _, sc := range scores {
		switch {
		case sc.ID == finding.DimSecurity && sc.Value < 60:
			ceil(sc.Value, fmt.Sprintf("Security score only %d/100", sc.Value), "")
		case sc.ID == AISlopID && sc.Value >= 50:
			ceil(40, fmt.Sprintf("Unfinished Risk %d/100 (%s)", sc.Value, sc.Label), "")
		}
	}
	if rec, ok := st.Runs["ai-signals"]; ok && rec.Run.Status == report.StatusNotApplicable && kind == analyzer.TargetWebsite {
		ceil(50, "Too little public content to judge", "")
	}

	// 2. Track record: the domain's age, from its registration date.
	if id := fact[facts.Identity](st, facts.KeyIdentity); id != nil && !id.Registered.IsZero() {
		age := now.Sub(id.Registered)
		days := int(age.Hours() / 24)
		text := fmt.Sprintf("Domain only %s old (registered %s)", ageText(id.Registered, now), id.Registered.Format("Jan 2006"))
		if age < 30*24*time.Hour {
			text = fmt.Sprintf("Domain only %d days old (registered %s)", days, id.Registered.Format("Jan 2006"))
		}
		// A young domain has no track record: no other signal can make up
		// for that, so it is a ceiling as well as a deduction.
		switch {
		case age < 30*24*time.Hour:
			add("identity", "", text, 20, domainFinding)
			ceil(10, text, domainFinding)
		case age < 91*24*time.Hour:
			add("identity", "", text, 15, domainFinding)
			ceil(30, text, domainFinding)
		case age < 182*24*time.Hour:
			add("identity", "", text, 12, domainFinding)
			ceil(50, text, domainFinding)
		case age < 365*24*time.Hour:
			add("identity", "", text, 6, domainFinding)
			ceil(70, text, domainFinding)
		}
	}

	// 3. A thin build costs completeness points.
	for _, s := range scores {
		if s.ID == BuildDepthID && s.Value < 65 {
			add("completeness", "", fmt.Sprintf("Thin build: Looks Shipped %d/100", s.Value), math.Min(12, math.Round(float64(65-s.Value)/3)), "")
		}
	}

	// 4. Evidence coverage: what could not be judged counts against trust.
	for _, id := range sortedRunIDs(st) {
		r := st.Runs[id].Run
		if r.Status == report.StatusFailed || r.Status == report.StatusSkipped {
			add("coverage", "", fmt.Sprintf("%s could not run: %s", r.Name, firstClause(r.Reason)), 3, "")
		}
	}
	if rec, ok := st.Runs["ai-signals"]; ok && rec.Run.Status == report.StatusNotApplicable {
		pts := 15.0
		if kind == analyzer.TargetRepository {
			pts = 8
		}
		add("coverage", "", "Too little content to assess: "+firstClause(rec.Run.Reason), pts, "")
	}
	if kind == analyzer.TargetWebsite {
		if raw, ok := st.Evidence[facts.KeyWebSnapshot]; ok {
			var ws facts.WebSnapshot
			if json.Unmarshal(raw, &ws) == nil {
				content := 0
				if webtext.Words(webtext.Visible(ws.Body)) >= contentWords {
					content++
				}
				for _, p := range ws.Pages {
					if p.Words >= contentWords {
						content++
					}
				}
				switch {
				case content == 0:
					add("coverage", "", "No public page with real content to judge", 6, "")
				case content == 1:
					add("coverage", "", "Only 1 public page with real content to judge", 6, "")
				case content == 2:
					add("coverage", "", "Only 2 public pages with real content to judge", 3, "")
				}

			}
		}
	} else if inv := fact[facts.Inventory](st, facts.KeyInventory); inv != nil {
		src := inv.KindCounts[facts.KindSource]
		switch {
		case src < 10:
			add("coverage", "", fmt.Sprintf("Tiny codebase: only %d source file%s to judge", src, map[bool]string{true: "", false: "s"}[src == 1]), 12, "")
		case src < 40:
			add("coverage", "", fmt.Sprintf("Small codebase: %d source files to judge", src), 5, "")
		}
		if fp := fact[facts.Fingerprint](st, facts.KeyFingerprint); fp != nil && fp.Git == nil {
			add("coverage", "", "No version history available", 4, "")
		}
	}

	// Plural texts for aggregated lines.
	for _, l := range lines {
		if l.key != "" && l.n > 1 {
			if t, ok := aggregate[l.key]; ok {
				l.text = fmt.Sprintf(t, l.n)
			}
		}
	}

	// Everything adds up: no area is capped.
	var comps []report.ScoreComponent
	var deds []report.Deduction
	var basis []string
	total := 0
	for _, g := range tsGroups {
		taken, n := 0, 0
		for _, l := range lines {
			if l.group != g.id {
				continue
			}
			p := int(math.Round(l.raw))
			if p <= 0 {
				continue
			}
			id := ""
			if len(l.ids) > 0 {
				id = l.ids[0]
			}
			deds = append(deds, report.Deduction{Group: g.id, Text: l.text, Points: p, FindingID: id})
			taken += p
			n++
		}
		total += taken
		comps = append(comps, report.ScoreComponent{ID: g.id, Name: g.name, Points: float64(taken), Findings: n, Assessed: true})
		if taken == 0 {
			basis = append(basis, g.name+": nothing deducted")
		} else {
			basis = append(basis, fmt.Sprintf("%s: −%d", g.name, taken))
		}
	}
	sort.SliceStable(deds, func(i, j int) bool { return deds[i].Points > deds[j].Points })
	sort.SliceStable(ceilings, func(i, j int) bool { return ceilings[i].Max < ceilings[j].Max })
	value := max(0, 100-total)
	if len(ceilings) > 0 && ceilings[0].Max < value {
		value = ceilings[0].Max
		basis = append([]string{fmt.Sprintf("Held at %d: %s", ceilings[0].Max, ceilings[0].Reason)}, basis...)
	}
	grade, label, rating := TrustGrade(value)
	conf := finding.ConfidenceMedium
	for _, c := range comps {
		if c.ID == "coverage" && c.Points > 5 {
			conf = finding.ConfidenceLow
		}
	}
	summary := fmt.Sprintf("%s (%s): %d point(s) deducted", label, grade, total)
	if len(ceilings) > 0 && ceilings[0].Max == value {
		summary = fmt.Sprintf("%s (%s): held at %d by %s", label, grade, value, lowerFirst(ceilings[0].Reason))
	} else if len(deds) > 0 {
		summary += fmt.Sprintf(", largest: %s (−%d)", lowerFirst(deds[0].Text), deds[0].Points)
	}
	return &report.Score{
		ID: TrustScoreID, Name: "Trust Score", Value: value, Rating: rating, Label: label, Grade: grade,
		Direction: report.HigherIsBetter, Confidence: conf, Summary: summary, Counts: finding.Counts(fs),
		Capabilities: sortedRunIDs(st), Basis: basis, Components: comps, Deductions: deds, Ceilings: ceilings,
		Methodology: MethodologyBase + "#trust-score",
	}
}

// shippedProduct reports whether a repository looks like something people
// run or buy (an application or a deployable service), not a library.
func shippedProduct(fp *facts.Fingerprint) bool {
	if fp.HasContainers {
		return true
	}
	for _, t := range fp.ProjectTypes {
		switch t {
		case "web-backend", "web-frontend", "mobile-app", "desktop-app", "application", "cms-site":
			return true
		}
	}
	return false
}

// contentWords is the visible text a page needs to count as content.
const contentWords = 80

func sortedRunIDs(st *State) []string {
	ids := make([]string, 0, len(st.Runs))
	for id := range st.Runs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// firstClause keeps a reason short: up to the first semicolon.
func firstClause(s string) string {
	if i := strings.Index(s, ";"); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
