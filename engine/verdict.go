package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/report"
)

// The verdict leads every report with three buyer questions (Trust,
// Finish, Risk). Each level is derived from findings tagged with their
// buyer impact plus the Unfinished Risk and Looks Shipped scores, and
// always lists its reasons. It reports observations, never advice.
//
// Documented in capybari-docs/methodology/verdict.md.

// VerdictDisclaimer is shown wherever the verdict is.
const VerdictDisclaimer = "Automated indicators from public evidence, not a recommendation or certification. Check the reasons and what was not checked."

// maxReasons bounds the reasons listed per axis.
const maxReasons = 6

// axisOf assigns a finding to a buyer question, or "" when it answers none
// (informational findings about AI use, for example).
func axisOf(f finding.Finding) string {
	switch f.Category {
	case "https", "tls", "mixed-content", "secret", "committed-env-file", "exposure", "malicious-package",
		"unknown-package", "vulnerable-library", "vulnerability", "cookie", "security-header", "disclosure", "sri",
		"insecure-credentials", "missing-legal", "missing-contact", "missing-refund":
		return report.AxisTrust
	case "coming-soon", "pricing-stub", "broken-link", "missing-docs":
		return report.AxisFinish
	case "stale-content", "linked-repo-inactive", "linked-repo-archived", "inactive-repository", "single-maintainer",
		"license-restriction", "unmaintained-dependency", "deprecated-package":
		return report.AxisRisk
	}
	switch f.Dimension {
	case finding.DimSecurity, finding.DimTrust, finding.DimData:
		return report.AxisTrust
	case finding.DimAISignals:
		if f.Category == "ai-builder" || f.Category == "ai-assistant-config" {
			return ""
		}
		return report.AxisFinish
	case finding.DimEvolution, finding.DimDependencies, finding.DimMaintainability, finding.DimStructure,
		finding.DimOperability, finding.DimChangeRisk:
		return report.AxisRisk
	}
	return ""
}

// covers lists the capabilities that can answer each question.
var covers = map[string]map[analyzer.TargetKind][]string{
	report.AxisTrust: {
		analyzer.TargetWebsite:    {"web-security", "commerce"},
		analyzer.TargetRepository: {"secrets", "vulns"},
	},
	report.AxisFinish: {
		analyzer.TargetWebsite:    {"ai-signals", "commerce", "completeness"},
		analyzer.TargetRepository: {"ai-signals"},
	},
	report.AxisRisk: {
		analyzer.TargetWebsite:    {"web-tech", "completeness"},
		analyzer.TargetRepository: {"longevity", "tech-detect", "dependencies", "vulns", "fingerprint", "code-health"},
	},
}

type verdictInput struct {
	st           *State
	fs           []finding.Finding
	scores       map[string]report.Score
	commerce     *facts.Commerce
	depth        *facts.SiteDepth
	longevity    *facts.Longevity
	completeness *facts.Completeness
	now          time.Time
}

// fact decodes evidence into out when present.
func fact[T any](st *State, key string) *T {
	raw, ok := st.Evidence[key]
	if !ok {
		return nil
	}
	var v T
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return &v
}

// ago phrases how long before now t was, e.g. "3 weeks ago".
func ago(t, now time.Time) string {
	d := now.Sub(t)
	switch days := int(d.Hours() / 24); {
	case days < 1:
		return "today"
	case days < 14:
		return fmt.Sprintf("%d days ago", days)
	case days < 60:
		return fmt.Sprintf("%d weeks ago", days/7)
	case days < 730:
		return fmt.Sprintf("%d months ago", days/30)
	default:
		return fmt.Sprintf("%d years ago", days/365)
	}
}

func (v *verdictInput) ran(id string) bool {
	rec, ok := v.st.Runs[id]
	return ok && rec.Run.Status == report.StatusOK
}

func (e *Engine) verdict(st *State, fs []finding.Finding, scores []report.Score) *report.Verdict {
	v := &verdictInput{st: st, fs: fs, scores: map[string]report.Score{}, now: e.cfg.Now().UTC(),
		commerce: fact[facts.Commerce](st, facts.KeyCommerce), depth: fact[facts.SiteDepth](st, facts.KeySiteDepth),
		longevity: fact[facts.Longevity](st, facts.KeyLongevity), completeness: fact[facts.Completeness](st, facts.KeyCompleteness)}
	for _, s := range scores {
		v.scores[s.ID] = s
	}
	out := &report.Verdict{Impact: map[string]int{finding.BuyerBlocks: 0, finding.BuyerSupportCost: 0, finding.BuyerCosmetic: 0}, Disclaimer: VerdictDisclaimer}
	for _, f := range fs {
		out.Impact[BuyerImpact(f)]++
	}
	var labels []string
	for _, ax := range []func() report.VerdictAxis{v.trust, v.finish, v.risk} {
		a := ax()
		out.Axes = append(out.Axes, a)
		labels = append(labels, a.Label)
	}
	out.Headline = strings.Join(labels, " · ")
	out.NotChecked = v.notChecked()
	return out
}

// concerns returns the axis's findings that matter to a buyer, blockers
// first, as reasons; and the highest impact seen.
func (v *verdictInput) concerns(axis string) (rs []report.VerdictReason, blocks, support int, worstSupport finding.Severity) {
	type c struct {
		f finding.Finding
		b string
	}
	var cs []c
	for _, f := range v.fs {
		if axisOf(f) != axis {
			continue
		}
		b := BuyerImpact(f)
		switch b {
		case finding.BuyerBlocks:
			blocks++
		case finding.BuyerSupportCost:
			support++
			if f.Severity.Rank() > worstSupport.Rank() {
				worstSupport = f.Severity
			}
		default:
			continue
		}
		cs = append(cs, c{f, b})
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if (cs[i].b == finding.BuyerBlocks) != (cs[j].b == finding.BuyerBlocks) {
			return cs[i].b == finding.BuyerBlocks
		}
		return cs[i].f.Severity.Rank() > cs[j].f.Severity.Rank()
	})
	for _, x := range cs {
		rs = append(rs, report.VerdictReason{Text: reasonText(x.f), Kind: "concern", Impact: x.b, FindingID: x.f.ID})
	}
	return rs, blocks, support, worstSupport
}

// reasonText phrases a finding for a buyer, quoting the evidence where it
// makes the point better than the title.
func reasonText(f finding.Finding) string {
	if f.Category == "placeholder-content" && len(f.Evidence) > 0 {
		phrase, _, _ := strings.Cut(f.Evidence[0].Detail, " ×")
		where := pathOf(f.Evidence[0].URL)
		return fmt.Sprintf("Placeholder text still on the site: %s%s", phrase, where)
	}
	return f.Title
}

func pathOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		if j := strings.Index(u[i+3:], "/"); j >= 0 && len(u[i+3+j:]) > 1 {
			return " (" + u[i+3+j:] + ")"
		}
	}
	return ""
}

func (v *verdictInput) covered(axis string) bool {
	for _, id := range covers[axis][v.st.Target.Kind] {
		if v.ran(id) {
			return true
		}
	}
	return false
}

func positive(text string) report.VerdictReason {
	return report.VerdictReason{Text: text, Kind: "positive"}
}

func limit(rs []report.VerdictReason) []report.VerdictReason {
	if len(rs) > maxReasons {
		return rs[:maxReasons]
	}
	return rs
}

func (v *verdictInput) has(cats ...string) bool {
	for _, f := range v.fs {
		for _, c := range cats {
			if f.Category == c {
				return true
			}
		}
	}
	return false
}

func (v *verdictInput) trust() report.VerdictAxis {
	a := report.VerdictAxis{ID: report.AxisTrust, Name: "Trust", Question: "Can I trust it with my data, money or account?"}
	if !v.covered(report.AxisTrust) {
		a.Label, a.Rating = "Trust not assessed", "unknown"
		return a
	}
	rs, blocks, support, _ := v.concerns(report.AxisTrust)
	var pos []report.VerdictReason
	web := v.st.Target.Kind == analyzer.TargetWebsite
	if web && v.ran("web-security") && !v.has("https", "tls") {
		pos = append(pos, positive("HTTPS with a valid certificate"))
	}
	c := v.commerce
	if c != nil {
		if len(c.PaymentProviders) > 0 {
			pos = append(pos, positive("Payments handled by "+strings.Join(c.PaymentProviders, ", ")))
		}
		if len(c.Stores) > 0 {
			pos = append(pos, positive("Distributed through "+strings.Join(c.Stores, ", ")))
		}
		switch {
		case c.Privacy != "" && c.Terms != "":
			pos = append(pos, positive("Privacy policy and terms published"))
		case c.Privacy != "":
			pos = append(pos, positive("Privacy policy published"))
		}
		if c.Refund != "" {
			pos = append(pos, positive("Refund or cancellation policy published"))
		}
		if c.Contact != "" {
			pos = append(pos, positive("Contact details published"))
		}
	}
	if !web {
		if v.ran("secrets") && !v.has("secret", "committed-env-file") {
			pos = append(pos, positive("No committed credentials found"))
		}
		if v.ran("vulns") && !v.has("vulnerability", "malicious-package", "unknown-package") {
			pos = append(pos, positive("No known-vulnerable or unknown dependencies"))
		}
	}
	a.Reasons = limit(append(rs, pos...))
	switch {
	case blocks > 0:
		a.Label, a.Rating = "Trust blockers found", "poor"
	case support > 0:
		a.Label, a.Rating = "Trust gaps", "fair"
	case c != nil && c.Sells && (len(c.PaymentProviders) > 0 || c.Checkout) && c.Privacy != "" && c.Terms != "":
		a.Label, a.Rating = "Commerce-ready", "good"
	default:
		a.Label, a.Rating = "No trust blockers", "good"
	}
	return a
}

func (v *verdictInput) finish() report.VerdictAxis {
	a := report.VerdictAxis{ID: report.AxisFinish, Name: "Finish", Question: "Is it finished enough to rely on, or still a demo?"}
	slop, hasSlop := v.scores[AISlopID]
	depth, hasDepth := v.scores[BuildDepthID]
	if !v.covered(report.AxisFinish) || (!hasSlop && !hasDepth && v.commerce == nil) {
		a.Label, a.Rating = "Finish not assessed", "unknown"
		return a
	}
	rs, blocks, support, _ := v.concerns(report.AxisFinish)
	if v.depth != nil {
		var missing []string
		for _, c := range v.depth.Checks {
			if c.Earned < c.Max/2 && c.Group != "specificity" && c.Group != "originality" {
				missing = append(missing, c.Name)
			}
		}
		if len(missing) > 0 {
			if len(missing) > 5 {
				missing = append(missing[:5], "…")
			}
			rs = append(rs, report.VerdictReason{Text: "Not yet in place: " + strings.Join(missing, ", "), Kind: "concern", Impact: finding.BuyerCosmetic})
		}
	}
	// Name the scores when they, rather than a single finding, set the level.
	if hasSlop && slop.Value >= 20 {
		rs = append(rs, report.VerdictReason{Text: fmt.Sprintf("Unfinished Risk %d/100 (%s)", slop.Value, slop.Label), Kind: "concern", Impact: finding.BuyerSupportCost})
	}
	if hasDepth && depth.Value < 65 {
		rs = append(rs, report.VerdictReason{Text: fmt.Sprintf("Looks Shipped %d/100 (%s)", depth.Value, depth.Label), Kind: "concern", Impact: finding.BuyerSupportCost})
	}
	var pos []report.VerdictReason
	if v.depth != nil {
		met := map[string]bool{}
		for _, c := range v.depth.Checks {
			met[c.ID] = c.Earned >= c.Max
		}
		content := 0
		for _, c := range v.depth.Checks {
			if c.ID == "content-pages" {
				content = int(c.Earned)
			}
		}
		if content >= 12 {
			pos = append(pos, positive("Several pages of real content"))
		}
		if met["title"] && met["description"] && met["share-preview"] && met["favicon"] {
			pos = append(pos, positive("Titles, description, link preview and favicon all set"))
		}
		if met["privacy"] && met["about"] {
			pos = append(pos, positive("About and privacy pages"))
		}
	}
	if c := v.completeness; c != nil {
		var has []string
		for _, x := range []struct{ v, name string }{{c.Docs, "documentation"}, {c.Changelog, "a changelog"}, {c.StatusPage, "a status page"}, {c.Community, "a support community"}} {
			if x.v != "" {
				has = append(has, x.name)
			}
		}
		if len(has) > 0 {
			pos = append(pos, positive("Has "+joinAnd(has)))
		}
	}
	if hasSlop && slop.Value < 20 && blocks == 0 && !v.has("placeholder-content", "template-leftover") {
		pos = append(pos, positive("No placeholders, template leftovers or generator defaults"))
	}
	a.Reasons = limit(append(rs, pos...))
	switch {
	case blocks > 0 || v.has("placeholder-content") || hasSlop && slop.Value >= 50 || hasDepth && depth.Value < 35:
		a.Label, a.Rating = "Unfinished", "poor"
	case support > 0 || hasSlop && slop.Value >= 20 || hasDepth && depth.Value < 65:
		a.Label, a.Rating = "Partly finished", "fair"
	default:
		a.Label, a.Rating = "Looks shipped", "good"
	}
	return a
}

func (v *verdictInput) risk() report.VerdictAxis {
	a := report.VerdictAxis{ID: report.AxisRisk, Name: "Risk", Question: "What breaks or ages badly in the next 6–12 months?"}
	if !v.covered(report.AxisRisk) {
		a.Label, a.Rating = "Risk not assessed", "unknown"
		return a
	}
	rs, blocks, support, worst := v.concerns(report.AxisRisk)
	var pos []report.VerdictReason
	if c := v.completeness; c != nil && !c.LatestDate.IsZero() && v.now.Sub(c.LatestDate) < 365*24*time.Hour {
		pos = append(pos, positive(fmt.Sprintf("Content updated %s (%s)", ago(c.LatestDate, v.now), sourceName(c.LatestDateSource))))
	}
	if c := v.completeness; c != nil {
		for _, r := range c.Repos {
			if !r.Archived && !r.PushedAt.IsZero() && v.now.Sub(r.PushedAt) < 180*24*time.Hour {
				pos = append(pos, positive(fmt.Sprintf("Linked source repository updated %s", ago(r.PushedAt, v.now))))
				break
			}
		}
	}
	if l := v.longevity; l != nil {
		if l.CommitsLastYear > 0 {
			pos = append(pos, positive(fmt.Sprintf("Active: %d commits in %d of the last 12 months", l.CommitsLastYear, l.ActiveMonths)))
		}
		if l.BusFactor >= 2 {
			pos = append(pos, positive(fmt.Sprintf("Shared maintenance: %d people made half the recent commits", l.BusFactor)))
		}
		if l.LatestRelease != "" && v.now.Sub(l.LatestReleaseDate) < 365*24*time.Hour {
			pos = append(pos, positive(fmt.Sprintf("Latest release %s, %s", l.LatestRelease, ago(l.LatestReleaseDate, v.now))))
		}
		if l.LicenseClass == "permissive" {
			pos = append(pos, positive(l.License+" license allows commercial use"))
		}
	}
	if !v.has("end-of-life", "deprecated-library", "runtime") {
		pos = append(pos, positive("No end-of-life components detected"))
	}
	if v.st.Target.Kind == analyzer.TargetRepository && v.ran("fingerprint") && !v.has("missing-tests", "missing-ci") {
		pos = append(pos, positive("Tests and CI present"))
	}
	a.Reasons = limit(append(rs, pos...))
	switch {
	case blocks > 0 || worst.Rank() >= finding.High.Rank():
		a.Label, a.Rating = "High regret risk", "poor"
	case support > 0:
		a.Label, a.Rating = "Some aging risk", "fair"
	default:
		a.Label, a.Rating = "Low regret risk", "good"
	}
	return a
}

func (v *verdictInput) notChecked() []string {
	var out []string
	if v.st.Target.Kind == analyzer.TargetWebsite {
		out = append(out, "Code quality, tests and dependencies (a website scan sees only public pages; scan the repository for these)",
			"Pages behind a login, and whether checkout actually completes")
	} else {
		out = append(out, "The running product (scan its website for trust and finish signals)")
	}
	ids := make([]string, 0, len(v.st.Runs))
	for id := range v.st.Runs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := v.st.Runs[id].Run
		skipped := r.Status == report.StatusSkipped || r.Status == report.StatusFailed
		if skipped || r.Status == report.StatusNotApplicable && relevant(id) {
			out = append(out, fmt.Sprintf("%s: %s", r.Name, strings.TrimSpace(string(r.Status)+" — "+r.Reason)))
		}
	}
	return append(out, "Comparison with similar products (peer benchmarks are not available yet)")
}

// joinAnd joins items as "a, b and c".
func joinAnd(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// sourceName shortens a date source URL to its path.
func sourceName(src string) string {
	if p := strings.TrimPrefix(pathOf(src), " ("); p != "" {
		return strings.TrimSuffix(p, ")")
	}
	if strings.Contains(src, "://") {
		return "front page"
	}
	return src
}

// relevant reports whether a not-applicable capability is worth naming in
// the verdict (one a buyer would expect to have run).
func relevant(id string) bool {
	return id == "ai-signals" || id == "commerce" || id == "vulns" || id == "dependencies" || id == "longevity" || id == "completeness"
}
