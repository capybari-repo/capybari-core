// Package report defines the unified Source Intelligence report and its
// exporters (JSON, Markdown, HTML and SARIF). The JSON form is canonical and
// is described by capybari-schemas/report.schema.json.
package report

import (
	"encoding/json"
	"time"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/netguard"
)

// SchemaVersion of the report format.
const SchemaVersion = "0.1"

// Tool identifies the program that produced the report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

// Mode records scan-wide switches that change what was analysed.
type Mode struct {
	Offline bool `json:"offline"`
	Active  bool `json:"active"`
	Hosted  bool `json:"hosted"`
}

// Scan describes one scan.
type Scan struct {
	ID         string          `json:"id"`
	Target     analyzer.Target `json:"target"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	DurationMS int64           `json:"duration_ms"`
	Mode       Mode            `json:"mode"`
	Question   string          `json:"question,omitempty"`
}

// Run statuses.
const (
	StatusOK = "ok"
	// StatusNotApplicable: nothing for the capability to analyse on this
	// target (e.g. no lockfiles). It does not lower score confidence.
	StatusNotApplicable = "not-applicable"
	// StatusSkipped: the capability could have produced results but did not
	// run (offline, no AI provider, an upstream capability failed).
	StatusSkipped = "skipped"
	StatusFailed  = "failed"
)

// CapabilityRun is the outcome of one capability in this scan.
type CapabilityRun struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Version      string             `json:"version"`
	Category     string             `json:"category"`
	Status       string             `json:"status"`
	Reason       string             `json:"reason,omitempty"`
	Summary      string             `json:"summary,omitempty"`
	DurationMS   int64              `json:"duration_ms"`
	Cached       bool               `json:"cached,omitempty"`
	Findings     int                `json:"findings"`
	Experimental bool               `json:"experimental,omitempty"`
	Execution    analyzer.Execution `json:"execution"`
	Engines      []analyzer.Engine  `json:"engines,omitempty"`
	Limitations  []string           `json:"limitations,omitempty"`
}

// Score directions.
const (
	// HigherIsBetter is the default for dimension scores: 0 = worst, 100 = best.
	HigherIsBetter = "higher-is-better"
	// HigherIsWorse is used by meters such as the AI Slop Score:
	// 0 = clean, 100 = worst.
	HigherIsWorse = "higher-is-worse"
)

// ScoreComponent is one group of evidence inside a composite score.
type ScoreComponent struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Points   float64 `json:"points"`   // penalty points contributed (after the group cap)
	Findings int     `json:"findings"` // findings in this group
	Assessed bool    `json:"assessed"` // false when no capability covering the group ran
	// FindingIDs lists the findings counted in this group (for drill-down).
	FindingIDs []string `json:"finding_ids,omitempty"`
}

// Score is one score. Dimension scores run 0 = worst, 100 = best; meters
// such as the AI Slop Score declare Direction "higher-is-worse". Rating is
// always from the reader's point of view (good = healthy / little slop).
type Score struct {
	ID           string                   `json:"id"`
	Name         string                   `json:"name"`
	Value        int                      `json:"value"`
	Rating       string                   `json:"rating"` // good, fair, poor
	Confidence   finding.Confidence       `json:"confidence"`
	Summary      string                   `json:"summary"`
	Counts       map[finding.Severity]int `json:"counts"`
	Capabilities []string                 `json:"capabilities"`
	// Basis says what was examined to produce the score (one line per
	// contributing capability), so a perfect score is never unexplained.
	Basis       []string `json:"basis,omitempty"`
	Methodology string   `json:"methodology"`
	// Direction is empty (= higher-is-better) for dimension scores.
	Direction string `json:"direction,omitempty"`
	// Label is a plain-language level, e.g. "Moderate slop".
	Label string `json:"label,omitempty"`
	// Components break a composite score down by evidence group.
	Components []ScoreComponent `json:"components,omitempty"`
}

// IsHigherWorse reports whether the score is a meter where 100 is worst.
func (s Score) IsHigherWorse() bool { return s.Direction == HigherIsWorse }

// Recommendation kinds.
const (
	RecRun     = "run"     // run another capability on the same target
	RecAccess  = "access"  // provide more access (a repository, a URL, ...)
	RecNetwork = "network" // re-run online to unlock a capability
)

// Recommendation is an evidence-based next step ("What else can we tell you?").
type Recommendation struct {
	Kind       string `json:"kind"`
	Capability string `json:"capability,omitempty"`
	Title      string `json:"title"`
	Reason     string `json:"reason"`
	Runnable   bool   `json:"runnable"`
	Priority   int    `json:"priority"`
}

// ArtifactRef points at a file produced by a capability.
type ArtifactRef struct {
	Name       string `json:"name"`
	Capability string `json:"capability"`
	MediaType  string `json:"media_type"`
	Path       string `json:"path,omitempty"`
	Bytes      int    `json:"bytes"`
}

// DataBoundary states what left the machine during the scan.
type DataBoundary struct {
	LeftMachine bool            `json:"left_machine"`
	AIUsed      bool            `json:"ai_used"`
	Calls       []netguard.Call `json:"calls,omitempty"`
	Disclosures []Disclosure    `json:"disclosures,omitempty"`
	Statement   string          `json:"statement"`
}

// Disclosure repeats a capability's privacy statement when it used the network.
type Disclosure struct {
	Capability string `json:"capability"`
	Statement  string `json:"statement"`
}

// Summary is the headline view.
type Summary struct {
	Headline    string                   `json:"headline"`
	Counts      map[finding.Severity]int `json:"counts"`
	TopFindings []string                 `json:"top_findings,omitempty"`
}

// Report is the unified Source Intelligence report.
type Report struct {
	SchemaVersion   string                     `json:"schema_version"`
	Tool            Tool                       `json:"tool"`
	Scan            Scan                       `json:"scan"`
	Summary         Summary                    `json:"summary"`
	Scores          []Score                    `json:"scores"`
	Findings        []finding.Finding          `json:"findings"`
	Facts           map[string]json.RawMessage `json:"facts"`
	Capabilities    []CapabilityRun            `json:"capabilities"`
	Recommendations []Recommendation           `json:"recommendations"`
	Artifacts       []ArtifactRef              `json:"artifacts,omitempty"`
	DataBoundary    DataBoundary               `json:"data_boundary"`
	Limitations     []string                   `json:"limitations,omitempty"`
}

// Fact decodes a fact from the report into out.
func (r *Report) Fact(key string, out any) bool {
	raw, ok := r.Facts[key]
	if !ok {
		return false
	}
	return json.Unmarshal(raw, out) == nil
}

// Capability returns the run record for id.
func (r *Report) Capability(id string) (CapabilityRun, bool) {
	for _, c := range r.Capabilities {
		if c.ID == id {
			return c, true
		}
	}
	return CapabilityRun{}, false
}

// ApplyBaseline marks each finding as new or existing relative to base.
func (r *Report) ApplyBaseline(base *Report) {
	seen := make(map[string]bool, len(base.Findings))
	for _, f := range base.Findings {
		seen[f.ID] = true
	}
	for i := range r.Findings {
		if seen[r.Findings[i].ID] {
			r.Findings[i].BaselineState = finding.BaselineExisting
		} else {
			r.Findings[i].BaselineState = finding.BaselineNew
		}
	}
}

// Rating converts a 0-100 value to good/fair/poor.
func Rating(v int) string {
	switch {
	case v >= 80:
		return "good"
	case v >= 55:
		return "fair"
	default:
		return "poor"
	}
}
