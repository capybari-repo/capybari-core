// Package finding defines the common finding schema shared by every
// Capybari Source Intelligence capability (Master Plan, Section 10).
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity of a finding. Ordered from most to least severe.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Severities lists all severities from most to least severe.
var Severities = []Severity{Critical, High, Medium, Low, Info}

// Rank returns a sortable rank: higher is more severe. Unknown severities rank 0.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	}
	return 0
}

// ParseSeverity parses a severity name case-insensitively.
func ParseSeverity(s string) (Severity, error) {
	v := Severity(strings.ToLower(strings.TrimSpace(s)))
	if v.Rank() == 0 {
		return "", fmt.Errorf("unknown severity %q (want critical, high, medium, low or info)", s)
	}
	return v, nil
}

// Confidence expresses how certain the analyzer is that the finding is real.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Weight converts confidence into a multiplier used by score aggregation.
func (c Confidence) Weight() float64 {
	switch c {
	case ConfidenceHigh:
		return 1.0
	case ConfidenceMedium:
		return 0.7
	case ConfidenceLow:
		return 0.4
	}
	return 0.7
}

// Dimensions of the Source Intelligence Model (Master Plan, Section 5), plus
// the website-specific "ai-signals" dimension.
const (
	DimIdentity        = "identity"
	DimStructure       = "structure"
	DimDependencies    = "dependencies"
	DimSecurity        = "security"
	DimChangeRisk      = "change-risk"
	DimMaintainability = "maintainability"
	DimData            = "data"
	DimInterfaces      = "interfaces"
	DimOperability     = "operability"
	DimEvolution       = "evolution"
	DimAISignals       = "ai-signals"
	DimTrust           = "trust"
)

// Dimensions lists every known dimension.
var Dimensions = []string{
	DimIdentity, DimStructure, DimDependencies, DimSecurity, DimChangeRisk,
	DimMaintainability, DimData, DimInterfaces, DimOperability, DimEvolution, DimAISignals,
}

// Location points at the place a finding was observed.
type Location struct {
	Path      string `json:"path,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Symbol    string `json:"symbol,omitempty"`
	URL       string `json:"url,omitempty"`
}

// Evidence is one concrete observation supporting a finding.
type Evidence struct {
	Location
	// Snippet is the relevant excerpt. Analyzers must redact secrets.
	Snippet string `json:"snippet,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Source identifies which capability (and underlying engine) produced a finding.
type Source struct {
	Capability    string `json:"capability"`
	Version       string `json:"version"`
	Engine        string `json:"engine,omitempty"`
	EngineVersion string `json:"engine_version,omitempty"`
}

// Rule references the rule, advisory or standard behind a finding.
type Rule struct {
	ID         string   `json:"id"`
	Name       string   `json:"name,omitempty"`
	References []string `json:"references,omitempty"`
}

// Impact describes technical and business consequences.
type Impact struct {
	Technical string `json:"technical,omitempty"`
	Business  string `json:"business,omitempty"`
	// Buyer says what the finding means to someone deciding whether to
	// trust, use or pay for the product (see the Buyer* constants). The
	// engine sets it when the analyzer did not.
	Buyer string `json:"buyer,omitempty"`
}

// Buyer impact levels.
const (
	// BuyerBlocks: a reason not to trust the product with data, money or an
	// account until it is fixed (no HTTPS, leaked keys, vulnerable code).
	BuyerBlocks = "blocks-purchase"
	// BuyerSupportCost: the product works but will cost its users time or
	// money (missing contact or refund path, end-of-life stack, no tests).
	BuyerSupportCost = "support-cost"
	// BuyerCosmetic: owner homework that does not change a buyer's decision
	// (a missing security header, version disclosure).
	BuyerCosmetic = "cosmetic"
)

// Remediation describes what to do about a finding.
type Remediation struct {
	Summary     string   `json:"summary"`
	Automatable bool     `json:"automatable"`
	References  []string `json:"references,omitempty"`
}

// BaselineState is set when a report is compared against a baseline.
type BaselineState string

const (
	BaselineNew      BaselineState = "new"
	BaselineExisting BaselineState = "existing"
)

// Finding is the common finding model. See capybari-schemas/finding.schema.json.
type Finding struct {
	ID                    string        `json:"id"`
	Dimension             string        `json:"dimension"`
	Category              string        `json:"category"`
	Title                 string        `json:"title"`
	Description           string        `json:"description,omitempty"`
	Severity              Severity      `json:"severity"`
	Confidence            Confidence    `json:"confidence"`
	Evidence              []Evidence    `json:"evidence,omitempty"`
	Source                Source        `json:"source"`
	Rule                  *Rule         `json:"rule,omitempty"`
	Component             string        `json:"component,omitempty"`
	Related               []string      `json:"related,omitempty"`
	Impact                *Impact       `json:"impact,omitempty"`
	Remediation           *Remediation  `json:"remediation,omitempty"`
	FalsePositiveGuidance string        `json:"false_positive_guidance,omitempty"`
	Tags                  []string      `json:"tags,omitempty"`
	DetectedAt            time.Time     `json:"detected_at"`
	BaselineState         BaselineState `json:"baseline_state,omitempty"`
}

// ComputeID returns a stable identifier. It deliberately ignores line numbers
// when a snippet or symbol is present so the ID survives unrelated edits,
// which keeps baselines stable.
func (f *Finding) ComputeID() string {
	h := sha256.New()
	write := func(s string) { h.Write([]byte(s)); h.Write([]byte{0}) }
	write(f.Source.Capability)
	write(f.Category)
	if f.Rule != nil {
		write(f.Rule.ID)
	}
	write(f.Component)
	for _, e := range f.Evidence {
		write(e.Path)
		write(e.URL)
		switch {
		case e.Symbol != "":
			write(e.Symbol)
		case e.Snippet != "":
			write(strings.Join(strings.Fields(e.Snippet), " "))
		default:
			write(fmt.Sprint(e.StartLine))
		}
	}
	if len(f.Evidence) == 0 {
		write(f.Title)
	}
	return "CSI-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// Sort orders findings by severity (desc), confidence, dimension, title and ID.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Confidence.Weight() != b.Confidence.Weight() {
			return a.Confidence.Weight() > b.Confidence.Weight()
		}
		if a.Dimension != b.Dimension {
			return a.Dimension < b.Dimension
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return a.ID < b.ID
	})
}

// Counts tallies findings per severity.
func Counts(fs []Finding) map[Severity]int {
	m := make(map[Severity]int, len(Severities))
	for _, s := range Severities {
		m[s] = 0
	}
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}

// Redact masks the middle of a secret-like value, keeping a short prefix so
// a human can recognise which credential it was.
func Redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	keep := 4
	return s[:keep] + strings.Repeat("*", min(len(s)-keep, 16))
}
