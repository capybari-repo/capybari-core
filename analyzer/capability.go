package analyzer

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"gopkg.in/yaml.v3"
)

// TargetKind is the kind of object a scan inspects.
type TargetKind string

const (
	TargetRepository TargetKind = "repository"
	TargetWebsite    TargetKind = "website"
)

// Requirement expresses whether a capability needs network access or AI.
type Requirement string

const (
	RequireNone     Requirement = "none"
	RequireOptional Requirement = "optional"
	RequireRequired Requirement = "required"
)

// Stability of a capability.
const (
	StabilityStable       = "stable"
	StabilityExperimental = "experimental"
)

// Cost classes used by the orchestrator to run cheap, high-signal work first.
const (
	CostLow    = "low"
	CostMedium = "medium"
	CostHigh   = "high"
)

// TargetHost is the placeholder in Execution.NetworkHosts meaning "the host
// of the website being scanned".
const TargetHost = "$target"

// Execution declares where and how a capability runs (Execution Strategy,
// Section 2: AI and Network Independence Matrix).
type Execution struct {
	Local   bool        `yaml:"local" json:"local"`
	Network Requirement `yaml:"network" json:"network"`
	AI      Requirement `yaml:"ai" json:"ai"`
	// NetworkHosts is the allow-list of hosts the capability may contact.
	// The engine enforces it. Use "$target" for the scanned website.
	NetworkHosts []string `yaml:"network_hosts,omitempty" json:"network_hosts,omitempty"`
}

// Engine credits a reused open-source component.
type Engine struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
	License string `yaml:"license" json:"license"`
	URL     string `yaml:"url,omitempty" json:"url,omitempty"`
}

// Condition decides when a follow-up recommendation applies. Any matching
// clause satisfies the condition; an empty condition always matches.
type Condition struct {
	FindingCategories []string `yaml:"finding_categories,omitempty" json:"finding_categories,omitempty"`
	Technologies      []string `yaml:"technologies,omitempty" json:"technologies,omitempty"`
	Evidence          []string `yaml:"evidence,omitempty" json:"evidence,omitempty"`
}

// Empty reports whether the condition has no clauses.
func (c Condition) Empty() bool {
	return len(c.FindingCategories) == 0 && len(c.Technologies) == 0 && len(c.Evidence) == 0
}

// FollowUp is an evidence-based transition to another capability
// (Cross-Tool Intelligence, Section 7).
type FollowUp struct {
	Capability string    `yaml:"capability" json:"capability"`
	Reason     string    `yaml:"reason" json:"reason"`
	When       Condition `yaml:"when,omitempty" json:"when,omitempty"`
}

// Capability is the registry metadata every analyzer declares in its
// capability.yaml (Unified Agent, Section 9).
type Capability struct {
	ID          string       `yaml:"id" json:"id"`
	Name        string       `yaml:"name" json:"name"`
	Version     string       `yaml:"version" json:"version"`
	Category    string       `yaml:"category" json:"category"`
	Summary     string       `yaml:"summary" json:"summary"`
	Stability   string       `yaml:"stability" json:"stability"`
	CoreAPI     string       `yaml:"core_api" json:"core_api"`
	Targets     []TargetKind `yaml:"targets" json:"targets"`
	Requires    []string     `yaml:"requires,omitempty" json:"requires,omitempty"`
	Optional    []string     `yaml:"optional,omitempty" json:"optional,omitempty"`
	Provides    []string     `yaml:"provides,omitempty" json:"provides,omitempty"`
	Findings    []string     `yaml:"findings,omitempty" json:"findings,omitempty"`
	Scores      []string     `yaml:"scores,omitempty" json:"scores,omitempty"`
	Cost        string       `yaml:"cost" json:"cost"`
	Execution   Execution    `yaml:"execution" json:"execution"`
	Privacy     string       `yaml:"privacy" json:"privacy"`
	Engines     []Engine     `yaml:"engines,omitempty" json:"engines,omitempty"`
	FollowUps   []FollowUp   `yaml:"follow_ups,omitempty" json:"follow_ups,omitempty"`
	Methodology string       `yaml:"methodology,omitempty" json:"methodology,omitempty"`
}

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
var semverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// Experimental reports whether the capability is explicitly experimental.
func (c Capability) Experimental() bool { return c.Stability == StabilityExperimental }

// Supports reports whether the capability accepts the given target kind.
func (c Capability) Supports(k TargetKind) bool { return slices.Contains(c.Targets, k) }

// Validate checks the metadata for completeness and consistency.
func (c Capability) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !idPattern.MatchString(c.ID) {
		bad("id %q must be lowercase kebab-case", c.ID)
	}
	if c.Name == "" {
		bad("name is required")
	}
	if !semverPattern.MatchString(c.Version) {
		bad("version %q must be semantic (x.y.z)", c.Version)
	}
	if c.Summary == "" {
		bad("summary is required")
	}
	if c.Stability != StabilityStable && c.Stability != StabilityExperimental {
		bad("stability must be %q or %q", StabilityStable, StabilityExperimental)
	}
	if c.CoreAPI == "" {
		bad("core_api is required (the capybari-core Analyzer API major version, e.g. \"v0\")")
	}
	if len(c.Targets) == 0 {
		bad("at least one target is required")
	}
	for _, t := range c.Targets {
		if t != TargetRepository && t != TargetWebsite {
			bad("unknown target %q", t)
		}
	}
	if !slices.Contains([]string{CostLow, CostMedium, CostHigh}, c.Cost) {
		bad("cost must be low, medium or high")
	}
	for _, r := range []Requirement{c.Execution.Network, c.Execution.AI} {
		if r != RequireNone && r != RequireOptional && r != RequireRequired {
			bad("execution requirement %q must be none, optional or required", r)
		}
	}
	if c.Execution.Network == RequireNone && len(c.Execution.NetworkHosts) > 0 {
		bad("network_hosts declared but network is none")
	}
	if c.Execution.Network != RequireNone && len(c.Execution.NetworkHosts) == 0 {
		bad("network use declared but no network_hosts allow-list")
	}
	if c.Privacy == "" {
		bad("privacy statement is required")
	}
	for _, e := range c.Engines {
		if e.Name == "" || e.License == "" {
			bad("engines need a name and a license")
		}
	}
	for _, f := range c.FollowUps {
		if f.Capability == "" || f.Reason == "" {
			bad("follow_ups need a capability and a reason")
		}
	}
	return errors.Join(errs...)
}

// ParseCapability decodes and validates capability.yaml content.
func ParseCapability(b []byte) (Capability, error) {
	var c Capability
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("capability.yaml: %w", err)
	}
	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("capability %q: %w", c.ID, err)
	}
	return c, nil
}

// MustParseCapability is ParseCapability for embedded metadata; it panics on
// invalid metadata, which is a programming error caught by tests.
func MustParseCapability(b []byte) Capability {
	c, err := ParseCapability(b)
	if err != nil {
		panic(err)
	}
	return c
}
