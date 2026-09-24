// Package analyzer is the contract between capybari-core and every
// capability. An analyzer repository implements Analyzer and ships a
// capability.yaml describing it.
package analyzer

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/capybari-repo/capybari-core/finding"
)

// APIVersion is the Analyzer API major version implemented by this core.
// Analyzers declare the version they target in capability.yaml (core_api).
const APIVersion = "v0"

// Target is the resolved object under analysis.
type Target struct {
	Kind TargetKind `json:"kind"`
	// Input is what the user supplied (path, archive, repository URL or website URL).
	Input string `json:"input"`
	// Root is the local directory holding the source for repository targets.
	Root string `json:"-"`
	// URL is the website URL for website targets, or the origin of a cloned repository.
	URL string `json:"url,omitempty"`
	// Display is a short human-readable name.
	Display string `json:"display"`
}

// Host returns the hostname of a website target.
func (t Target) Host() string {
	u, err := url.Parse(t.URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// EvidenceReader gives analyzers read access to evidence published by other
// capabilities earlier in the scan.
type EvidenceReader interface {
	// Get decodes the evidence stored under key into out. It reports false
	// when no evidence exists for key.
	Get(key string, out any) (bool, error)
	Has(key string) bool
}

// Options are free-form scan options (e.g. "active" for owner-authorised
// active probes). Values are strings; helpers parse them.
type Options map[string]string

// Bool returns the boolean value of an option, false when absent or invalid.
func (o Options) Bool(key string) bool {
	v, err := strconv.ParseBool(o[key])
	return err == nil && v
}

// Well-known option keys.
const (
	OptionActive   = "active"   // allow active (owner-authorised) website probes
	OptionQuestion = "question" // the user's optional "What do you want to know?"
)

// Input is everything an analyzer receives for one run.
type Input struct {
	Target   Target
	Evidence EvidenceReader
	// HTTP is a client restricted to the capability's declared hosts. It is
	// nil when the capability declares no network use or the scan is offline.
	HTTP    *http.Client
	Options Options
	Log     *slog.Logger
	Now     func() time.Time
}

// Artifact is a file produced by a capability (e.g. an SBOM).
type Artifact struct {
	Name      string `json:"name"`
	MediaType string `json:"media_type"`
	Data      []byte `json:"-"`
}

// Result is what an analyzer returns.
type Result struct {
	Findings []finding.Finding
	// Evidence is published under the keys declared in Capability.Provides
	// and becomes available to later capabilities and to the report.
	Evidence  map[string]any
	Artifacts []Artifact
	// Summary is a one-line, plain-language description of what was found.
	Summary string
	// Limitations lists what this run could not see or assess.
	Limitations []string
}

// Analyzer is implemented by every capability.
type Analyzer interface {
	Capability() Capability
	Analyze(ctx context.Context, in *Input) (*Result, error)
}

// Applicable may be implemented to decline a run after dependencies have
// produced evidence (e.g. "no lockfiles found"). The reason is shown to users.
type Applicable interface {
	Applies(in *Input) (ok bool, reason string)
}
