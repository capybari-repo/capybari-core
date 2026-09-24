// Package engine is the Source Intelligence orchestrator: it holds the
// capability registry, plans which capabilities apply to a target, runs them
// (cheap and high-signal first, in parallel where possible), and turns the
// results into one unified report.
package engine

import (
	"fmt"
	"sort"

	"github.com/capybari-repo/capybari-core/analyzer"
)

// Registry is the formal capability registry (Unified Agent, Section 9).
type Registry struct {
	byID map[string]analyzer.Analyzer
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{byID: map[string]analyzer.Analyzer{}} }

// Register adds analyzers after validating their metadata.
func (r *Registry) Register(as ...analyzer.Analyzer) error {
	for _, a := range as {
		c := a.Capability()
		if err := c.Validate(); err != nil {
			return fmt.Errorf("register %q: %w", c.ID, err)
		}
		if c.CoreAPI != analyzer.APIVersion {
			return fmt.Errorf("register %q: targets core API %s, this core implements %s", c.ID, c.CoreAPI, analyzer.APIVersion)
		}
		if _, dup := r.byID[c.ID]; dup {
			return fmt.Errorf("register %q: capability already registered", c.ID)
		}
		r.byID[c.ID] = a
	}
	return nil
}

// MustRegister is Register that panics; for static wiring in main packages.
func (r *Registry) MustRegister(as ...analyzer.Analyzer) *Registry {
	if err := r.Register(as...); err != nil {
		panic(err)
	}
	return r
}

// Get returns the analyzer for id.
func (r *Registry) Get(id string) (analyzer.Analyzer, bool) {
	a, ok := r.byID[id]
	return a, ok
}

// All returns every analyzer ordered by capability ID.
func (r *Registry) All() []analyzer.Analyzer {
	out := make([]analyzer.Analyzer, 0, len(r.byID))
	for _, a := range r.byID {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Capability().ID < out[j].Capability().ID })
	return out
}

// Capabilities returns all capability metadata ordered by ID.
func (r *Registry) Capabilities() []analyzer.Capability {
	all := r.All()
	out := make([]analyzer.Capability, len(all))
	for i, a := range all {
		out[i] = a.Capability()
	}
	return out
}

// providers returns capability IDs providing an evidence key for a target kind.
func (r *Registry) providers(key string, kind analyzer.TargetKind) []string {
	var ids []string
	for id, a := range r.byID {
		c := a.Capability()
		if !c.Supports(kind) {
			continue
		}
		for _, p := range c.Provides {
			if p == key {
				ids = append(ids, id)
				break
			}
		}
	}
	sort.Strings(ids)
	return ids
}
