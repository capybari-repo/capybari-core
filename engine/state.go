package engine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/capybari/capybari-core/analyzer"
	"github.com/capybari/capybari-core/finding"
	"github.com/capybari/capybari-core/netguard"
	"github.com/capybari/capybari-core/report"
)

// StoredArtifact is an artifact with its content, as kept in scan state.
type StoredArtifact struct {
	Name      string `json:"name"`
	MediaType string `json:"media_type"`
	Data      []byte `json:"data"`
}

// RunRecord is the stored outcome of one capability.
type RunRecord struct {
	Run       report.CapabilityRun       `json:"run"`
	Findings  []finding.Finding          `json:"findings,omitempty"`
	Artifacts []StoredArtifact           `json:"artifacts,omitempty"`
	Evidence  map[string]json.RawMessage `json:"evidence,omitempty"`
}

// State is the persistent scan context. It is serialisable so hosted
// deployments can store it and later expand the same scan with more
// capabilities without re-running earlier work (Cross-Tool Intelligence,
// Section 6).
type State struct {
	mu        sync.RWMutex
	ScanID    string                     `json:"scan_id"`
	Target    analyzer.Target            `json:"target"`
	StartedAt time.Time                  `json:"started_at"`
	UpdatedAt time.Time                  `json:"updated_at"`
	Options   analyzer.Options           `json:"options,omitempty"`
	Evidence  map[string]json.RawMessage `json:"evidence"`
	Runs      map[string]*RunRecord      `json:"runs"`
	Calls     []netguard.Call            `json:"calls,omitempty"`
	Mode      report.Mode                `json:"mode"`
}

// NewState creates an empty scan context for a target.
func NewState(t analyzer.Target, now time.Time) *State {
	return &State{
		ScanID:    NewScanID(),
		Target:    t,
		StartedAt: now,
		UpdatedAt: now,
		Evidence:  map[string]json.RawMessage{},
		Runs:      map[string]*RunRecord{},
	}
}

// NewScanID returns a random scan identifier.
func NewScanID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "scn_" + hex.EncodeToString(b[:])
}

// Get implements analyzer.EvidenceReader.
func (s *State) Get(key string, out any) (bool, error) {
	s.mu.RLock()
	raw, ok := s.Evidence[key]
	s.mu.RUnlock()
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(raw, out)
}

// Has implements analyzer.EvidenceReader.
func (s *State) Has(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.Evidence[key]
	return ok
}

func (s *State) evidenceRaw(key string) (json.RawMessage, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	raw, ok := s.Evidence[key]
	return raw, ok
}

func (s *State) record(id string, rec *RunRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Runs[id] = rec
	for k, v := range rec.Evidence {
		s.Evidence[k] = v
	}
}

func (s *State) run(id string) (*RunRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.Runs[id]
	return r, ok
}

func (s *State) mergeCalls(calls []netguard.Call) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := map[string]int{}
	for i, c := range s.Calls {
		idx[c.Capability+"\x00"+c.Host+"\x00"+c.Method] = i
	}
	for _, c := range calls {
		k := c.Capability + "\x00" + c.Host + "\x00" + c.Method
		if i, ok := idx[k]; ok {
			s.Calls[i].Count += c.Count
			s.Calls[i].Blocked += c.Blocked
			continue
		}
		idx[k] = len(s.Calls)
		s.Calls = append(s.Calls, c)
	}
}

// MarshalJSON serialises the state under its lock.
func (s *State) MarshalJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	type alias State
	return json.Marshal((*alias)(s))
}
