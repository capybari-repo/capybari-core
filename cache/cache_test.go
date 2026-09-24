package cache

import (
	"path/filepath"
	"testing"

	"github.com/capybari-repo/capybari-core/engine"
	"github.com/capybari-repo/capybari-core/report"
)

func TestRoundTrip(t *testing.T) {
	c, err := Open(filepath.Join(t.TempDir(), "c.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, ok := c.Get("k"); ok {
		t.Fatal("unexpected hit")
	}
	rec := &engine.RunRecord{Run: report.CapabilityRun{ID: "a", Summary: "s"}, Artifacts: []engine.StoredArtifact{{Name: "x", Data: []byte{1, 2}}}}
	if err := c.Put("k", rec); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get("k")
	if !ok || got.Run.Summary != "s" || len(got.Artifacts[0].Data) != 2 {
		t.Fatalf("got %+v", got)
	}
	if err := c.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("k"); ok {
		t.Fatal("clear failed")
	}
}
