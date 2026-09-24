// Package analyzertest helps analyzer repositories test capabilities
// through the real engine pipeline and compare output with golden files.
package analyzertest

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/capybari/capybari-core/analyzer"
	"github.com/capybari/capybari-core/builtin"
	"github.com/capybari/capybari-core/engine"
	"github.com/capybari/capybari-core/report"
)

var update = flag.Bool("update", false, "rewrite golden files")

// FixedTime is the clock used by Run so outputs are reproducible.
var FixedTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Options configure Run.
type Options struct {
	// Deps are capabilities that provide evidence the analyzer needs.
	Deps []analyzer.Analyzer
	// Offline forbids network access (default true for determinism).
	Online  bool
	Options analyzer.Options
}

// Repo returns a repository target rooted at dir.
func Repo(t testing.TB, dir string) analyzer.Target {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	return analyzer.Target{Kind: analyzer.TargetRepository, Input: dir, Root: abs, Display: filepath.Base(abs)}
}

// Website returns a website target.
func Website(u string) analyzer.Target {
	return analyzer.Target{Kind: analyzer.TargetWebsite, Input: u, URL: u, Display: u}
}

// Run executes a (plus its dependencies) through the engine and returns
// the report. It fails the test if a did not run successfully.
func Run(t testing.TB, a analyzer.Analyzer, target analyzer.Target, o Options) *report.Report {
	t.Helper()
	r, _ := RunState(t, a, target, o)
	return r
}

// RunState is Run that also returns the scan state, whose evidence is not
// stripped for the report (e.g. the inventory file list).
func RunState(t testing.TB, a analyzer.Analyzer, target analyzer.Target, o Options) (*report.Report, *engine.State) {
	t.Helper()
	reg := engine.NewRegistry()
	all := []analyzer.Analyzer{a}
	for _, b := range builtin.All() {
		if b.Capability().ID != a.Capability().ID {
			all = append(all, b)
		}
	}
	if err := reg.Register(append(all, o.Deps...)...); err != nil {
		t.Fatal(err)
	}
	e := engine.New(engine.Config{
		Registry: reg,
		Tool:     report.Tool{Name: "capybari-test", Version: "0.0.0-test"},
		Offline:  !o.Online,
		Now:      func() time.Time { return FixedTime },
	})
	r, st, err := e.Analyze(context.Background(), target, engine.Selection{Only: []string{a.Capability().ID}}, o.Options)
	if err != nil {
		t.Fatal(err)
	}
	run, ok := r.Capability(a.Capability().ID)
	if !ok {
		t.Fatalf("capability %s did not run", a.Capability().ID)
	}
	if run.Status != report.StatusOK {
		t.Fatalf("capability %s: %s (%s)", run.ID, run.Status, run.Reason)
	}
	return r, st
}

// Golden compares v (encoded as indented JSON) with testdata/<name>.golden.json.
// Run tests with -update to rewrite the file.
func Golden(t testing.TB, name string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", name+".golden.json")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden file (run `go test ./... -update` to create it): %v", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs from golden file; run `go test ./... -update` and review the diff.\n--- got ---\n%s", path, got)
	}
}

// Fact decodes evidence key from a report.
func Fact[T any](t testing.TB, r *report.Report, key string) T {
	t.Helper()
	var v T
	if !r.Fact(key, &v) {
		t.Fatalf("report has no %q fact", key)
	}
	return v
}
