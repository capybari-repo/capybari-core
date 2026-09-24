// Package standalone lets every analyzer repository ship a small binary
// that runs its capability on its own (cmd/capybari-<id>). The full
// experience is the unified `capybari` CLI; standalone binaries exist so a
// single capability can be tried, tested and embedded in isolation.
package standalone

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/capybari/capybari-core/analyzer"
	"github.com/capybari/capybari-core/builtin"
	"github.com/capybari/capybari-core/engine"
	"github.com/capybari/capybari-core/report"
	"github.com/capybari/capybari-core/target"
)

// Main runs the primary analyzer (plus any analyzers it depends on) against
// the target given on the command line and exits.
func Main(version string, primary analyzer.Analyzer, deps ...analyzer.Analyzer) {
	os.Exit(Run(os.Args[1:], os.Stdout, os.Stderr, version, primary, deps...))
}

// Run is Main without the process exit, for tests.
func Run(args []string, stdout, stderr io.Writer, version string, primary analyzer.Analyzer, deps ...analyzer.Analyzer) int {
	c := primary.Capability()
	fs := flag.NewFlagSet("capybari-"+c.ID, flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "md", "output format: json, md, html or sarif")
	out := fs.String("o", "", "write the report to this file instead of stdout")
	offline := fs.Bool("offline", false, "forbid all network access")
	as := fs.String("as", "", "force the target kind: repository or website")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "capybari-%s %s: %s\n\nUsage: capybari-%s [flags] <folder | archive | repository URL | website URL>\n\n", c.ID, version, c.Summary, c.ID)
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nThis runs one capability. For the full Software X-Ray use the unified CLI: https://github.com/capybari/capybari-cli\n")
	}
	// Accept flags before or after the target, like the unified CLI.
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) != 1 {
		fs.Usage()
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	res, err := target.Resolve(ctx, pos[0], target.Options{As: analyzer.TargetKind(*as), AllowClone: true})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	defer res.Cleanup()

	reg := engine.NewRegistry()
	all := append([]analyzer.Analyzer{primary}, deps...)
	for _, b := range builtin.All() {
		if b.Capability().ID != c.ID {
			all = append(all, b)
		}
	}
	if err := reg.Register(all...); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	e := engine.New(engine.Config{Registry: reg, Tool: report.Tool{Name: "capybari-" + c.ID, Version: version}, Offline: *offline})
	r, _, err := e.Analyze(ctx, res.Target, engine.Selection{Only: []string{c.ID}}, nil)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	w := stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		defer f.Close()
		w = f
	}
	if err := report.Write(w, r, *format); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if run, ok := r.Capability(c.ID); ok && run.Status == report.StatusFailed {
		fmt.Fprintf(stderr, "capability failed: %s\n", run.Reason)
		return 1
	}
	return 0
}
