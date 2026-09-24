package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
)

// Formats supported by Write.
var Formats = []string{"json", "md", "html", "sarif"}

// Extension returns the file extension for a format.
func Extension(format string) string {
	switch format {
	case "md":
		return ".md"
	case "html":
		return ".html"
	case "sarif":
		return ".sarif"
	}
	return ".json"
}

// Write renders the report in the given format.
func Write(w io.Writer, r *Report, format string) error {
	switch format {
	case "json":
		return WriteJSON(w, r)
	case "md", "markdown":
		return WriteMarkdown(w, r)
	case "html":
		return WriteHTML(w, r)
	case "sarif":
		return WriteSARIF(w, r)
	}
	return fmt.Errorf("unknown format %q (want %s)", format, strings.Join(Formats, ", "))
}

// WriteJSON writes the canonical JSON report.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// Read decodes a JSON report.
func Read(rd io.Reader) (*Report, error) {
	var r Report
	if err := json.NewDecoder(rd).Decode(&r); err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	return &r, nil
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "\r", "").Replace(s)
}

func location(e finding.Evidence) string {
	switch {
	case e.Path != "" && e.StartLine > 0:
		return fmt.Sprintf("%s:%d", e.Path, e.StartLine)
	case e.Path != "":
		return e.Path
	case e.URL != "":
		return e.URL
	}
	return ""
}

// WriteMarkdown writes a human-readable Markdown report.
func WriteMarkdown(w io.Writer, r *Report) error {
	b := &strings.Builder{}
	p := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }

	p("# Software X-Ray: %s\n\n", r.Scan.Target.Display)
	p("> %s\n\n", r.Summary.Headline)
	p("- **Target:** %s (`%s`)\n", r.Scan.Target.Kind, r.Scan.Target.Input)
	p("- **Scan:** `%s` · %s · %.1fs\n", r.Scan.ID, r.Scan.FinishedAt.Format("2006-01-02 15:04 MST"), float64(r.Scan.DurationMS)/1000)
	p("- **Tool:** %s %s\n", r.Tool.Name, r.Tool.Version)
	mode := "online"
	if r.Scan.Mode.Offline {
		mode = "offline"
	}
	p("- **Mode:** %s", mode)
	if r.Scan.Mode.Active {
		p(", active probes enabled")
	}
	p("\n\n")

	if len(r.Scores) > 0 {
		p("## Scores\n\n_All scores: 0 = worst, 100 = best._\n\n| Dimension | Score | Rating | Confidence | Summary |\n|---|---:|---|---|---|\n")
		for _, s := range r.Scores {
			p("| %s | **%d** | %s | %s | %s |\n", s.Name, s.Value, s.Rating, s.Confidence, mdEscape(s.Summary))
		}
		p("\n")
	}

	writeIdentity(b, r)

	p("## Findings\n\n")
	c := r.Summary.Counts
	p("Critical **%d** · High **%d** · Medium **%d** · Low **%d** · Info **%d**\n\n",
		c[finding.Critical], c[finding.High], c[finding.Medium], c[finding.Low], c[finding.Info])
	if len(r.Findings) == 0 {
		p("No findings.\n\n")
	} else {
		p("| Severity | Confidence | Dimension | Finding | Location | Capability |\n|---|---|---|---|---|---|\n")
		for _, f := range r.Findings {
			loc := ""
			if len(f.Evidence) > 0 {
				loc = "`" + mdEscape(location(f.Evidence[0])) + "`"
				if len(f.Evidence) > 1 {
					loc += fmt.Sprintf(" (+%d)", len(f.Evidence)-1)
				}
			}
			title := mdEscape(f.Title)
			if f.BaselineState == finding.BaselineNew {
				title = "🆕 " + title
			}
			p("| %s | %s | %s | %s | %s | %s |\n", f.Severity, f.Confidence, f.Dimension, title, loc, f.Source.Capability)
		}
		p("\n")
		p("### Details\n\n")
		for i, f := range r.Findings {
			if i >= 50 {
				p("_…and %d more findings. See the JSON report for the complete list._\n\n", len(r.Findings)-50)
				break
			}
			p("#### %s `%s`\n\n", mdEscape(f.Title), f.ID)
			p("**%s** severity · **%s** confidence · %s/%s · found by `%s`", f.Severity, f.Confidence, f.Dimension, f.Category, f.Source.Capability)
			if f.Source.Engine != "" {
				p(" (engine: %s)", f.Source.Engine)
			}
			p("\n\n")
			if f.Description != "" {
				p("%s\n\n", f.Description)
			}
			for j, e := range f.Evidence {
				if j >= 5 {
					p("- …%d more locations\n", len(f.Evidence)-5)
					break
				}
				line := "- " + location(e)
				if e.Detail != "" {
					line += " — " + e.Detail
				}
				p("%s\n", line)
				if e.Snippet != "" {
					p("  ```\n  %s\n  ```\n", strings.ReplaceAll(e.Snippet, "\n", "\n  "))
				}
			}
			if f.Rule != nil {
				p("\n**Rule:** %s", f.Rule.ID)
				if len(f.Rule.References) > 0 {
					p(" — %s", strings.Join(f.Rule.References, ", "))
				}
				p("\n")
			}
			if f.Remediation != nil {
				p("\n**Remediation:** %s\n", f.Remediation.Summary)
			}
			if f.FalsePositiveGuidance != "" {
				p("\n_False positive?_ %s\n", f.FalsePositiveGuidance)
			}
			p("\n")
		}
	}

	if len(r.Recommendations) > 0 {
		p("## What else can we tell you?\n\n")
		for i, rec := range r.Recommendations {
			if i >= 5 {
				break
			}
			p("%d. **%s**: %s\n", i+1, rec.Title, rec.Reason)
		}
		p("\n")
	}

	p("## Capabilities run\n\n| Capability | Status | Findings | Time | Network | Notes |\n|---|---|---:|---:|---|---|\n")
	for _, cr := range r.Capabilities {
		notes := cr.Summary
		if cr.Reason != "" {
			notes = cr.Reason
		}
		if cr.Cached {
			notes = "(cached) " + notes
		}
		name := cr.Name
		if cr.Experimental {
			name += " _(experimental)_"
		}
		p("| %s `%s@%s` | %s | %d | %dms | %s | %s |\n", name, cr.ID, cr.Version, cr.Status, cr.Findings, cr.DurationMS, cr.Execution.Network, mdEscape(notes))
	}
	p("\n")

	if len(r.Artifacts) > 0 {
		p("## Artifacts\n\n")
		for _, a := range r.Artifacts {
			path := a.Name
			if a.Path != "" {
				path = a.Path
			}
			p("- `%s` (%s, %d bytes) from %s\n", path, a.MediaType, a.Bytes, a.Capability)
		}
		p("\n")
	}

	p("## Data boundary\n\n%s\n\n", r.DataBoundary.Statement)
	for _, c := range r.DataBoundary.Calls {
		p("- `%s` → %s %s ×%d", c.Capability, c.Method, c.Host, c.Count)
		if c.Blocked > 0 {
			p(" (%d blocked)", c.Blocked)
		}
		p("\n")
	}
	for _, d := range r.DataBoundary.Disclosures {
		p("- **%s:** %s\n", d.Capability, d.Statement)
	}
	p("\n")

	if len(r.Limitations) > 0 {
		p("## Limitations\n\n")
		for _, l := range r.Limitations {
			p("- %s\n", l)
		}
		p("\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeIdentity(b *strings.Builder, r *Report) {
	p := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	var fp facts.Fingerprint
	var inv facts.Inventory
	var tech facts.Technologies
	var deps facts.Dependencies
	var ws facts.WebSnapshot
	hasFP, hasInv, hasTech := r.Fact(facts.KeyFingerprint, &fp), r.Fact(facts.KeyInventory, &inv), r.Fact(facts.KeyTechnologies, &tech)
	hasDeps, hasWS := r.Fact(facts.KeyDependencies, &deps), r.Fact(facts.KeyWebSnapshot, &ws)
	if !hasFP && !hasInv && !hasTech && !hasDeps && !hasWS {
		return
	}
	p("## What is it?\n\n")
	if hasFP {
		p("- **Project type:** %s\n", strings.Join(fp.ProjectTypes, ", "))
		if fp.PrimaryLanguage != "" {
			p("- **Primary language:** %s\n", fp.PrimaryLanguage)
		}
		if len(fp.PackageManagers) > 0 {
			p("- **Package managers:** %s\n", strings.Join(fp.PackageManagers, ", "))
		}
		if len(fp.Runtimes) > 0 {
			var rs []string
			for _, rt := range fp.Runtimes {
				rs = append(rs, strings.TrimSpace(rt.Name+" "+rt.Version))
			}
			p("- **Runtimes:** %s\n", strings.Join(rs, ", "))
		}
		if len(fp.EntryPoints) > 0 {
			p("- **Entry points:** %s\n", strings.Join(capList(fp.EntryPoints, 8), ", "))
		}
		p("- **Tests:** %v · **CI:** %s · **Containers:** %v · **Docs:** %v\n", yes(fp.HasTests), orNone(fp.HasCI), yes(fp.HasContainers), yes(fp.HasDocs))
		if fp.Git != nil {
			p("- **History:** %d commits by %d contributors", fp.Git.Commits, fp.Git.Contributors)
			if !fp.Git.LastCommit.IsZero() {
				p(", last commit %s", fp.Git.LastCommit.Format("2006-01-02"))
			}
			p("\n")
		}
		p("- **Size:** %s · **Fingerprint:** `%s`\n", fp.Size, fp.Digest)
	}
	if hasInv {
		var langs []string
		for i, l := range inv.Languages {
			if i == 6 {
				break
			}
			langs = append(langs, fmt.Sprintf("%s %.0f%%", l.Language, l.Share*100))
		}
		p("- **Files:** %d (%d lines) · **Languages:** %s\n", inv.TotalFiles, inv.TotalLines, strings.Join(langs, ", "))
	}
	if hasWS {
		p("- **URL:** %s → %s (HTTP %d)\n", ws.RequestedURL, ws.FinalURL, ws.Status)
		if ws.Title != "" {
			p("- **Title:** %s\n", mdEscape(ws.Title))
		}
	}
	if hasTech && len(tech.Items) > 0 {
		items := append([]facts.Technology(nil), tech.Items...)
		sort.SliceStable(items, func(i, j int) bool { return items[i].Category < items[j].Category })
		var ts []string
		for _, t := range items {
			s := t.Name
			if t.Version != "" {
				s += " " + t.Version
			}
			ts = append(ts, s)
		}
		p("- **Technologies:** %s\n", strings.Join(capList(ts, 25), ", "))
	}
	if hasDeps {
		direct := 0
		for _, d := range deps.Packages {
			if d.Direct != nil && *d.Direct {
				direct++
			}
		}
		p("- **Dependencies:** %d packages from %d manifest(s)", len(deps.Packages), len(deps.Manifests))
		if direct > 0 {
			p(", %d direct", direct)
		}
		p("\n")
	}
	var arch facts.Architecture
	if r.Fact(facts.KeyArchitecture, &arch) && arch.Mermaid != "" {
		p("\n### Architecture\n\n```mermaid\n%s\n```\n", arch.Mermaid)
	}
	p("\n")
}

func capList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), fmt.Sprintf("+%d more", len(s)-n))
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}
