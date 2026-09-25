package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
)

//go:embed report.html.tmpl
var htmlTemplate string

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"loc":      location,
	"sevcount": func(m map[finding.Severity]int, s string) int { return m[finding.Severity(s)] },
	"join":     strings.Join,
	"pct":      func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) },
	"seconds":  func(ms int64) string { return fmt.Sprintf("%.1fs", float64(ms)/1000) },
	"add":      func(a, b int) int { return a + b },
	"top":      func(n int, rs []Recommendation) []Recommendation { return rs[:min(n, len(rs))] },
	"mark":     reasonMark,
	"impact":   ImpactLabel,
}).Parse(htmlTemplate))

type htmlView struct {
	*Report
	Fingerprint  *facts.Fingerprint
	Inventory    *facts.Inventory
	Technologies *facts.Technologies
	Dependencies *facts.Dependencies
	Web          *facts.WebSnapshot
	Architecture *facts.Architecture
	DirectDeps   int
	DimAnchor    map[string]string // finding ID -> dimension, first finding per dimension
}

// WriteHTML writes a single self-contained HTML report (no external assets).
func WriteHTML(w io.Writer, r *Report) error {
	v := htmlView{Report: r, DimAnchor: map[string]string{}}
	seenDim := map[string]bool{}
	for _, f := range r.Findings {
		if !seenDim[f.Dimension] {
			seenDim[f.Dimension] = true
			v.DimAnchor[f.ID] = f.Dimension
		}
	}
	var fp facts.Fingerprint
	if r.Fact(facts.KeyFingerprint, &fp) {
		v.Fingerprint = &fp
	}
	var inv facts.Inventory
	if r.Fact(facts.KeyInventory, &inv) {
		v.Inventory = &inv
	}
	var tech facts.Technologies
	if r.Fact(facts.KeyTechnologies, &tech) && len(tech.Items) > 0 {
		v.Technologies = &tech
	}
	var deps facts.Dependencies
	if r.Fact(facts.KeyDependencies, &deps) {
		v.Dependencies = &deps
		for _, p := range deps.Packages {
			if p.Direct != nil && *p.Direct {
				v.DirectDeps++
			}
		}
	}
	var ws facts.WebSnapshot
	if r.Fact(facts.KeyWebSnapshot, &ws) {
		v.Web = &ws
	}
	var arch facts.Architecture
	if r.Fact(facts.KeyArchitecture, &arch) && len(arch.Nodes) > 0 {
		v.Architecture = &arch
	}
	return htmlTmpl.Execute(w, v)
}
