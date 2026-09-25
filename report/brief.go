package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/capybari-repo/capybari-core/finding"
)

// ImpactLabel is the reader-facing name of a buyer impact.
func ImpactLabel(buyer string) string {
	switch buyer {
	case finding.BuyerBlocks:
		return "Blocks purchase"
	case finding.BuyerSupportCost:
		return "Raises support cost"
	case finding.BuyerCosmetic:
		return "Cosmetic / owner homework"
	}
	return ""
}

func reasonMark(rs VerdictReason) string {
	switch {
	case rs.Kind == "positive":
		return "✓"
	case rs.Impact == finding.BuyerBlocks:
		return "⛔"
	case rs.Impact == finding.BuyerSupportCost:
		return "⚠"
	}
	return "·"
}

// Axis returns the verdict axis with the given ID.
func (v *Verdict) Axis(id string) (VerdictAxis, bool) {
	for _, a := range v.Axes {
		if a.ID == id {
			return a, true
		}
	}
	return VerdictAxis{}, false
}

// writeVerdict renders the verdict block in Markdown, with at most n
// reasons per axis (0 = all).
func writeVerdict(b *strings.Builder, v *Verdict, n int) {
	for _, a := range v.Axes {
		fmt.Fprintf(b, "**%s: %s** — _%s_\n\n", a.Name, a.Label, a.Question)
		for i, rs := range a.Reasons {
			if n > 0 && i >= n {
				break
			}
			fmt.Fprintf(b, "- %s %s\n", reasonMark(rs), mdEscape(rs.Text))
		}
		if len(a.Reasons) > 0 {
			b.WriteString("\n")
		}
	}
	fmt.Fprintf(b, "Findings for buyers: **%d** block purchase · **%d** raise support cost · **%d** cosmetic (owner homework)\n\n",
		v.Impact[finding.BuyerBlocks], v.Impact[finding.BuyerSupportCost], v.Impact[finding.BuyerCosmetic])
	if len(v.NotChecked) > 0 {
		b.WriteString("**Not checked:**\n\n")
		for _, s := range v.NotChecked {
			fmt.Fprintf(b, "- %s\n", mdEscape(s))
		}
		b.WriteString("\n")
	}
}

// Brief is the half-page buyer brief: the verdict, a few reasons per
// question and what was not checked, without the finding list. link, when
// set, points at the full report.
func Brief(r *Report, link string) string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "## Buyer brief: %s\n\n", r.Scan.Target.Display)
	if r.Verdict == nil {
		b.WriteString("No verdict: the scan did not produce enough evidence.\n")
		return b.String()
	}
	fmt.Fprintf(b, "**%s**\n\n", r.Verdict.Headline)
	writeVerdict(b, r.Verdict, 3)
	if link != "" {
		fmt.Fprintf(b, "Full report with the evidence behind every point: %s\n\n", link)
	}
	fmt.Fprintf(b, "_%s Scanned %s with Capybari Source Intelligence._\n", r.Verdict.Disclaimer, r.Scan.FinishedAt.Format("2 Jan 2006"))
	return b.String()
}

// WriteBrief writes the buyer brief.
func WriteBrief(w io.Writer, r *Report) error {
	_, err := io.WriteString(w, Brief(r, ""))
	return err
}
