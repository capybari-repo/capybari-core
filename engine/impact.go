package engine

import "github.com/capybari-repo/capybari-core/finding"

// Buyer impact answers "does this change whether I should trust, use or pay
// for the product?" rather than "how bad is it technically?". A missing
// security header is owner homework; no HTTPS, a leaked key or an invented
// package is a reason to stop. Analyzers may set Impact.Buyer themselves;
// otherwise the engine classifies by category and severity.
//
// Documented in capybari-docs/methodology/verdict.md#buyer-impact.

type impactRule struct {
	// blocksAt is the lowest severity at which the finding blocks a
	// purchase ("" = never); supportAt the lowest at which it raises
	// support cost ("" = never). Below both it is cosmetic.
	blocksAt, supportAt finding.Severity
}

var impactRules = map[string]impactRule{
	// Data, money and accounts at risk.
	"https":              {finding.High, finding.Low},
	"tls":                {finding.High, finding.Low},
	"mixed-content":      {finding.High, finding.Low},
	"secret":             {finding.Medium, finding.Low},
	"committed-env-file": {finding.Medium, finding.Low},
	"exposure":           {finding.Medium, finding.Low},
	"malicious-package":  {finding.Low, ""},
	"unknown-package":    {finding.High, finding.Low},
	// Front-end library advisories rarely apply to how a site uses the
	// library; only critical ones stop a buyer.
	"vulnerable-library": {finding.Critical, finding.Low},
	"vulnerability":      {finding.High, finding.Medium},
	"cookie":             {"", finding.Medium},
	// Ages badly or costs users time.
	"end-of-life":             {"", finding.Low},
	"deprecated-library":      {"", finding.Low},
	"runtime":                 {"", finding.Medium},
	"maintenance-signal":      {"", finding.Low},
	"missing-tests":           {"", finding.Low},
	"missing-ci":              {"", finding.Low},
	"missing-license":         {"", finding.Low},
	"missing-lockfile":        {"", finding.Medium},
	"swallowed-errors":        {"", finding.Medium},
	"scaffold-code":           {"", finding.Medium},
	"placeholder-config":      {"", finding.Medium},
	"placeholder-content":     {"", finding.Low},
	"template-leftover":       {"", finding.Medium},
	"ai-boilerplate":          {"", finding.Medium},
	"hotspot":                 {"", finding.High},
	"unmaintained-dependency": {"", finding.Low},
	"deprecated-package":      {"", finding.Low},
	"inactive-repository":     {"", finding.Low},
	"single-maintainer":       {"", finding.Low},
	"stale-content":           {"", finding.Low},
	"linked-repo-inactive":    {"", finding.Low},
	"linked-repo-archived":    {"", finding.Low},
	"missing-docs":            {"", finding.Low},
	"complexity":              {"", finding.High},
	"dependency-cycle":        {"", finding.High},
	// Owner homework: never changes a buyer's decision on its own.
	"security-header": {"", ""},
	"disclosure":      {"", ""},
	"sri":             {"", finding.High},
}

// at reports whether sev is at or above min ("" = never).
func at(sev, min finding.Severity) bool {
	return min != "" && sev.Rank() >= min.Rank()
}

// BuyerImpact classifies a finding for buyers.
func BuyerImpact(f finding.Finding) string {
	if f.Impact != nil && f.Impact.Buyer != "" {
		return f.Impact.Buyer
	}
	if f.Severity == finding.Info {
		return finding.BuyerCosmetic
	}
	r, ok := impactRules[f.Category]
	if !ok {
		r = impactRule{finding.Critical, finding.Medium}
	}
	switch {
	case at(f.Severity, r.blocksAt):
		return finding.BuyerBlocks
	case at(f.Severity, r.supportAt):
		return finding.BuyerSupportCost
	}
	return finding.BuyerCosmetic
}

// tagBuyerImpact fills Impact.Buyer on every finding.
func tagBuyerImpact(fs []finding.Finding) {
	for i := range fs {
		b := BuyerImpact(fs[i])
		if fs[i].Impact == nil {
			fs[i].Impact = &finding.Impact{}
		}
		fs[i].Impact.Buyer = b
	}
}
