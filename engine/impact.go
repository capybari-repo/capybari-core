package engine

import (
	"sort"

	"github.com/capybari-repo/capybari-core/finding"
)

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
	"linked-app-stale":        {"", finding.Low},
	"app-no-track-record":     {"", finding.Low},
	"brand-inconsistent":      {"", finding.Low},
	"broken-link":             {"", finding.Low},
	"dead-cta":                {"", finding.Low},
	"domain-new":              {"", finding.Low},
	"domain-expiring":         {"", finding.Low},
	"email-spoofable":         {"", finding.Low},
	"brand-mismatch":          {"", finding.Low},
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

// buyerRank orders impacts for display: blockers, support cost, cosmetic.
var buyerRank = map[string]int{finding.BuyerBlocks: 0, finding.BuyerSupportCost: 1, finding.BuyerCosmetic: 2}

// fearRank orders categories by how sharply they speak to a buyer (lower
// comes first). Unlisted categories sit in the middle (30); notes that
// inform but rarely alarm come last. Reports, summaries and share cards all
// lead with the same finding because they all use this order.
var fearRank = map[string]int{
	"insecure-credentials": 1, "https": 2, "tls": 2, "secret": 3, "committed-env-file": 3, "exposure": 3, "malicious-package": 3,
	"coming-soon": 4, "missing-legal": 5,
	"email-spoofable": 10, "placeholder-content": 14, "vulnerable-library": 16, "vulnerability": 16, "unknown-package": 16,
	"dead-cta": 18, "broken-link": 20, "domain-new": 22, "young-domain": 22, "no-ops-trail": 24, "missing-contact": 26,
	"inactive-repository": 28, "license-restriction": 29,
	"brand-mismatch": 40, "brand-inconsistent": 41, "app-no-track-record": 41, "missing-docs": 42, "linked-app-stale": 44, "purchase-path-unverified": 45, "stale-content": 46, "single-maintainer": 47,
	"unmaintained-dependency": 48, "missing-refund": 49, "domain-expiring": 49, "maintenance-signal": 50,
}

// FearRank returns how early a category should lead for buyers.
func FearRank(category string) int {
	if n, ok := fearRank[category]; ok {
		return n
	}
	return 30
}

// sortForBuyers puts what matters to buyers first: blockers, then support
// cost, then cosmetic; within each, the sharpest category first, then the
// usual severity order.
func sortForBuyers(fs []finding.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := buyerRank[fs[i].Impact.Buyer], buyerRank[fs[j].Impact.Buyer]
		if a != b {
			return a < b
		}
		if a == buyerRank[finding.BuyerCosmetic] {
			return false
		}
		return FearRank(fs[i].Category) < FearRank(fs[j].Category)
	})
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
