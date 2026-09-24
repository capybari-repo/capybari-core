package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/capybari/capybari-core/finding"
)

// SARIF 2.1.0 subset sufficient for GitHub code scanning.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Help             *sarifText     `json:"help,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
	BaselineState       string            `json:"baselineState,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.Critical, finding.High:
		return "error"
	case finding.Medium:
		return "warning"
	}
	return "note"
}

// securitySeverity maps to GitHub's numeric security-severity property.
func securitySeverity(s finding.Severity) string {
	switch s {
	case finding.Critical:
		return "9.5"
	case finding.High:
		return "8.0"
	case finding.Medium:
		return "5.5"
	case finding.Low:
		return "3.0"
	}
	return "0.0"
}

func ruleID(f finding.Finding) string {
	if f.Rule != nil && f.Rule.ID != "" {
		return f.Source.Capability + "/" + f.Rule.ID
	}
	return f.Source.Capability + "/" + f.Category
}

// WriteSARIF writes findings that have file locations as SARIF 2.1.0.
// Findings without a repository path (e.g. website findings) are attached
// to the scanned URL so nothing is silently dropped.
func WriteSARIF(w io.Writer, r *Report) error {
	rules := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range r.Findings {
		id := ruleID(f)
		if _, ok := rules[id]; !ok {
			rule := sarifRule{ID: id, ShortDescription: sarifText{Text: f.Title},
				Properties: map[string]any{"tags": append([]string{f.Dimension, f.Category}, f.Tags...), "security-severity": securitySeverity(f.Severity)}}
			if f.Rule != nil {
				rule.Name = f.Rule.Name
				if len(f.Rule.References) > 0 {
					rule.HelpURI = f.Rule.References[0]
				}
			}
			if f.Remediation != nil {
				rule.Help = &sarifText{Text: f.Remediation.Summary}
			}
			rules[id] = rule
		}
		msg := f.Title
		if f.Description != "" {
			msg += ". " + f.Description
		}
		res := sarifResult{
			RuleID: id, Level: sarifLevel(f.Severity), Message: sarifText{Text: msg},
			PartialFingerprints: map[string]string{"capybariFindingId/v1": f.ID},
			Properties:          map[string]any{"severity": f.Severity, "confidence": f.Confidence, "dimension": f.Dimension},
		}
		switch f.BaselineState {
		case finding.BaselineNew:
			res.BaselineState = "new"
		case finding.BaselineExisting:
			res.BaselineState = "unchanged"
		}
		for _, e := range f.Evidence {
			uri := e.Path
			if uri == "" {
				uri = e.URL
			}
			if uri == "" {
				continue
			}
			loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}}
			if e.StartLine > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: e.StartLine, EndLine: e.EndLine}
			}
			res.Locations = append(res.Locations, loc)
			if len(res.Locations) == 10 {
				break
			}
		}
		if len(res.Locations) == 0 && r.Scan.Target.URL != "" {
			res.Locations = []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: r.Scan.Target.URL}}}}
		}
		results = append(results, res)
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ruleList := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		ruleList = append(ruleList, rules[id])
	}
	if results == nil {
		results = []sarifResult{}
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "Capybari Source Intelligence", Version: r.Tool.Version,
				InformationURI: "https://github.com/capybari/capybari-cli", Rules: ruleList,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
