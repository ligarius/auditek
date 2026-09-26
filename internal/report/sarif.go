package report

import (
	"encoding/json"

	"auditek/internal/findings"
)

// SARIF 2.1.0 mínimo pero válido, para subir a GitHub code scanning u otras
// herramientas que consumen el estándar. Ver https://sarifweb.azurewebsites.net.

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	toolVersion  = "0.3.0"
	toolInfoURI  = "https://github.com/ligarius/auditek"
)

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
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifText       `json:"shortDescription"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
}
type sarifRuleConfig struct {
	Level string `json:"level"`
}
type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	RuleIndex  int               `json:"ruleIndex"`
	Level      string            `json:"level"`
	Message    sarifText         `json:"message"`
	Locations  []sarifLocation   `json:"locations"`
	Properties map[string]string `json:"properties,omitempty"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}

// sarifLevel mapea la severidad de auditek al enum de SARIF (error/warning/note).
func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default: // low, info
		return "note"
	}
}

// BuildSARIF construye el documento SARIF 2.1.0 (JSON indentado) a partir de los
// hallazgos. Cada RuleID único se registra una vez en tool.driver.rules y los
// resultados lo referencian por índice.
func BuildSARIF(scanID, target string, fs []findings.Finding) ([]byte, error) {
	var rules []sarifRule
	ruleIndex := map[string]int{}

	results := make([]sarifResult, 0, len(fs))
	for _, f := range fs {
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			idx = len(rules)
			ruleIndex[f.RuleID] = idx
			rules = append(rules, sarifRule{
				ID:                   f.RuleID,
				Name:                 f.RuleName,
				ShortDescription:     sarifText{Text: f.RuleName},
				DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(f.Severity)},
			})
		}

		msg := f.RuleName
		if f.Impact != "" {
			msg += " — " + f.Impact
		}
		props := map[string]string{"severity": f.Severity}
		if f.CVE != "" {
			props["cve"] = f.CVE
		}

		loc := f.Target
		if loc == "" {
			loc = target
		}

		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: loc}},
			}},
			Properties: props,
		})
	}

	doc := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "auditek",
				InformationURI: toolInfoURI,
				Version:        toolVersion,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	return json.MarshalIndent(doc, "", "  ")
}
