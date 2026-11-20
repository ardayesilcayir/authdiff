package report

import (
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	infoURI      = "https://github.com/ardayesilcayir/authdiff"
	ruleHelpBase = infoURI + "/blob/main/docs/rules/"
)

type sText struct {
	Text string `json:"text"`
}

type sRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sText          `json:"shortDescription"`
	FullDescription      sText          `json:"fullDescription"`
	HelpURI              string         `json:"helpUri"`
	DefaultConfiguration map[string]any `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sText             `json:"message"`
	Locations           []map[string]any  `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
	Suppressions        []map[string]any  `json:"suppressions,omitempty"`
}

func cvssText(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func tagsFor(owasp, cwe string) []string {
	tags := []string{"security"}
	if owasp != "" {
		tags = append(tags, owasp)
	}
	if cwe != "" {
		tags = append(tags, cwe)
	}
	return tags
}

func ruleFrom(m finding.RuleMeta) sRule {
	return sRule{
		ID:                   m.ID,
		Name:                 m.Name,
		ShortDescription:     sText{m.Name},
		FullDescription:      sText{m.Description},
		HelpURI:              ruleHelpBase + m.ID + ".md",
		DefaultConfiguration: map[string]any{"level": m.Severity.SARIFLevel()},
		Properties: map[string]any{
			"tags":              tagsFor(m.OWASP, m.CWE),
			"security-severity": cvssText(m.CVSS),
		},
	}
}

// WriteSARIF writes r as a SARIF 2.1.0 log.
func WriteSARIF(w io.Writer, r *finding.Result) error {
	rules := make([]sRule, 0, len(r.Rules))
	index := map[string]int{}
	for _, m := range r.Rules {
		if _, dup := index[m.ID]; dup {
			continue
		}
		index[m.ID] = len(rules)
		rules = append(rules, ruleFrom(m))
	}

	results := make([]sResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		idx, ok := index[f.RuleID]
		if !ok {
			idx = len(rules)
			index[f.RuleID] = idx
			rules = append(rules, ruleFrom(finding.RuleMeta{
				ID: f.RuleID, Name: f.RuleID, Description: f.Title, OWASP: f.OWASP, CWE: f.CWE,
				Severity: f.Severity, CVSS: f.CVSS,
			}))
		}
		msg := f.Title
		if f.Victim != "" || f.Attacker != "" {
			msg += " (" + f.Victim + " → " + f.Attacker + ")"
		}
		line := f.Line
		if line < 1 {
			line = 1
		}
		res := sResult{
			RuleID: f.RuleID, RuleIndex: idx, Level: f.Severity.SARIFLevel(),
			Message: sText{msg},
			Locations: []map[string]any{{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": strings.ReplaceAll(r.SpecPath, `\`, "/")},
				"region":           map[string]any{"startLine": line},
			}}},
			PartialFingerprints: map[string]string{"authdiffFindingId": f.ID},
			Properties: map[string]any{
				"confidence": string(f.Confidence),
				"victim":     f.Victim,
				"attacker":   f.Attacker,
				"similarity": math.Round(f.Similarity*1e4) / 1e4,
			},
		}
		if f.Suppressed {
			res.Suppressions = []map[string]any{{"kind": "external"}}
		}
		results = append(results, res)
	}

	doc := map[string]any{
		"$schema": sarifSchema,
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "authdiff", "version": r.Tool.Version, "informationUri": infoURI, "rules": rules,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}
