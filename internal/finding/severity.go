// Package finding defines the shared data model for authdiff scan results.
package finding

import (
	"fmt"
	"strings"
)

// Severity is the impact rating of a finding.
type Severity string

// Severity levels.
const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Confidence is how sure a rule is about a finding.
type Confidence string

// Confidence levels.
const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// ParseSeverity parses a severity name case-insensitively.
func ParseSeverity(s string) (Severity, error) {
	switch v := Severity(strings.ToLower(strings.TrimSpace(s))); v {
	case Critical, High, Medium, Low, Info:
		return v, nil
	}
	return "", fmt.Errorf("unknown severity %q (want critical, high, medium, low or info)", s)
}

// Rank returns a sortable weight: critical=5 down to info=1, unknown=0.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	}
	return 0
}

// DefaultCVSS returns the estimated CVSS 3.1 base score for a severity.
func DefaultCVSS(s Severity) float64 {
	switch s {
	case Critical:
		return 9.1
	case High:
		return 8.1
	case Medium:
		return 6.5
	case Low:
		return 3.7
	}
	return 0.0
}

// SARIFLevel maps the severity to a SARIF result level.
func (s Severity) SARIFLevel() string {
	switch s {
	case Critical, High:
		return "error"
	case Medium:
		return "warning"
	}
	return "note"
}
