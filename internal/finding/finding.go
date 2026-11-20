package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

// Exchange is one masked request/response pair kept as evidence.
type Exchange struct {
	Step            string            `json:"step"`
	Profile         string            `json:"profile"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"requestHeaders,omitempty"`
	RequestBody     string            `json:"requestBody,omitempty"`
	Status          int               `json:"status"`
	ResponseHeaders map[string]string `json:"responseHeaders,omitempty"`
	ResponseBody    string            `json:"responseBody,omitempty"`
	DurationMs      int64             `json:"durationMs"`
	Truncated       bool              `json:"truncated,omitempty"`
}

// Finding is a single detected authorization issue.
type Finding struct {
	ID          string     `json:"id"`
	RuleID      string     `json:"ruleId"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	OWASP       string     `json:"owasp,omitempty"`
	CWE         string     `json:"cwe,omitempty"`
	Severity    Severity   `json:"severity"`
	CVSS        float64    `json:"cvss"`
	Confidence  Confidence `json:"confidence"`
	Method      string     `json:"method"`
	Path        string     `json:"path"`
	Line        int        `json:"line,omitempty"`
	Victim      string     `json:"victim,omitempty"`
	Attacker    string     `json:"attacker,omitempty"`
	Similarity  float64    `json:"similarity"`
	Evidence    []Exchange `json:"evidence,omitempty"`
	Remediation string     `json:"remediation,omitempty"`
	Suppressed  bool       `json:"suppressed"`
}

// NewID derives the stable 12-hex-char finding ID.
func NewID(rule, method, path, victim, attacker string) string {
	sum := sha256.Sum256([]byte(rule + "|" + method + "|" + path + "|" + victim + "|" + attacker))
	return hex.EncodeToString(sum[:])[:12]
}

// RuleMeta describes a rule for reports.
type RuleMeta struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	OWASP       string   `json:"owasp,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Severity    Severity `json:"severity"`
	CVSS        float64  `json:"cvss"`
}

// Outcome is the result of one endpoint/profile probe in the matrix.
type Outcome string

// Outcome values.
const (
	Allowed    Outcome = "allowed"
	Denied     Outcome = "denied"
	Unexpected Outcome = "unexpected"
	Skipped    Outcome = "skipped"
	Errored    Outcome = "error"
)

// MatrixCell is one cell of the endpoint x profile access matrix.
type MatrixCell struct {
	Endpoint string  `json:"endpoint"`
	Profile  string  `json:"profile"`
	Status   int     `json:"status"`
	Outcome  Outcome `json:"outcome"`
}

// Stats holds scan counters.
type Stats struct {
	Endpoints int `json:"endpoints"`
	Requests  int `json:"requests"`
	Blocked   int `json:"blocked"`
	Errors    int `json:"errors"`
}

// Tool identifies the producing tool.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Result is the full output of a scan.
type Result struct {
	Tool       Tool         `json:"tool"`
	Target     string       `json:"target"`
	SpecPath   string       `json:"specPath"`
	StartedAt  time.Time    `json:"startedAt"`
	FinishedAt time.Time    `json:"finishedAt"`
	Profiles   []string     `json:"profiles"`
	Stats      Stats        `json:"stats"`
	Rules      []RuleMeta   `json:"rules"`
	Findings   []Finding    `json:"findings"`
	Matrix     []MatrixCell `json:"matrix"`
}

// Sort orders findings by severity (descending), then RuleID, Method, Path, Victim, Attacker.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := a.Severity.Rank(), b.Severity.Rank(); ra != rb {
			return ra > rb
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Victim != b.Victim {
			return a.Victim < b.Victim
		}
		return a.Attacker < b.Attacker
	})
}

// Active returns the findings that are not suppressed.
func (r *Result) Active() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if !f.Suppressed {
			out = append(out, f)
		}
	}
	return out
}

// FailsAt reports whether any active finding has severity at or above t.
func (r *Result) FailsAt(t Severity) bool {
	for _, f := range r.Active() {
		if f.Severity.Rank() >= t.Rank() {
			return true
		}
	}
	return false
}
