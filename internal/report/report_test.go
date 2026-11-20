package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

var update = flag.Bool("update", false, "update golden files")

func fixture() *finding.Result {
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return &finding.Result{
		Tool:       finding.Tool{Name: "authdiff", Version: "0.1.0"},
		Target:     "http://localhost:8000",
		SpecPath:   `specs\openapi.yaml`,
		StartedAt:  t0,
		FinishedAt: t0.Add(2500 * time.Millisecond),
		Profiles:   []string{"alice", "bob", "anon"},
		Stats:      finding.Stats{Endpoints: 3, Requests: 27, Blocked: 1, Errors: 0},
		Rules: []finding.RuleMeta{
			{ID: "AD-BOLA-001", Name: "BrokenObjectLevelAuthorization", Description: "Another user can read an object they do not own.", OWASP: "API1:2023", CWE: "CWE-639", Remediation: "Check object ownership on the server.", Severity: finding.High, CVSS: 8.1},
			{ID: "AD-NOAUTH-001", Name: "MissingAuthentication", Description: "Endpoint answers without credentials.", OWASP: "API2:2023", CWE: "CWE-306", Severity: finding.Critical, CVSS: 9.1},
		},
		Findings: []finding.Finding{
			{ID: "aaaaaaaaaaaa", RuleID: "AD-NOAUTH-001", Title: "Endpoint reachable without authentication", Description: "GET /orders/{orderId} returned 200 to anon.", OWASP: "API2:2023", CWE: "CWE-306", Severity: finding.Critical, CVSS: 9.1, Confidence: finding.ConfHigh, Method: "GET", Path: "/orders/{orderId}", Line: 12, Victim: "alice", Attacker: "anon", Similarity: 0.97, Remediation: "Require authentication.",
				Evidence: []finding.Exchange{{Step: "attacker", Profile: "anon", Method: "GET", URL: "http://localhost:8000/orders/101", Status: 200, ResponseHeaders: map[string]string{"Content-Type": "text/html"}, ResponseBody: `<script>alert(1)</script>`, DurationMs: 12}}},
			{ID: "bbbbbbbbbbbb", RuleID: "AD-BOLA-001", Title: "Cross-user object read", Description: "bob read alice's order.", OWASP: "API1:2023", CWE: "CWE-639", Severity: finding.High, CVSS: 8.1, Confidence: finding.ConfMedium, Method: "GET", Path: "/orders/{orderId}", Victim: "alice", Attacker: "bob", Similarity: 0.91,
				Evidence: []finding.Exchange{{Step: "victim", Profile: "alice", Method: "GET", URL: "http://localhost:8000/orders/101", Status: 200, RequestHeaders: map[string]string{"Authorization": "****abcd"}, ResponseBody: `{"id":101}`}}},
			{ID: "cccccccccccc", RuleID: "AD-BOLA-001", Title: "Cross-user object read", Severity: finding.High, CVSS: 8.1, Confidence: finding.ConfLow, Method: "GET", Path: "/users/{id}", Victim: "bob", Attacker: "alice", Similarity: 0.88, Suppressed: true},
		},
		Matrix: mat(),
	}
}

func mat() []finding.MatrixCell {
	var m []finding.MatrixCell
	eps := []string{"GET /orders/{orderId}", "GET /users/{id}", "DELETE /orders/{orderId}"}
	outs := []finding.Outcome{finding.Allowed, finding.Denied, finding.Unexpected, finding.Skipped, finding.Errored}
	for i, e := range eps {
		for j, p := range []string{"alice", "bob", "anon"} {
			o := outs[(i*3+j)%len(outs)]
			st := 200
			if o == finding.Denied {
				st = 403
			}
			m = append(m, finding.MatrixCell{Endpoint: e, Profile: p, Status: st, Outcome: o})
		}
	}
	return m
}

func norm(b []byte) string { return strings.ReplaceAll(string(b), "\r\n", "\n") }

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		require.NoError(t, os.WriteFile(p, []byte(norm(got)), 0o644))
	}
	want, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, norm(want), norm(got))
}

func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteJSON(&buf, fixture()))
	assert.Contains(t, buf.String(), "\n  \"tool\"")
	got, err := ReadJSON(&buf)
	require.NoError(t, err)
	assert.Equal(t, fixture(), got)
	_, err = ReadJSON(strings.NewReader("{"))
	assert.Error(t, err)
}

func TestSARIFGolden(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteSARIF(&buf, fixture()))
	golden(t, "results.sarif.golden", buf.Bytes())
}

func TestSARIFShape(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteSARIF(&buf, fixture()))
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []map[string]any `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID       string `json:"ruleId"`
				RuleIndex    int    `json:"ruleIndex"`
				Suppressions []any  `json:"suppressions"`
				Locations    []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	assert.Equal(t, "2.1.0", doc.Version)
	run := doc.Runs[0]
	require.Len(t, run.Results, 3)
	suppressed := 0
	for _, res := range run.Results {
		require.True(t, res.RuleIndex >= 0 && res.RuleIndex < len(run.Tool.Driver.Rules))
		assert.Equal(t, res.RuleID, run.Tool.Driver.Rules[res.RuleIndex]["id"])
		pl := res.Locations[0].PhysicalLocation
		assert.GreaterOrEqual(t, pl.Region.StartLine, 1)
		assert.Equal(t, "specs/openapi.yaml", pl.ArtifactLocation.URI)
		if len(res.Suppressions) > 0 {
			suppressed++
		}
	}
	assert.Equal(t, 1, suppressed)
}

func TestSARIFUnknownRule(t *testing.T) {
	r := fixture()
	r.Findings[0].RuleID = "AD-CUSTOM-1"
	var buf bytes.Buffer
	require.NoError(t, WriteSARIF(&buf, r))
	assert.Contains(t, buf.String(), "AD-CUSTOM-1")
	assert.Contains(t, buf.String(), `"ruleIndex": 2`)
}

func TestHTMLGolden(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteHTML(&buf, fixture()))
	golden(t, "report.html.golden", buf.Bytes())
}

func TestHTMLEscapes(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteHTML(&buf, fixture()))
	out := buf.String()
	assert.NotContains(t, out, "<script>alert(1)</script>")
	assert.Contains(t, out, "&lt;script&gt;")
	assert.Contains(t, out, `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">`)
	assert.NotContains(t, out, "<script")
	for _, c := range []string{"allowed", "denied", "unexpected", "skipped", "error"} {
		assert.Contains(t, out, `class="cell `+c+`"`)
	}
}

func TestHTMLEmpty(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteHTML(&buf, &finding.Result{}))
	assert.Contains(t, buf.String(), "No findings")
}

func TestTerminalGolden(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteTerminal(&buf, fixture(), false))
	golden(t, "terminal.golden", buf.Bytes())
}

func TestTerminalEmptyAndColor(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteTerminal(&buf, &finding.Result{}, false))
	assert.Contains(t, buf.String(), "No findings.")
	buf.Reset()
	require.NoError(t, WriteTerminal(&buf, fixture(), true))
	assert.Contains(t, buf.String(), "AD-BOLA-001")
}

func TestWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out", "x")
	var out bytes.Buffer
	paths, err := Write(dir, []string{"json", "sarif", "html", "terminal"}, fixture(), &out, false)
	require.NoError(t, err)
	assert.Len(t, paths, 3)
	for _, n := range []string{"results.json", "results.sarif", "report.html"} {
		assert.FileExists(t, filepath.Join(dir, n))
	}
	assert.Contains(t, out.String(), "findings")
	_, err = Write(dir, []string{"pdf"}, fixture(), &out, false)
	assert.Error(t, err)
}
