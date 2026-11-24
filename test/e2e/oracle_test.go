//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ardayesilcayir/authdiff/pkg/authdiff"
)

const defaultURL = "http://localhost:8000"

// repoRoot is the repository root relative to this package directory.
const repoRoot = "../.."

type endpoint struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}

type expectation struct {
	ID          string `yaml:"id"`
	Rule        string `yaml:"rule"`
	Method      string `yaml:"method"`
	Path        string `yaml:"path"`
	Destructive bool   `yaml:"destructive"`
}

type oracle struct {
	Expected  []expectation `yaml:"expected"`
	Negatives []endpoint    `yaml:"negatives"`
}

// tuple identifies a finding class: rule, method and path template.
type tuple struct{ Rule, Method, Path string }

func (t tuple) String() string { return t.Rule + " " + t.Method + " " + t.Path }

// labURL is AUTHDIFF_E2E_URL without a trailing slash, or defaultURL.
func labURL() string {
	base := strings.TrimRight(os.Getenv("AUTHDIFF_E2E_URL"), "/")
	if base == "" {
		base = defaultURL
	}
	return base
}

func loadOracle(t *testing.T) oracle {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "vuln-lab", "VULNERABILITIES.md"))
	if err != nil {
		t.Fatalf("read oracle: %v", err)
	}
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	parts := bytes.SplitN(data, []byte("---\n"), 3)
	if len(parts) < 3 || len(parts[0]) != 0 {
		t.Fatal("VULNERABILITIES.md: missing YAML front-matter")
	}
	var o oracle
	if err := yaml.Unmarshal(parts[1], &o); err != nil {
		t.Fatalf("parse front-matter: %v", err)
	}
	if len(o.Expected) == 0 {
		t.Fatal("front-matter has no expected findings")
	}
	return o
}

// waitForLab fails the test unless the lab serves its spec.
func waitForLab(t *testing.T, base string) {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for i := 0; i < 5; i++ {
		resp, err := client.Get(base + "/openapi.json")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			err = fmt.Errorf("status %d", resp.StatusCode)
		}
		lastErr = err
		time.Sleep(time.Second)
	}
	t.Fatalf("vuln-lab not reachable at %s (start it with `make lab`): %v", base, lastErr)
}

// checkOracle compares the active findings of res with the oracle: every
// expected (rule, method, path) tuple must be found, nothing else, and no
// finding may be on a negative endpoint. It logs recall and the false
// positive rate.
func checkOracle(t *testing.T, orc oracle, res *authdiff.Result) {
	t.Helper()
	want := map[tuple]string{}
	for _, e := range orc.Expected {
		want[tuple{e.Rule, e.Method, e.Path}] = e.ID
	}
	negative := map[endpoint]bool{}
	for _, n := range orc.Negatives {
		negative[n] = true
	}

	got := map[tuple]int{}
	for _, f := range res.Active() {
		got[tuple{f.RuleID, f.Method, f.Path}]++
		if negative[endpoint{f.Method, f.Path}] {
			t.Errorf("finding on negative endpoint %s %s: %s (victim %s, attacker %s)",
				f.Method, f.Path, f.RuleID, f.Victim, f.Attacker)
		}
	}

	var hit, fp []string
	var missing []string
	for tp, id := range want {
		if got[tp] > 0 {
			hit = append(hit, id+" "+tp.String())
		} else {
			missing = append(missing, id+" "+tp.String())
		}
	}
	for tp, n := range got {
		if _, ok := want[tp]; !ok {
			fp = append(fp, fmt.Sprintf("%s (x%d)", tp, n))
		}
	}
	sort.Strings(hit)
	sort.Strings(missing)
	sort.Strings(fp)
	for _, h := range hit {
		t.Logf("found   %s", h)
	}
	for _, m := range missing {
		t.Errorf("missing %s", m)
	}
	for _, f := range fp {
		t.Errorf("unexpected finding %s", f)
	}

	recall := float64(len(hit)) / float64(len(want))
	fpRate := 0.0
	if len(got) > 0 {
		fpRate = float64(len(fp)) / float64(len(got))
	}
	t.Logf("recall: %.2f (%d/%d expected)", recall, len(hit), len(want))
	t.Logf("false positive rate: %.2f (%d/%d distinct (rule, method, path) tuples)", fpRate, len(fp), len(got))
}
