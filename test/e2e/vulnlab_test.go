//go:build e2e

// Package e2e runs a full destructive scan against the bundled vuln-lab and
// checks the findings against the oracle in vuln-lab/VULNERABILITIES.md.
//
// The lab is stateful and a destructive scan mutates it (users are deleted,
// roles escalated), so it must be restarted before every run:
//
//	docker compose up -d --build --force-recreate vuln-lab
//	go test -tags e2e -count=1 ./test/e2e/...
//
// AUTHDIFF_E2E_URL overrides the lab URL (default http://localhost:8000).
// An unreachable lab fails the test; it is never skipped.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
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

// loadEnv sets every KEY=VALUE line of path in the test environment.
func loadEnv(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open env file: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("env file: malformed line %q", line)
		}
		t.Setenv(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read env file: %v", err)
	}
}

// waitForLab fails the test unless the lab serves its spec.
func waitForLab(t *testing.T, base string) {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for i := 0; i < 5; i++ {
		resp, err := client.Get(base + "/openapi.json")
		if err == nil {
			resp.Body.Close()
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

// writeConfig copies examples/authdiff.yaml into a temp dir, pointed at base.
func writeConfig(t *testing.T, base string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "examples", "authdiff.yaml"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		t.Fatalf("AUTHDIFF_E2E_URL %q is not a URL", base)
	}
	s := strings.ReplaceAll(string(data), defaultURL, base)
	s = strings.ReplaceAll(s, `"localhost:8000"`, fmt.Sprintf("%q", u.Host))
	path := filepath.Join(t.TempDir(), "authdiff.yaml")
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVulnLab(t *testing.T) {
	base := strings.TrimRight(os.Getenv("AUTHDIFF_E2E_URL"), "/")
	if base == "" {
		base = defaultURL
	}
	orc := loadOracle(t)
	loadEnv(t, filepath.Join(repoRoot, "examples", "vuln-lab.env"))
	waitForLab(t, base)
	cfgPath := writeConfig(t, base)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	allow := true
	outDir := t.TempDir()
	res, err := authdiff.Scan(ctx, authdiff.ScanOptions{
		ConfigPath: cfgPath,
		Version:    "e2e",
		Overrides:  authdiff.Overrides{AllowDestructive: &allow, OutputDir: &outDir},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	t.Logf("scan: %d findings, %d requests, %d blocked, %d errors",
		len(res.Findings), res.Stats.Requests, res.Stats.Blocked, res.Stats.Errors)

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
