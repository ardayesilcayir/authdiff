//go:build e2e

// Package e2e runs a full destructive scan against the bundled vuln-lab and
// checks the findings against the oracle in vuln-lab/VULNERABILITIES.md.
//
// The lab is stateful and a destructive scan mutates it (users are deleted,
// roles escalated), so it must be restarted before every run:
//
//	docker compose up -d --build --force-recreate vuln-lab
//	go test -tags e2e -count=1 -run TestVulnLab ./test/e2e/...
//
// TestUIDemoMatchesOracle (ui_test.go) mutates the lab too, so each of the
// two tests needs its own fresh lab: run them one at a time with -run and
// recreate the lab in between.
//
// AUTHDIFF_E2E_URL overrides the lab URL (default http://localhost:8000).
// An unreachable lab fails the test; it is never skipped.
package e2e

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ardayesilcayir/authdiff/pkg/authdiff"
)

// loadEnv sets every KEY=VALUE line of path in the test environment.
func loadEnv(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: fixed file in the repository
	if err != nil {
		t.Fatalf("open env file: %v", err)
	}
	defer func() { _ = f.Close() }()
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
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil { //nolint:gosec // G703: path is in t.TempDir()
		t.Fatal(err)
	}
	return path
}

func TestVulnLab(t *testing.T) {
	base := labURL()
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

	checkOracle(t, orc, res)
}
