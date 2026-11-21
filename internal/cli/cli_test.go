package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/report"
)

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestInitCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	code, out, errOut := run(t, "init", "--dir", dir)
	if code != 0 {
		t.Fatalf("init exit %d: %s", code, errOut)
	}
	cfgData, err := os.ReadFile(filepath.Join(dir, "authdiff.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ignore, err := os.ReadFile(filepath.Join(dir, ".authdiff-ignore"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"version: 1", "acknowledgeAuthorization", "${env:ALICE_TOKEN}", "allowHosts", "failOn"} {
		if !strings.Contains(string(cfgData), want) {
			t.Errorf("authdiff.yaml lacks %q", want)
		}
	}
	if !strings.HasPrefix(string(ignore), "#") {
		t.Errorf(".authdiff-ignore has no header comment: %q", ignore)
	}
	if !strings.Contains(out, "authdiff.yaml") {
		t.Errorf("stdout = %q", out)
	}
	// The template refuses to scan until the user acknowledges authorization,
	// and parses once that is done and its env vars exist.
	if !strings.Contains(string(cfgData), "acknowledgeAuthorization: false") {
		t.Error("template must not pre-acknowledge authorization")
	}
	for _, v := range []string{"ADMIN_TOKEN", "ALICE_TOKEN", "BOB_TOKEN"} {
		t.Setenv(v, "x")
	}
	acked := strings.Replace(string(cfgData), "acknowledgeAuthorization: false", "acknowledgeAuthorization: true", 1)
	if _, err := config.Parse([]byte(acked)); err != nil {
		t.Errorf("template does not parse: %v", err)
	}

	code, _, errOut = run(t, "init", "--dir", dir)
	if code != 2 || !strings.Contains(errOut, "--force") {
		t.Errorf("second init: exit %d, stderr %q", code, errOut)
	}
	if code, _, errOut = run(t, "init", "--dir", dir, "--force"); code != 0 {
		t.Errorf("init --force: exit %d %s", code, errOut)
	}
}

func TestInitDoesNotPartiallyWrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".authdiff-ignore"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := run(t, "init", "--dir", dir); code != 2 {
		t.Errorf("exit %d", code)
	}
	if exists(filepath.Join(dir, "authdiff.yaml")) {
		t.Error("authdiff.yaml written although .authdiff-ignore existed")
	}
}

func TestRulesList(t *testing.T) {
	code, out, errOut := run(t, "rules", "list")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(strings.SplitN(out, "\n", 2)[0], "ID") || !strings.Contains(out, "SEVERITY") ||
		!strings.Contains(out, "OWASP") || !strings.Contains(out, "NAME") {
		t.Errorf("header missing: %q", out)
	}
	for _, id := range []string{"AD-BOLA-001", "AD-BOLA-002", "AD-BFLA-001", "AD-NOAUTH-001",
		"AD-MASS-001", "AD-METHOD-001", "AD-MATRIX-001", "AD-LEAK-001"} {
		if !strings.Contains(out, id) {
			t.Errorf("rules list lacks %s", id)
		}
	}
	if n := strings.Count(out, "AD-"); n != 8 {
		t.Errorf("listed %d rules, want 8", n)
	}
}

func TestRulesListCustomDir(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "c.yaml", "AD-CUSTOM-001")
	code, out, _ := run(t, "rules", "list", "--rules", dir)
	if code != 0 || !strings.Contains(out, "AD-CUSTOM-001") {
		t.Errorf("exit %d out %q", code, out)
	}
	writeRule(t, dir, "d.yaml", "AD-BOLA-001")
	if code, _, errOut := run(t, "rules", "list", "--rules", dir); code != 2 || !strings.Contains(errOut, "duplicate") {
		t.Errorf("duplicate: exit %d %q", code, errOut)
	}
}

func writeRule(t *testing.T, dir, name, id string) {
	t.Helper()
	src := `id: ` + id + `
name: Custom
owasp: "API1:2023"
severity: low
applies: { methods: [GET] }
steps:
  - { name: me, as: any_user, use: self }
match: me.ok
`
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRulesValidate(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "good.yaml", "AD-CUSTOM-001")
	code, out, _ := run(t, "rules", "validate", filepath.Join(dir, "good.yaml"))
	if code != 0 || strings.TrimSpace(out) != "OK AD-CUSTOM-001" {
		t.Errorf("good: exit %d out %q", code, out)
	}
}

func TestRulesValidateBad(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("id: nope\nmatch: \"(((\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, "rules", "validate", bad)
	if code != 2 || strings.Contains(out, "OK") || errOut == "" {
		t.Errorf("bad: exit %d out %q err %q", code, out, errOut)
	}
	if code, _, _ := run(t, "rules", "validate"); code != 2 {
		t.Errorf("missing arg: exit %d", code)
	}
}

func TestScanRefusesWithoutAck(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	data, _ := os.ReadFile(p)
	data = []byte(strings.Replace(string(data), "acknowledgeAuthorization: true", "acknowledgeAuthorization: false", 1))
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := run(t, "scan", "-c", p)
	if code != 2 || !strings.Contains(errOut, "acknowledgeAuthorization") {
		t.Errorf("exit %d stderr %q", code, errOut)
	}
	if api.hits.Load() != 0 {
		t.Errorf("%d requests sent without acknowledgement", api.hits.Load())
	}
}

func TestScanDryRunNoNetwork(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	code, out, errOut := run(t, "scan", "-c", p, "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	header := strings.Fields(strings.SplitN(out, "\n", 2)[0])
	if strings.Join(header, ",") != "RULE,STEP,PROFILE,METHOD,PATH,DESTRUCTIVE" {
		t.Errorf("header = %v", header)
	}
	if !strings.Contains(out, "AD-BOLA-001") || !strings.Contains(out, "/orders/101") {
		t.Errorf("plan = %q", out)
	}
	if api.hits.Load() != 0 {
		t.Errorf("dry run sent %d requests", api.hits.Load())
	}
	if exists(outDir(p)) {
		t.Error("dry run wrote reports")
	}
}

func TestScanFailOn(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	code, out, errOut := run(t, "scan", "-c", p, "--fail-on", "high", "--format", "terminal")
	if code != 1 {
		t.Errorf("--fail-on high: exit %d, stderr %s", code, errOut)
	}
	if !strings.Contains(out, "AD-BOLA-001") {
		t.Errorf("terminal report missing finding: %q", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("color written to a non-terminal")
	}
	if code, _, errOut := run(t, "scan", "-c", p, "--fail-on", "critical"); code != 0 {
		t.Errorf("--fail-on critical: exit %d, stderr %s", code, errOut)
	}
	if code, _, _ := run(t, "scan", "-c", p, "--fail-on", "bogus"); code != 2 {
		t.Errorf("--fail-on bogus: exit %d", code)
	}
}

func TestScanWritesOutputs(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	dir := filepath.Join(t.TempDir(), "reports")
	code, _, errOut := run(t, "scan", "-c", p, "--format", "json,sarif,html", "--output", dir, "--rate", "500")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, name := range []string{"results.json", "results.sarif", "report.html"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, tok := range []string{aliceToken, bobToken} {
			if strings.Contains(string(data), tok) {
				t.Errorf("%s contains token %q", name, tok)
			}
		}
	}
	for _, tok := range []string{aliceToken, bobToken} {
		if strings.Contains(errOut, tok) {
			t.Errorf("log contains token")
		}
	}
	f, _ := os.Open(filepath.Join(dir, "results.json"))
	defer func() { _ = f.Close() }()
	res, err := report.ReadJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tool.Version != "1.2.3" || res.Target != api.URL || len(res.Findings) == 0 {
		t.Errorf("result = %+v", res)
	}
}

func TestScanUnknownFormatWritesNothing(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	dir := filepath.Join(t.TempDir(), "reports")
	code, _, errOut := run(t, "scan", "-c", p, "--format", "json,pdf", "--output", dir)
	if code != 2 || !strings.Contains(errOut, "pdf") {
		t.Errorf("exit %d stderr %q", code, errOut)
	}
	if exists(dir) || api.hits.Load() != 0 {
		t.Errorf("work done despite bad format (hits %d)", api.hits.Load())
	}
}

func TestIgnoreSuppresses(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	if code, _, errOut := run(t, "scan", "-c", p, "--fail-on", "high"); code != 1 {
		t.Fatalf("first scan exit %d: %s", code, errOut)
	}
	f, err := os.Open(filepath.Join(outDir(p), "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := report.ReadJSON(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("# acknowledged\n")
	for _, fd := range res.Findings {
		b.WriteString(fd.ID + " # " + fd.RuleID + "\n")
	}
	ignore := filepath.Join(t.TempDir(), ".authdiff-ignore")
	if err := os.WriteFile(ignore, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run(t, "scan", "-c", p, "--fail-on", "high", "--ignore-file", ignore); code != 0 {
		t.Errorf("second scan exit %d: %s", code, errOut)
	}
}

func TestScanInterrupted(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, _, errOut := runCtx(t, ctx, "scan", "-c", p)
	if code != 2 || !strings.Contains(errOut, "scan interrupted, partial results written") {
		t.Errorf("exit %d stderr %q", code, errOut)
	}
	if !exists(filepath.Join(outDir(p), "results.json")) {
		t.Error("partial results.json not written")
	}
}

func TestReportCommand(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	if code, _, errOut := run(t, "scan", "-c", p); code != 0 {
		t.Fatalf("scan exit %d: %s", code, errOut)
	}
	in := filepath.Join(outDir(p), "results.json")
	dir := filepath.Join(t.TempDir(), "re")
	code, out, errOut := run(t, "report", "-i", in, "-f", "html,sarif,terminal", "-o", dir)
	if code != 0 {
		t.Fatalf("report exit %d: %s", code, errOut)
	}
	if !exists(filepath.Join(dir, "report.html")) || !exists(filepath.Join(dir, "results.sarif")) {
		t.Error("report files missing")
	}
	if !strings.Contains(out, "AD-BOLA-001") {
		t.Errorf("terminal output = %q", out)
	}

	bad := filepath.Join(t.TempDir(), "bad")
	if code, _, _ := run(t, "report", "-i", in, "-f", "html,pdf", "-o", bad); code != 2 || exists(bad) {
		t.Errorf("unknown format: exit %d, dir exists %v", code, exists(bad))
	}
	if code, _, _ := run(t, "report", "-i", filepath.Join(dir, "missing.json")); code != 2 {
		t.Errorf("missing input: exit %d", code)
	}
}

func TestInventory(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	code, out, errOut := run(t, "inventory", "-c", p)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	header := strings.Fields(strings.SplitN(out, "\n", 2)[0])
	if strings.Join(header, ",") != "METHOD,PATH,OPERATION,SECURED,PARAMS" {
		t.Errorf("header = %v", header)
	}
	if !strings.Contains(out, "/orders/{orderId}") || !strings.Contains(out, "getOrder") || !strings.Contains(out, "orderId(path)") {
		t.Errorf("inventory = %q", out)
	}

	code, out, _ = run(t, "inventory", "-c", p, "--json")
	var eps []map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &eps) != nil || len(eps) != 1 || eps[0]["path"] != "/orders/{orderId}" {
		t.Errorf("json: exit %d out %q", code, out)
	}
	if api.hits.Load() != 0 {
		t.Errorf("inventory sent %d requests", api.hits.Load())
	}
}

func TestInventorySpecURLUsesScope(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	data, _ := os.ReadFile(p)
	data = []byte(strings.Replace(string(data), "./openapi.yaml", "http://evil.example:9/openapi.yaml", 1))
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := run(t, "inventory", "-c", p)
	if code != 2 || !strings.Contains(errOut, "scope") {
		t.Errorf("out-of-scope spec: exit %d %q", code, errOut)
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := run(t, "version")
	if code != 0 || strings.TrimSpace(out) != "authdiff 1.2.3 (commit abc123, built 2026-11-20)" {
		t.Errorf("exit %d out %q", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	if code, _, _ := run(t, "scan", "--no-such-flag"); code != 2 {
		t.Errorf("unknown flag: exit %d", code)
	}
	if code, _, _ := run(t, "nope"); code != 2 {
		t.Errorf("unknown command: exit %d", code)
	}
	if code, _, _ := run(t, "--log-format", "xml", "version"); code != 2 {
		t.Errorf("bad log format: exit %d", code)
	}
	if code, _, _ := run(t, "scan", "-c", filepath.Join(t.TempDir(), "missing.yaml")); code != 2 {
		t.Errorf("missing config: exit %d", code)
	}
}

func TestVerboseJSONLogs(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	code, _, errOut := run(t, "-v", "--log-format", "json", "scan", "-c", p)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(errOut), "\n")
	var sawDebug bool
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("non-JSON log line %q", l)
		}
		if m["level"] == "DEBUG" {
			sawDebug = true
		}
	}
	if !sawDebug {
		t.Errorf("-v produced no debug lines: %q", errOut)
	}
}
