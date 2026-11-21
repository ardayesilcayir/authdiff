package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	specKey = "spec-query-key-SECRET-9876"
	baseKey = "base-userinfo-SECRET-5432"
)

func TestDryRunURLSpecDownloadsOnlySpec(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	editConfig(t, p, "./openapi.yaml", api.URL+"/openapi.yaml")
	code, out, errOut := run(t, "scan", "-c", p, "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	paths, uas := api.seen()
	if len(paths) != 1 || paths[0] != "/openapi.yaml" {
		t.Errorf("dry run requests = %v, want exactly the spec download", paths)
	}
	if len(uas) == 1 && !strings.HasPrefix(uas[0], "authdiff/1.2.3 ") {
		t.Errorf("spec download User-Agent = %q", uas[0])
	}
	if !strings.Contains(errOut, "dry run: downloading spec") {
		t.Errorf("no download log: %q", errOut)
	}
	if !strings.Contains(out, "AD-BOLA-001") {
		t.Errorf("plan = %q", out)
	}
}

func TestDryRunHelpMentionsSpecDownload(t *testing.T) {
	_, out, _ := run(t, "scan", "--help")
	if !strings.Contains(out, "except downloading the spec when target.spec is a URL") {
		t.Errorf("--dry-run help = %q", out)
	}
}

func TestScanURLSpecUserAgent(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	editConfig(t, p, "./openapi.yaml", "HTTP"+strings.TrimPrefix(api.URL, "http")+"/openapi.yaml")
	if code, _, errOut := run(t, "scan", "-c", p); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	paths, uas := api.seen()
	for i, pth := range paths {
		if !strings.HasPrefix(uas[i], "authdiff/1.2.3 (+https://github.com/ardayesilcayir/authdiff)") {
			t.Errorf("%s sent with User-Agent %q", pth, uas[i])
		}
	}
	if len(paths) == 0 || paths[0] != "/openapi.yaml" {
		t.Errorf("upper-case scheme spec not downloaded: %v", paths)
	}
}

// secretProject points the spec URL and baseUrl at env-expanded secrets.
func secretProject(t *testing.T, api *miniAPI, specPath string) string {
	t.Helper()
	p := writeProject(t, api, "")
	t.Setenv("AD_SPEC_KEY", specKey)
	t.Setenv("AD_BASE_KEY", baseKey)
	editConfig(t, p,
		"./openapi.yaml", `"http://scanner:${env:AD_BASE_KEY}@`+api.host()+specPath+"?api_key=${env:AD_SPEC_KEY}&v=1"+`"`)
	return p
}

func assertNoSecret(t *testing.T, where, s string) {
	t.Helper()
	for _, k := range []string{specKey, baseKey} {
		if strings.Contains(s, k) {
			t.Errorf("%s leaks secret %q", where, k)
		}
	}
}

func TestURLSecretsNotLeaked(t *testing.T) {
	api := newMiniAPI(t)
	p := secretProject(t, api, "/openapi.yaml")
	dir := filepath.Join(t.TempDir(), "out")
	code, out, errOut := run(t, "-v", "scan", "-c", p, "--format", "terminal,json,sarif,html", "--output", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	assertNoSecret(t, "stdout", out)
	assertNoSecret(t, "stderr", errOut)
	for _, name := range []string{"results.json", "results.sarif", "report.html"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		assertNoSecret(t, name, string(data))
		if !strings.Contains(string(data), "api_key=****") {
			t.Errorf("%s: spec URL not shown in redacted form", name)
		}
	}

	_, _, errOut = run(t, "-v", "scan", "-c", p, "--dry-run")
	assertNoSecret(t, "dry-run stderr", errOut)
	_, out, errOut = run(t, "-v", "inventory", "-c", p, "--json")
	assertNoSecret(t, "inventory", out+errOut)
}

func TestURLSecretsNotLeakedInErrors(t *testing.T) {
	api := newMiniAPI(t)
	p := secretProject(t, api, "/missing.yaml")
	for _, args := range [][]string{
		{"-v", "scan", "-c", p},
		{"-v", "scan", "-c", p, "--dry-run"},
		{"-v", "inventory", "-c", p},
	} {
		code, out, errOut := run(t, args...)
		if code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
		if !strings.Contains(errOut, "unexpected status") {
			t.Errorf("%v: stderr %q lacks the spec error", args, errOut)
		}
		assertNoSecret(t, strings.Join(args, " "), out+errOut)
	}
}
