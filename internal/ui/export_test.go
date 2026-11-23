package ui

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/config"
)

// unzip extracts b into a temp dir and returns it plus the entry names.
func unzip(t *testing.T, b []byte) (string, []string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var names []string
	for _, f := range zr.File {
		if strings.ContainsAny(f.Name, `/\`) || f.FileInfo().IsDir() {
			t.Errorf("zip entry %q is not a top-level file", f.Name)
			continue
		}
		names = append(names, f.Name)
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f.Name), data, 0o600); err != nil { //nolint:gosec // G305: names checked above to be top-level
			t.Fatal(err)
		}
	}
	return dir, names
}

// setEnvExample sets every NAME= line of .env.example to a dummy value.
func setEnvExample(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".env.example")) //nolint:gosec // G304: test temp dir
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		name, val, ok := strings.Cut(line, "=")
		if !ok || val != "" {
			t.Errorf(".env.example line %q is not NAME=", line)
		}
		names = append(names, name)
		t.Setenv(name, "dummy-"+name)
	}
	return names
}

func TestExportZipRoundTrip(t *testing.T) {
	st := newTestStore(t)
	sec := NewSecrets()
	p := sampleProject()
	sec.Set(p.Name, "alice", Secret{Token: testToken})
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	name, err := st.SaveSpec(p.Name, strings.NewReader("openapi: 3.0.0\n"), ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	p.SpecFile = name
	if err := st.AppendIgnore(p.Name, "0123456789ab", "accepted"); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := WriteExportZip(&buf, st, p); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte(testToken)) {
		t.Fatal("zip contains a token")
	}
	dir, names := unzip(t, buf.Bytes())
	want := "authdiff.yaml,spec.yaml,.authdiff-ignore,.env.example"
	if strings.Join(names, ",") != want {
		t.Errorf("entries = %v, want %s", names, want)
	}
	vars := setEnvExample(t, dir)
	if strings.Join(vars, ",") != "AUTHDIFF_ALICE_TOKEN,AUTHDIFF_STAGING_ADMIN_PASSWORD,AUTHDIFF_STAGING_ADMIN_USERNAME" {
		t.Errorf(".env.example vars = %v", vars)
	}
	c, err := config.Load(filepath.Join(dir, "authdiff.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Target.Spec != "spec.yaml" || c.Profiles["alice"].Auth.Token != "dummy-AUTHDIFF_ALICE_TOKEN" {
		t.Errorf("loaded config = %+v", c)
	}
	if ign, _ := os.ReadFile(filepath.Join(dir, ".authdiff-ignore")); !strings.Contains(string(ign), "0123456789ab") { //nolint:gosec // G304: test temp dir
		t.Errorf(".authdiff-ignore = %q", ign)
	}
}

func TestExportZipURLSpecNoIgnore(t *testing.T) {
	st := newTestStore(t)
	p := sampleProject()
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteExportZip(&buf, st, p); err != nil {
		t.Fatal(err)
	}
	dir, names := unzip(t, buf.Bytes())
	if strings.Join(names, ",") != "authdiff.yaml,.authdiff-ignore,.env.example" {
		t.Errorf("entries = %v", names)
	}
	setEnvExample(t, dir)
	c, err := config.Load(filepath.Join(dir, "authdiff.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Target.Spec != p.SpecURL {
		t.Errorf("Spec = %q", c.Target.Spec)
	}

	p.BaseURL = ""
	if err := WriteExportZip(&bytes.Buffer{}, st, p); err == nil {
		t.Error("invalid project exported")
	}
}

func TestExportZipDemo(t *testing.T) {
	st := newTestStore(t)
	p, err := EnsureDemo(st, NewSecrets(), "http://localhost:8000")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteExportZip(&buf, st, p); err != nil {
		t.Fatal(err)
	}
	dir, names := unzip(t, buf.Bytes())
	if strings.Join(names, ",") != "authdiff.yaml,.authdiff-ignore,.env.example,vuln-lab.env" {
		t.Errorf("entries = %v", names)
	}
	if vars := setEnvExample(t, dir); strings.Join(vars, ",") != "ADMIN_TOKEN,ALICE_TOKEN,BOB_TOKEN" {
		t.Errorf("demo vars = %v", vars)
	}
	if _, err := config.Load(filepath.Join(dir, "authdiff.yaml")); err != nil {
		t.Fatal(err)
	}
	lab, _ := os.ReadFile(filepath.Join(dir, "vuln-lab.env")) //nolint:gosec // G304: test temp dir
	if !strings.Contains(string(lab), "ALICE_TOKEN=eyJ") {
		t.Errorf("vuln-lab.env = %q", lab)
	}
}
