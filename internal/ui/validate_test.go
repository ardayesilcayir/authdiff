package ui

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidProfileName(t *testing.T) {
	for _, n := range []string{"a", "admin", "alice", "bob", "anonymous", "staging-admin", "u2", strings.Repeat("a", 32)} {
		if !ValidProfileName(n) {
			t.Errorf("ValidProfileName(%q) = false", n)
		}
	}
	for _, n := range []string{"", "1a", "-a", "A", "a_b", "a.b", "a b", strings.Repeat("a", 33)} {
		if ValidProfileName(n) {
			t.Errorf("ValidProfileName(%q) = true", n)
		}
	}
}

func collidingProject() *Project {
	p := sampleProject()
	p.Profiles = append(p.Profiles,
		ProfileDef{Name: "a-b", Role: "user", AuthType: "bearer"},
		ProfileDef{Name: "a_b", Role: "user", AuthType: "bearer"})
	return p
}

func TestValidateProfileNamesCollision(t *testing.T) {
	if err := ValidateProfileNames(sampleProject()); err != nil {
		t.Fatalf("sample project: %v", err)
	}
	p := collidingProject()
	err := ValidateProfileNames(p)
	if err == nil || !strings.Contains(err.Error(), `"a-b"`) || !strings.Contains(err.Error(), `"a_b"`) {
		t.Fatalf("err = %v, want both profile names", err)
	}
	sec := NewSecrets()
	sec.Set(p.Name, "a-b", Secret{Token: "t1"})
	sec.Set(p.Name, "a_b", Secret{Token: "t2"})
	if _, err := BuildConfig(p, sec, ""); err == nil || !strings.Contains(err.Error(), "a_b") {
		t.Errorf("BuildConfig err = %v", err)
	}
	if _, err := PlaceholderConfig(p); err == nil {
		t.Error("PlaceholderConfig accepted colliding profiles")
	}
	if err := WriteExportZip(&bytes.Buffer{}, newTestStore(t), p); err == nil {
		t.Error("export accepted colliding profiles")
	}

	dup := sampleProject()
	dup.Profiles = append(dup.Profiles, ProfileDef{Name: "alice", AuthType: "none"})
	if err := ValidateProfileNames(dup); err == nil {
		t.Error("duplicate profile name accepted")
	}
}

func TestEnvVarsDeduped(t *testing.T) {
	got := envVars(collidingProject())
	seen := map[string]bool{}
	for _, v := range got {
		if seen[v] {
			t.Errorf("envVars repeats %q: %v", v, got)
		}
		seen[v] = true
	}
}

func TestSpecFileChecked(t *testing.T) {
	st := newTestStore(t)
	for _, bad := range []string{"../../x", "project.json", demoSecretsFile, "spec.txt", `..\x`} {
		p := sampleProject()
		p.SpecFile = bad
		if err := st.Save(p); err == nil {
			t.Errorf("Save accepted SpecFile %q", bad)
		}
		if _, err := BuildConfig(p, NewSecrets(), st.Dir(p.Name)); err == nil || !strings.Contains(err.Error(), "spec") {
			t.Errorf("BuildConfig SpecFile %q: err = %v", bad, err)
		}
		if _, err := PlaceholderConfig(p); err == nil {
			t.Errorf("PlaceholderConfig accepted SpecFile %q", bad)
		}
		if err := WriteExportZip(&bytes.Buffer{}, st, p); err == nil {
			t.Errorf("export accepted SpecFile %q", bad)
		}
	}
	// A tampered project.json is refused on read.
	p := sampleProject()
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(st.Dir(p.Name), projectFile)
	b, _ := os.ReadFile(path) //nolint:gosec // G304: test temp dir
	b = bytes.Replace(b, []byte(`"name": "staging-api",`), []byte(`"name": "staging-api", "specFile": "../../x",`), 1)
	if err := os.WriteFile(path, b, 0o600); err != nil { //nolint:gosec // G703: test temp dir
		t.Fatal(err)
	}
	if _, err := st.Get(p.Name); err == nil {
		t.Error("Get accepted a tampered SpecFile")
	}
	for _, ok := range []string{"", "spec.yaml", "spec.json"} {
		if err := checkSpecFile(ok); err != nil {
			t.Errorf("checkSpecFile(%q) = %v", ok, err)
		}
	}
}

func TestProxyCredentialsRejected(t *testing.T) {
	st := newTestStore(t)
	p := sampleProject()
	p.Safety.Proxy = "http://user:s3cret-pw@proxy.local:8080"
	err := st.Save(p)
	if err == nil {
		t.Fatal("Save accepted a proxy with credentials")
	}
	if strings.Contains(err.Error(), "s3cret-pw") || strings.Contains(err.Error(), "proxy.local") {
		t.Errorf("error echoes the proxy URL: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(st.Dir(p.Name), projectFile)); statErr == nil {
		t.Error("project.json written despite the error")
	}
	p.Safety.Proxy = "http://user@proxy.local:8080"
	if err := st.Save(p); err == nil {
		t.Error("Save accepted a proxy with a user name")
	}
	p.Safety.Proxy = "http://proxy.local:8080"
	if err := st.Save(p); err != nil {
		t.Errorf("plain proxy rejected: %v", err)
	}
}
