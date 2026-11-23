package ui

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/finding"
)

const testToken = "tok-ALICE-0123456789-secret"

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := NewStore(filepath.Join(t.TempDir(), "projects"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// sampleProject is a valid, non-demo project with a bearer, a basic and an
// anonymous profile.
func sampleProject() *Project {
	return &Project{
		Name:         "staging-api",
		BaseURL:      "https://staging.example.com",
		SpecURL:      "https://staging.example.com/openapi.json",
		AllowHosts:   []string{"staging.example.com:443"},
		Acknowledged: true,
		Exclude:      []string{"DELETE /users/{id}"},
		Tags:         []string{"orders"},
		Profiles: []ProfileDef{
			{Name: "alice", Role: "user", AuthType: "bearer", Owns: map[string][]string{"orderId": {"1", "2"}},
				Identifiers: []string{"alice@example.com"}},
			{Name: "staging-admin", Role: "admin", AuthType: "basic"},
			{Name: "anonymous", Role: "none", AuthType: "none"},
		},
		Harvest:      []config.HarvestRule{{Endpoint: "GET /me/orders", Extract: map[string]string{"orderId": "$.items[*].id"}}},
		Safety:       SafetyDef{Rate: 3, Concurrency: 2, TimeoutSec: 7},
		Matrix:       map[string][]string{"GET /admin/*": {"admin"}},
		IgnoreFields: []string{"$.requestId"},
		Threshold:    0.9,
		Step:         "profiles",
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"a", "staging-api", "0", "a-b-c-1", strings.Repeat("a", 63)} {
		if !ValidName(n) {
			t.Errorf("ValidName(%q) = false, want true", n)
		}
	}
	for _, n := range []string{"", "../x", "A", "-a", "a/b", "a.b", "a b", `a\b`, strings.Repeat("a", 64)} {
		if ValidName(n) {
			t.Errorf("ValidName(%q) = true, want false", n)
		}
	}
}

func TestStoreRejectsInvalidNames(t *testing.T) {
	st := newTestStore(t)
	if err := st.Save(&Project{Name: "../x"}); err == nil {
		t.Error("Save(../x) succeeded")
	}
	if _, err := st.Get("../x"); err == nil {
		t.Error("Get(../x) succeeded")
	}
	if _, err := st.SaveSpec("../x", strings.NewReader("{}"), ".json"); err == nil {
		t.Error("SaveSpec(../x) succeeded")
	}
	if err := st.AppendIgnore("../x", "0123456789ab", "r"); err == nil {
		t.Error("AppendIgnore(../x) succeeded")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	st := newTestStore(t)
	p := sampleProject()
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	if p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		t.Fatal("Save did not set timestamps")
	}
	got, err := st.Get(p.Name)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(filepath.Join(st.Dir(p.Name), "project.json"))
	if !bytes.Contains(a, []byte(`"baseUrl"`)) || !bytes.Contains(a, []byte(`"allowHosts"`)) {
		t.Errorf("project.json is not camelCase:\n%s", a)
	}
	if !got.CreatedAt.Equal(p.CreatedAt) || got.Name != p.Name || got.Profiles[0].Owns["orderId"][1] != "2" ||
		got.Safety.TimeoutSec != 7 || got.Matrix["GET /admin/*"][0] != "admin" || got.Step != "profiles" {
		t.Errorf("round trip mismatch: %+v", got)
	}

	// A second save keeps CreatedAt and moves UpdatedAt.
	created := got.CreatedAt
	time.Sleep(2 * time.Millisecond)
	if err := st.Save(got); err != nil {
		t.Fatal(err)
	}
	if !got.CreatedAt.Equal(created) || !got.UpdatedAt.After(created) {
		t.Errorf("timestamps after resave: created %v updated %v", got.CreatedAt, got.UpdatedAt)
	}

	if _, err := st.Get("missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Get(missing) err = %v, want ErrNotExist", err)
	}
}

func TestListNewestFirst(t *testing.T) {
	st := newTestStore(t)
	for _, n := range []string{"first", "second", "third"} {
		if err := st.Save(&Project{Name: n}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Directories that are not projects are skipped.
	_ = os.MkdirAll(filepath.Join(st.root, "not-a-project"), 0o700)
	_ = os.MkdirAll(filepath.Join(st.root, "Bad.Name"), 0o700)
	_ = os.WriteFile(filepath.Join(st.root, "stray.txt"), []byte("x"), 0o600)
	_ = os.MkdirAll(filepath.Join(st.root, "corrupt"), 0o700)
	_ = os.WriteFile(filepath.Join(st.root, "corrupt", "project.json"), []byte("{"), 0o600)

	list, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range list {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "third,second,first" {
		t.Errorf("List order = %v", names)
	}
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are not enforced on Windows")
	}
	st := newTestStore(t)
	p := sampleProject()
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveSpec(p.Name, strings.NewReader("openapi: 3.0.0"), ".yml"); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendIgnore(p.Name, "0123456789ab", "known"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{st.root, st.Dir(p.Name)} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode %v, want 0700", d, fi.Mode().Perm())
		}
	}
	for _, f := range []string{"project.json", "spec.yaml", ".authdiff-ignore"} {
		fi, err := os.Stat(filepath.Join(st.Dir(p.Name), f))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", f, fi.Mode().Perm())
		}
	}
}

func TestSaveSpec(t *testing.T) {
	st := newTestStore(t)
	if err := st.Save(&Project{Name: "p"}); err != nil {
		t.Fatal(err)
	}
	name, err := st.SaveSpec("p", strings.NewReader("{}"), ".JSON")
	if err != nil || name != "spec.json" {
		t.Fatalf("SaveSpec json = %q, %v", name, err)
	}
	name, err = st.SaveSpec("p", strings.NewReader("openapi: 3.0.0"), "yml")
	if err != nil || name != "spec.yaml" {
		t.Fatalf("SaveSpec yml = %q, %v", name, err)
	}
	if _, err := os.Stat(filepath.Join(st.Dir("p"), "spec.json")); !errors.Is(err, os.ErrNotExist) {
		t.Error("old spec.json was not removed")
	}
	if b, _ := os.ReadFile(filepath.Join(st.Dir("p"), "spec.yaml")); string(b) != "openapi: 3.0.0" {
		t.Errorf("spec.yaml = %q", b)
	}
	if _, err := st.SaveSpec("p", strings.NewReader("x"), ".txt"); err == nil {
		t.Error("SaveSpec(.txt) succeeded")
	}
}

func TestSaveSpecTooLarge(t *testing.T) {
	st := newTestStore(t)
	if err := st.Save(&Project{Name: "p"}); err != nil {
		t.Fatal(err)
	}
	big := bytes.NewReader(make([]byte, maxSpecBytes+1))
	if _, err := st.SaveSpec("p", big, ".json"); err == nil {
		t.Fatal("SaveSpec accepted a spec over 10 MiB")
	}
	if _, err := os.Stat(filepath.Join(st.Dir("p"), "spec.json")); !errors.Is(err, os.ErrNotExist) {
		t.Error("oversized spec was written")
	}
	exact := bytes.NewReader(make([]byte, maxSpecBytes))
	if _, err := st.SaveSpec("p", exact, ".json"); err != nil {
		t.Errorf("SaveSpec rejected exactly 10 MiB: %v", err)
	}
}

func TestAppendIgnore(t *testing.T) {
	st := newTestStore(t)
	if err := st.Save(&Project{Name: "p"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendIgnore("p", "0123456789ab", "accepted\nrisk # yes"); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendIgnore("p", "bbbbbbbbbbbb", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendIgnore("p", "0123456789ab", "again"); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendIgnore("p", "nothex", "x"); err == nil {
		t.Error("AppendIgnore accepted an invalid ID")
	}
	path := filepath.Join(st.Dir("p"), ".authdiff-ignore")
	b, err := finding.LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	fs := b.Apply([]finding.Finding{{ID: "0123456789ab"}, {ID: "bbbbbbbbbbbb"}, {ID: "cccccccccccc"}})
	if !fs[0].Suppressed || !fs[1].Suppressed || fs[2].Suppressed {
		t.Errorf("suppressed = %v %v %v", fs[0].Suppressed, fs[1].Suppressed, fs[2].Suppressed)
	}
	raw, _ := os.ReadFile(path) //nolint:gosec // G304: test temp dir
	if strings.Count(string(raw), "0123456789ab") != 1 {
		t.Errorf("duplicate ID written:\n%s", raw)
	}
}

func TestRunsDir(t *testing.T) {
	st := newTestStore(t)
	if got, want := st.RunsDir("p"), filepath.Join(st.Dir("p"), "runs"); got != want {
		t.Errorf("RunsDir = %q, want %q", got, want)
	}
}

func TestSecrets(t *testing.T) {
	sec := NewSecrets()
	if _, ok := sec.Get("p", "alice"); ok {
		t.Fatal("empty Secrets returned a value")
	}
	sec.Set("p", "alice", Secret{Token: "abcdefgh1234"})
	sec.Set("p", "bob", Secret{Username: "bob", Password: "short"})
	if s, ok := sec.Get("p", "alice"); !ok || s.Token != "abcdefgh1234" {
		t.Errorf("Get = %+v, %v", s, ok)
	}
	m := sec.Masked("p", "alice")
	if m["token"] != "•••• 1234" || len(m) != 1 {
		t.Errorf("Masked(alice) = %v", m)
	}
	m = sec.Masked("p", "bob")
	if m["username"] != "••••" || m["password"] != "••••" {
		t.Errorf("Masked(bob) = %v", m)
	}
	if len(sec.Masked("p", "nobody")) != 0 {
		t.Error("Masked(nobody) not empty")
	}
}

func TestMissing(t *testing.T) {
	sec := NewSecrets()
	p := sampleProject()
	got := sec.Missing(p)
	if strings.Join(got, ",") != "alice,staging-admin" {
		t.Errorf("Missing = %v", got)
	}
	t.Setenv("AUTHDIFF_ALICE_TOKEN", "from-env")
	sec.Set(p.Name, "staging-admin", Secret{Username: "admin"})
	if got := sec.Missing(p); strings.Join(got, ",") != "staging-admin" {
		t.Errorf("Missing with env and partial basic = %v", got)
	}
	sec.Set(p.Name, "staging-admin", Secret{Username: "admin", Password: "pw"})
	if got := sec.Missing(p); len(got) != 0 {
		t.Errorf("Missing = %v, want none", got)
	}
}

func TestEnvName(t *testing.T) {
	cases := map[[2]string]string{
		{"staging-admin", "token"}: "AUTHDIFF_STAGING_ADMIN_TOKEN",
		{"alice", "password"}:      "AUTHDIFF_ALICE_PASSWORD",
		{"Bob.2", "username"}:      "AUTHDIFF_BOB_2_USERNAME",
	}
	for in, want := range cases {
		if got := EnvName(in[0], in[1]); got != want {
			t.Errorf("EnvName(%q,%q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestNoSecretOnDisk(t *testing.T) {
	st := newTestStore(t)
	sec := NewSecrets()
	p := sampleProject()
	sec.Set(p.Name, "alice", Secret{Token: testToken})
	sec.Set(p.Name, "staging-admin", Secret{Username: "admin-user", Password: "pw-0123456789-secret"})
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveSpec(p.Name, strings.NewReader("{}"), ".json"); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendIgnore(p.Name, "0123456789ab", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildConfig(p, sec, st.Dir(p.Name)); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, st.root, testToken, "admin-user", "pw-0123456789-secret")
}

func assertNoSecrets(t *testing.T, root string, secrets ...string) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path) //nolint:gosec // G304: test temp dir
		if err != nil {
			return err
		}
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("%s contains secret %q", path, s)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
