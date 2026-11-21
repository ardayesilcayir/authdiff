package rules

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

func TestLoadBuiltin(t *testing.T) {
	rs, err := LoadBuiltin()
	require.NoError(t, err)
	var ids []string
	for _, r := range rs {
		ids = append(ids, r.ID)
		assert.NotZero(t, r.CVSS, r.ID)
		assert.Equal(t, "docs/rules/"+r.ID+".md", r.Remediation)
	}
	sort.Strings(ids)
	assert.Equal(t, []string{"AD-BFLA-001", "AD-BOLA-001", "AD-BOLA-002", "AD-LEAK-001",
		"AD-MASS-001", "AD-MATRIX-001", "AD-METHOD-001", "AD-NOAUTH-001"}, ids)
}

const goodRule = `
id: AD-TEST-001
name: t
severity: high
steps:
  - {name: owner, as: owner, use: owner}
match: owner.ok
`

func writeRule(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "r.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func TestValidateErrors(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"bad id", "id: bad\nname: t\nseverity: high\nsteps: [{name: a, as: owner, use: owner}]\nmatch: a.ok\n", "id"},
		{"bad role", "id: AD-X-1\nname: t\nseverity: high\nsteps: [{name: a, as: root, use: owner}]\nmatch: a.ok\n", "as"},
		{"bad use", "id: AD-X-1\nname: t\nseverity: high\nsteps: [{name: a, as: owner, use: root}]\nmatch: a.ok\n", "use"},
		{"bad match", "id: AD-X-1\nname: t\nseverity: high\nsteps: [{name: a, as: owner, use: owner}]\nmatch: owner.status ==\n", "match"},
		{"ghost", "id: AD-X-1\nname: t\nseverity: high\nsteps: [{name: a, as: owner, use: owner}]\nmatch: ghost.ok\n", "match"},
		{"dup step", "id: AD-X-1\nname: t\nseverity: high\nsteps: [{name: a, as: owner, use: owner},{name: a, as: owner, use: owner}]\nmatch: a.ok\n", "steps"},
		{"bad step name", "id: AD-X-1\nname: t\nseverity: high\nsteps: [{name: A-b, as: owner, use: owner}]\nmatch: true\n", "steps"},
		{"bad severity", "id: AD-X-1\nname: t\nseverity: nope\nsteps: [{name: a, as: owner, use: owner}]\nmatch: a.ok\n", "severity"},
		{"bad kind", "id: AD-X-1\nname: t\nseverity: high\nkind: zzz\n", "kind"},
		{"no steps", "id: AD-X-1\nname: t\nseverity: high\nmatch: true\n", "steps"},
		{"no match", "id: AD-X-1\nname: t\nseverity: high\nsteps: [{name: a, as: owner, use: owner}]\n", "match"},
		{"bad victim", "id: AD-X-1\nname: t\nseverity: high\nvictim: zz\nsteps: [{name: a, as: owner, use: owner}]\nmatch: a.ok\n", "victim"},
		{"bad attacker", "id: AD-X-1\nname: t\nseverity: high\nattacker: zz\nsteps: [{name: a, as: owner, use: owner}]\nmatch: a.ok\n", "attacker"},
		{"bad conf", "id: AD-X-1\nname: t\nseverity: high\nsteps: [{name: a, as: owner, use: owner}]\nmatch: a.ok\nconfidence: {high: 'a.ok &&'}\n", "confidence.high"},
		{"not yaml", "id: [", "yaml"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadFile(writeRule(t, c.yaml))
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.want)
			assert.Contains(t, err.Error(), "r.yaml")
		})
	}
	_, err := LoadFile(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)
}

func TestRoleBraces(t *testing.T) {
	r, err := LoadFile(writeRule(t, `
id: AD-TEST-002
name: t
severity: low
steps:
  - {name: a, as: "{{owner}}", use: "{{owner.owns}}"}
match: a.ok
`))
	require.NoError(t, err)
	assert.Equal(t, "owner", r.Steps[0].As)
	assert.Equal(t, "owner", r.Steps[0].Use)
	assert.Equal(t, "a", r.Victim)
	assert.Equal(t, "a", r.Attacker)
	assert.Equal(t, finding.DefaultCVSS(finding.Low), r.CVSS)
	assert.Equal(t, "template", r.Kind)
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(goodRule), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "note.txt"), []byte("x"), 0o600))
	rs, err := LoadDir(dir)
	require.NoError(t, err)
	require.Len(t, rs, 1)
	assert.Contains(t, rs[0].Source, "a.yaml")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.yaml"), []byte("id: bad"), 0o600))
	_, err = LoadDir(dir)
	require.Error(t, err)
	_, err = LoadDir(filepath.Join(dir, "nope"))
	require.Error(t, err)
}

func builtin(t *testing.T, id string) *Rule {
	t.Helper()
	rs, err := LoadBuiltin()
	require.NoError(t, err)
	for i := range rs {
		if rs[i].ID == id {
			return &rs[i]
		}
	}
	t.Fatalf("rule %s not found", id)
	return nil
}

func step(status int, body string) StepEnv {
	return StepEnv{Sent: true, Status: status, OK: status >= 200 && status < 300, Body: body}
}

func TestEvalBOLA(t *testing.T) {
	r := builtin(t, "AD-BOLA-001")
	fn := Funcs{
		Similarity:    func(_, _ string) float64 { return 1.0 },
		Evidence:      func(string, []string) bool { return true },
		MatrixForbids: func(string) bool { return false },
	}
	ep := EndpointEnv{Method: "GET", Path: "/orders/{id}", Secured: true}
	env := func(owner, att, anon StepEnv) map[string]any {
		return NewEnv(map[string]StepEnv{"owner": owner, "attacker": att, "anon": anon}, ep, 0.85, nil, fn)
	}

	ok, conf, err := r.Eval(env(step(200, `{"a":1}`), step(200, `{"a":1}`), step(401, "")))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, finding.ConfHigh, conf)

	fn.Evidence = func(string, []string) bool { return false }
	ok, conf, err = r.Eval(NewEnv(map[string]StepEnv{"owner": step(200, "x"), "attacker": step(200, "x"), "anon": step(401, "")}, ep, 0.85, nil, fn))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, finding.ConfMedium, conf)

	ok, conf, err = r.Eval(env(step(200, "x"), step(200, "x"), step(200, "x")))
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, finding.Confidence(""), conf)

	ok, _, err = r.Eval(env(step(200, ""), step(200, "x"), step(401, "")))
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestEvalNoAuthMatrixAllows(t *testing.T) {
	r := builtin(t, "AD-NOAUTH-001")
	fn := Funcs{
		Evidence:     func(string, []string) bool { return true },
		MatrixAllows: func(s string) bool { return s == "anon" },
	}
	env := NewEnv(map[string]StepEnv{"ref": step(200, "x"), "anon": step(200, "x")},
		EndpointEnv{Secured: true}, 0.85, []string{"alice@example.com"}, fn)
	ok, _, err := r.Eval(env)
	require.NoError(t, err)
	assert.False(t, ok, "matrix allows anonymous: no finding")

	fn.MatrixAllows = nil // default: no matrix entry
	env = NewEnv(map[string]StepEnv{"ref": step(200, "x"), "anon": step(200, "x")},
		EndpointEnv{Secured: true}, 0.85, []string{"alice@example.com"}, fn)
	ok, conf, err := r.Eval(env)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, finding.ConfHigh, conf)
}

func TestEvalNoAuthAndBFLA(t *testing.T) {
	fn := Funcs{
		Similarity:    func(_, _ string) float64 { return 0 },
		Evidence:      func(string, []string) bool { return false },
		MatrixForbids: func(s string) bool { return s == "anon" },
	}
	r := builtin(t, "AD-NOAUTH-001")
	env := NewEnv(map[string]StepEnv{"ref": step(200, "x"), "anon": step(200, "x")}, EndpointEnv{}, 0.85, []string{"1"}, fn)
	ok, conf, err := r.Eval(env)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, finding.ConfMedium, conf)

	b := builtin(t, "AD-BFLA-001")
	env = NewEnv(map[string]StepEnv{"admin": {Sent: false}, "attacker": step(200, "x")}, EndpointEnv{}, 0.85, nil, fn)
	ok, _, err = b.Eval(env)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestEvalNonTemplateAndRuntimeError(t *testing.T) {
	m := builtin(t, "AD-MASS-001")
	ok, conf, err := m.Eval(nil)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, finding.ConfMedium, conf)
	assert.Equal(t, "AD-MASS-001", m.Meta().ID)
	assert.Equal(t, finding.High, m.Meta().Severity)

	r := builtin(t, "AD-BOLA-002")
	_, _, err = r.Eval(map[string]any{})
	assert.Error(t, err)
}

func TestMultilineMatch(t *testing.T) {
	r, err := LoadFile(writeRule(t, `
id: AD-TEST-003
name: t
severity: low
steps:
  - {name: a, as: owner, use: owner}
match: >
  a.ok &&
  a.status == 200
confidence:
  low: a.ok
`))
	require.NoError(t, err)
	ok, _, err := r.Eval(NewEnv(map[string]StepEnv{"a": step(200, "")}, EndpointEnv{}, 0.85, nil, Funcs{}))
	require.NoError(t, err)
	assert.True(t, ok)
}
