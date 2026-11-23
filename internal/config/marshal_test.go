package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalRoundTrip(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "adm-secret-1234")
	t.Setenv("ALICE_TOKEN", "alice-secret-1234")
	t.Setenv("BOB_TOKEN", "bob-secret-1234")
	raw, err := os.ReadFile("testdata/example.yaml")
	require.NoError(t, err)
	first, err := Parse(raw)
	require.NoError(t, err)

	out, err := Marshal(first)
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "timeout: 10s")
	assert.NotContains(t, s, "name: alice", "profile name is the map key")
	assert.NotContains(t, s, "proxy:", "empty fields are omitted")
	assert.NotContains(t, s, "insecure:", "false fields are omitted")

	second, err := Parse(out)
	require.NoError(t, err)
	assert.Equal(t, first, second)
}

func TestMarshalKeepsEnvPlaceholder(t *testing.T) {
	c := validConfig()
	a := c.Profiles["alice"]
	a.Auth.Token = "${env:ALICE_TOKEN}"
	c.Profiles["alice"] = a

	out, err := Marshal(c)
	require.NoError(t, err)
	assert.Contains(t, string(out), "${env:ALICE_TOKEN}")

	t.Setenv("ALICE_TOKEN", "alice-secret-1234")
	p := filepath.Join(t.TempDir(), "authdiff.yaml")
	require.NoError(t, os.WriteFile(p, out, 0o600))
	loaded, err := Load(p)
	require.NoError(t, err)
	assert.Equal(t, "alice-secret-1234", loaded.Profiles["alice"].Auth.Token)
	assert.Equal(t, "alice", loaded.Profiles["alice"].Name)
}

func TestMarshalNil(t *testing.T) {
	_, err := Marshal(nil)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "nil"))
}

func TestCloneIsDeep(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "adm-secret-1234")
	t.Setenv("ALICE_TOKEN", "alice-secret-1234")
	t.Setenv("BOB_TOKEN", "bob-secret-1234")
	orig, err := Load("testdata/example.yaml")
	require.NoError(t, err)
	orig.Bodies = map[string]any{"POST /orders": map[string]any{"items": []any{"a", map[string]any{"k": 1}}}}
	orig.Rules.Dirs = make([]string, 1, 4)
	want, err := Load("testdata/example.yaml")
	require.NoError(t, err)
	want.Bodies = map[string]any{"POST /orders": map[string]any{"items": []any{"a", map[string]any{"k": 1}}}}
	want.Rules.Dirs = make([]string, 1, 4)

	c := orig.Clone()
	assert.Equal(t, orig, c)
	c.Scope.AllowHosts[0] = "x"
	c.Profiles["alice"].Owns["orderId"][0] = "x"
	p := c.Profiles["bob"]
	p.Role = "x"
	c.Profiles["bob"] = p
	c.Harvest[0].Extract["orderId"] = "x"
	c.Matrix["POST /orders"].Allow[0] = "x"
	c.Compare.IgnoreFields[0] = "x"
	c.Output.Formats[0] = "x"
	c.Bodies["POST /orders"].(map[string]any)["items"].([]any)[1].(map[string]any)["k"] = 2
	c.Rules.Dirs = append(c.Rules.Dirs, "x")
	a := c.Profiles["alice"]
	a.Identifiers = append(a.Identifiers, "x")
	a.Identifiers[0] = "y"
	c.Profiles["alice"] = a
	assert.Equal(t, want, orig)
	assert.Nil(t, (*Config)(nil).Clone())
}
