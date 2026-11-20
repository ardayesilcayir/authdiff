package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConfig() *Config {
	c := &Config{
		Version: 1,
		Target:  Target{BaseURL: "http://localhost:8000", Spec: "./openapi.json"},
		Scope:   Scope{AllowHosts: []string{"localhost:8000"}, AcknowledgeAuthorization: true},
		Profiles: map[string]Profile{
			"alice": {Name: "alice", Auth: Auth{Type: "bearer", Token: "tok"}},
		},
	}
	c.ApplyDefaults()
	return c
}

func TestLoadExample(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "adm-secret-1234")
	t.Setenv("ALICE_TOKEN", "alice-secret-1234")
	t.Setenv("BOB_TOKEN", "bob-secret-1234")

	c, err := Load("testdata/example.yaml")
	require.NoError(t, err)
	assert.Len(t, c.Profiles, 4)
	assert.Equal(t, []string{"101", "102"}, c.Profiles["alice"].Owns["orderId"])
	assert.Equal(t, []string{"2"}, c.Profiles["alice"].Owns["userId"])
	assert.Equal(t, 5.0, c.Safety.Rate)
	assert.Equal(t, 0.85, c.Compare.SimilarityThreshold)
	assert.Equal(t, "alice", c.Profiles["alice"].Name)
	assert.Equal(t, "adm-secret-1234", c.Profiles["admin"].Auth.Token)
	assert.Equal(t, 10*time.Second, c.Safety.Timeout)
	assert.Equal(t, []string{"admin", "owner"}, c.Matrix["GET /orders/{orderId}"].Allow)
	assert.Equal(t, "GET /me/orders", c.Harvest[0].Endpoint)
	assert.Equal(t, "high", c.Output.FailOn)
	assert.Equal(t, []string{"admin", "alice", "anonymous", "bob"}, c.ProfileNames())
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("testdata/nope.yaml")
	require.Error(t, err)
}

func TestParseBadYAML(t *testing.T) {
	_, err := Parse([]byte("version: [unclosed"))
	require.Error(t, err)
}

func TestEnvMissing(t *testing.T) {
	_, err := Parse([]byte("version: 1\nprofiles:\n  a:\n    auth: { type: bearer, token: \"${env:NOPE_TOKEN}\" }\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOPE_TOKEN")
}

func TestDefaults(t *testing.T) {
	c, err := Load("testdata/minimal.yaml")
	require.NoError(t, err)
	assert.Equal(t, 5.0, c.Safety.Rate)
	assert.Equal(t, 4, c.Safety.Concurrency)
	assert.Equal(t, 10*time.Second, c.Safety.Timeout)
	assert.Equal(t, int64(5242880), c.Safety.MaxResponseBytes)
	assert.Equal(t, []string{"terminal", "json"}, c.Output.Formats)
	assert.Equal(t, "./authdiff-out", c.Output.Dir)
	assert.Equal(t, 0.85, c.Compare.SimilarityThreshold)
	assert.False(t, c.Safety.AllowDestructive)
}

func TestOwnsAcceptsNumbersAndStrings(t *testing.T) {
	c, err := Parse([]byte(`version: 1
target: { baseUrl: "http://h", spec: s }
scope: { allowHosts: ["h"], acknowledgeAuthorization: true }
profiles:
  a:
    auth: { type: none }
    owns: { id: [101, "abc"] }
`))
	require.NoError(t, err)
	assert.Equal(t, []string{"101", "abc"}, c.Profiles["a"].Owns["id"])
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		mut  func(c *Config)
		want string
	}{
		{"version", func(c *Config) { c.Version = 2 }, "version"},
		{"empty baseUrl", func(c *Config) { c.Target.BaseURL = "" }, "baseUrl"},
		{"empty spec", func(c *Config) { c.Target.Spec = "" }, "spec"},
		{"empty allowHosts", func(c *Config) { c.Scope.AllowHosts = nil }, "allowHosts"},
		{"not acknowledged", func(c *Config) { c.Scope.AcknowledgeAuthorization = false }, "acknowledgeAuthorization"},
		{"host not allowed", func(c *Config) { c.Scope.AllowHosts = []string{"other.com"} }, "allowHosts"},
		{"no profiles", func(c *Config) { c.Profiles = nil }, "profile"},
		{"unknown auth", func(c *Config) { c.Profiles["alice"] = Profile{Auth: Auth{Type: "magic"}} }, "magic"},
		{"bearer empty token", func(c *Config) { c.Profiles["alice"] = Profile{Auth: Auth{Type: "bearer"}} }, "token"},
		{"rate", func(c *Config) { c.Safety.Rate = 0 }, "rate"},
		{"concurrency", func(c *Config) { c.Safety.Concurrency = 0 }, "concurrency"},
		{"threshold high", func(c *Config) { c.Compare.SimilarityThreshold = 1.5 }, "similarityThreshold"},
		{"threshold low", func(c *Config) { c.Compare.SimilarityThreshold = -0.1 }, "similarityThreshold"},
		{"failOn", func(c *Config) { c.Output.FailOn = "bogus" }, "failOn"},
		{"format", func(c *Config) { c.Output.Formats = []string{"pdf"} }, "pdf"},
		{"bad baseUrl", func(c *Config) { c.Target.BaseURL = "://x" }, "baseUrl"},
		{"apikey empty token", func(c *Config) { c.Profiles["alice"] = Profile{Auth: Auth{Type: "apikey", Name: "k"}} }, "token"},
		{"apikey bad in", func(c *Config) { c.Profiles["alice"] = Profile{Auth: Auth{Type: "apikey", Token: "t", In: "body"}} }, "auth.in"},
		{"basic fields", func(c *Config) { c.Profiles["alice"] = Profile{Auth: Auth{Type: "basic"}} }, "username"},
		{"cookie empty token", func(c *Config) { c.Profiles["alice"] = Profile{Auth: Auth{Type: "cookie", Name: "s"}} }, "token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mut(c)
			err := Validate(c)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestValidateOK(t *testing.T) {
	c := validConfig()
	c.Output.FailOn = "high"
	c.Output.Formats = []string{"terminal", "json", "sarif", "html"}
	require.NoError(t, Validate(c))
	c.Output.FailOn = ""
	require.NoError(t, Validate(c))
}

func TestValidateNamelessCookieAndApikey(t *testing.T) {
	c := validConfig()
	c.Profiles["alice"] = Profile{Auth: Auth{Type: "cookie", Token: "session=abc; csrf=xyz"}}
	c.Profiles["bob"] = Profile{Auth: Auth{Type: "apikey", Token: "k"}}
	require.NoError(t, Validate(c))
}

func TestValidateJoinsAllErrors(t *testing.T) {
	c := validConfig()
	c.Version = 3
	c.Safety.Rate = -1
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version")
	assert.Contains(t, err.Error(), "rate")
}

func TestHostMatching(t *testing.T) {
	cases := []struct {
		base  string
		allow []string
		ok    bool
	}{
		{"http://LOCALHOST:8000", []string{"localhost:8000"}, true},
		{"https://example.com", []string{"example.com"}, true},
		{"https://example.com", []string{"example.com:443"}, true},
		{"http://example.com", []string{"example.com:80"}, true},
		{"https://example.com.evil.io", []string{"example.com"}, false},
		{"http://localhost:9000", []string{"localhost:8000"}, false},
	}
	for _, tc := range cases {
		c := validConfig()
		c.Target.BaseURL = tc.base
		c.Scope.AllowHosts = tc.allow
		err := Validate(c)
		if tc.ok {
			assert.NoError(t, err, tc.base)
		} else {
			assert.Error(t, err, tc.base)
		}
	}
}

func TestSecrets(t *testing.T) {
	c := validConfig()
	c.Profiles["bob"] = Profile{Auth: Auth{Type: "basic", Username: "bob", Password: "pw-1234"}}
	c.Profiles["anon"] = Profile{Auth: Auth{Type: "none"}}
	assert.ElementsMatch(t, []string{"tok", "pw-1234"}, c.Secrets())
}

func TestProfileNamesSorted(t *testing.T) {
	c := validConfig()
	c.Profiles["bob"] = Profile{}
	c.Profiles["admin"] = Profile{}
	assert.Equal(t, []string{"admin", "alice", "bob"}, c.ProfileNames())
}
