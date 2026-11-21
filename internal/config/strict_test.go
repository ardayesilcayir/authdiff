package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const strictBase = `version: 1
target: { baseUrl: "http://localhost:8000", spec: ./openapi.json }
scope: { allowHosts: ["localhost:8000"], acknowledgeAuthorization: true }
profiles:
  alice: { role: user, auth: { type: bearer, token: "${env:AD_STRICT_TOKEN}" } }
`

// Typos in keys fail loudly instead of silently using a default.
func TestParseRejectsUnknownKeys(t *testing.T) {
	t.Setenv("AD_STRICT_TOKEN", "tok-strict-123456")
	_, err := Parse([]byte(strictBase + "safety: { allowDestructve: true }\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowDestructve")
	_, err = Parse([]byte(strictBase))
	require.NoError(t, err)
}

// A decode error that quotes an expanded env value never shows the secret.
func TestParseErrorsScrubEnvValues(t *testing.T) {
	secret := "s3cr3t-token-value-9876"
	t.Setenv("AD_STRICT_TOKEN", secret)
	// The token lands where a number is expected, so yaml quotes it.
	bad := strictBase + "safety: { rate: ${env:AD_STRICT_TOKEN} }\n"
	_, err := Parse([]byte(bad))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)
	assert.NotContains(t, err.Error(), secret[:7], "yaml's truncated quote is scrubbed too")
	assert.Contains(t, err.Error(), "****9876")
	// Validation errors are scrubbed too.
	t.Setenv("AD_STRICT_TYPE", "magic-auth-type-secret")
	bad2 := strings.Replace(strictBase, "type: bearer", "type: ${env:AD_STRICT_TYPE}", 1)
	_, err = Parse([]byte(bad2))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "magic-auth-type-secret")
}

func TestBaseURLUserinfoRejected(t *testing.T) {
	c := validConfig()
	c.Target.BaseURL = "http://user:pw-1234@localhost:8000"
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credentials")
	assert.NotContains(t, err.Error(), "pw-1234")
}

func TestSecretsIncludeBasicUserAndEncoding(t *testing.T) {
	c := validConfig()
	c.Profiles["bob"] = Profile{Auth: Auth{Type: "basic", Username: "bobuser", Password: "pw-1234"}}
	s := c.Secrets()
	assert.Contains(t, s, "bobuser")
	assert.Contains(t, s, "Ym9idXNlcjpwdy0xMjM0") // base64("bobuser:pw-1234")
}
