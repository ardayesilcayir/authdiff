package transport

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const someJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c29unNuT22EssY2bcYkOOSiQ"

// Server-issued JWTs (not in the config) are scrubbed from evidence.
func TestRedactorScrubsJWTs(t *testing.T) {
	d := newRedactor(nil)
	got := d.String(`{"access_token":"` + someJWT + `"}`)
	assert.NotContains(t, got, "eyJhbGciOiJIUzI1NiJ9")
	assert.Contains(t, got, `"****OSiQ"`)
	h := d.Headers(http.Header{"X-Token": {"Bearer " + someJWT}})
	assert.Equal(t, "Bearer ****OSiQ", h["X-Token"])
	assert.Equal(t, "plain eyJ text", d.String("plain eyJ text"), "non-JWT text is untouched")
	assert.False(t, strings.Contains(Redact("x "+someJWT, nil), "eyJhbGci"))
}
