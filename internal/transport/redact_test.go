package transport

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedact(t *testing.T) {
	assert.Equal(t, "****5678", Redact("abcdefgh12345678", []string{"abcdefgh12345678"}))
	assert.Equal(t, "Bearer ****5678", Redact("Bearer abcdefgh12345678", []string{"abcdefgh12345678"}))
	assert.Equal(t, "pw=****", Redact("pw=abc123", []string{"abc123"}), "short secrets show only ****")
	assert.Equal(t, "****5678", Redact("12345678", []string{"12345678"}), "8 chars is long enough for a suffix")
	assert.Equal(t, "****", Redact("1234567", []string{"1234567"}))
	assert.Equal(t, "a=****5678&b=****5678", Redact("a=abcdefgh12345678&b=abcdefgh12345678", []string{"abcdefgh12345678"}))
	assert.Equal(t, "nothing here", Redact("nothing here", []string{"", "zzzzzzzzzz"}))
	assert.Equal(t, "unchanged", Redact("unchanged", nil))
}

func TestRedactOverlappingSecretsLongerFirst(t *testing.T) {
	assert.Equal(t, "x****ijklx", Redact("xabcdefghijklx", []string{"abcdefgh", "abcdefghijkl"}))
	assert.Equal(t, "x****ijklx", Redact("xabcdefghijklx", []string{"abcdefghijkl", "abcdefgh"}))
}

func TestRedactEncodedVariants(t *testing.T) {
	secret := "p@ss w/ord&1234"
	in := "http://h/?k=p%40ss+w%2Ford%261234 and /p@ss%20w%2Ford&1234 raw " + secret
	out := Redact(in, []string{secret})
	assert.NotContains(t, out, "ss")
	assert.NotContains(t, out, "w%2F")
	assert.Equal(t, 3, strings.Count(out, "****1234"))

	jsonSecret := `a"b<c>d-secret` //nolint:gosec // G101: test fixture, not a real credential
	for _, in := range []string{`{"k":"a\"b<c>d-secret"}`, `{"k":"a\"b<c>d-secret"}`} {
		out = Redact(in, []string{jsonSecret})
		assert.NotContains(t, out, "secret", in)
		assert.Contains(t, out, "****cret", in)
	}
}

func TestRedactHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer abcdefgh12345678")
	h.Set("Cookie", "sid=cookievalue-9999")
	h.Add("Set-Cookie", "a=1; Path=/")
	h.Add("Set-Cookie", "b=secretcookie-4321")
	h["X-API-Key"] = []string{"my-api-key-abcd"} // non-canonical map key
	h.Set("Location", "http://h/cb?token=tok_abcdef123456")
	h.Set("Content-Type", "application/json")
	h.Add("Accept", "text/html")
	h.Add("Accept", "application/json")
	h.Set("X-Short", "abc")

	got := RedactHeaders(h, []string{"tok_abcdef123456"})
	assert.Equal(t, "****5678", got["Authorization"])
	assert.Equal(t, "****9999", got["Cookie"])
	assert.Equal(t, "****4321", got["Set-Cookie"])
	assert.Equal(t, "****abcd", got["X-Api-Key"])
	assert.Equal(t, "http://h/cb?token=****3456", got["Location"])
	assert.Equal(t, "application/json", got["Content-Type"])
	assert.Equal(t, "text/html, application/json", got["Accept"])
	assert.Equal(t, "abc", got["X-Short"])
}

func TestRedactHeadersShortAlwaysMasked(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "short")
	got := RedactHeaders(h, nil)
	assert.Equal(t, "****", got["Authorization"])
	assert.Empty(t, RedactHeaders(nil, nil))
}
