package identity

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func apply(t *testing.T, a config.Auth) *http.Request {
	t.Helper()
	req := httptest.NewRequest("GET", "http://h/x", nil)
	(&Profile{Auth: a}).Apply(req)
	return req
}

func TestApplyAuth(t *testing.T) {
	r := apply(t, config.Auth{Type: "bearer", Token: "tok"})
	assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))

	r = apply(t, config.Auth{Type: "cookie", Token: "sid=abc; x=1"}) //nolint:gosec // G101: test fixture, not a real credential
	assert.Equal(t, "sid=abc; x=1", r.Header.Get("Cookie"))
	r = apply(t, config.Auth{Type: "cookie", Name: "sid", Token: "abc"})
	assert.Equal(t, "sid=abc", r.Header.Get("Cookie"))

	r = apply(t, config.Auth{Type: "apikey", Token: "k"})
	assert.Equal(t, "k", r.Header.Get("X-API-Key"))
	r = apply(t, config.Auth{Type: "apikey", Token: "k", Name: "X-Key", In: "header"})
	assert.Equal(t, "k", r.Header.Get("X-Key"))
	r = apply(t, config.Auth{Type: "apikey", Token: "k", In: "query"})
	assert.Equal(t, "k", r.URL.Query().Get("api_key"))
	r = apply(t, config.Auth{Type: "apikey", Token: "k", In: "query", Name: "key"})
	assert.Equal(t, "k", r.URL.Query().Get("key"))

	r = apply(t, config.Auth{Type: "basic", Username: "u", Password: "p"})
	u, p, ok := r.BasicAuth()
	assert.True(t, ok)
	assert.Equal(t, "u", u)
	assert.Equal(t, "p", p)

	r = apply(t, config.Auth{Type: "none"})
	assert.Empty(t, r.Header)
	r = apply(t, config.Auth{Type: "weird"})
	assert.Empty(t, r.Header)
}

func testCfg() *config.Config {
	return &config.Config{Profiles: map[string]config.Profile{
		"bob": {Name: "bob", Role: "user", Auth: config.Auth{Type: "bearer", Token: "b"}},
		"alice": {Name: "alice", Role: "admin", Auth: config.Auth{Type: "none"},
			Identifiers: []string{"alice@x.io", "7"},
			Owns:        map[string][]string{"userId": {"7", "8"}, "orderId": {"101", "102"}}},
	}}
}

func TestIdentifiers(t *testing.T) {
	ps := FromConfig(testCfg())
	require.Len(t, ps, 2)
	assert.Equal(t, "alice", ps[0].Name)
	assert.Equal(t, "bob", ps[1].Name)
	assert.Equal(t, []string{"7", "8", "alice@x.io"}, ps[0].Identifiers)
	assert.Empty(t, ps[1].Identifiers)
	assert.True(t, ps[0].IsAdmin())
	assert.False(t, ps[1].IsAdmin())
	assert.True(t, ps[0].IsAnonymous())
	assert.False(t, ps[1].IsAnonymous())
}

func TestPoolFromConfigAndHasAll(t *testing.T) {
	p := NewPool(testCfg())
	assert.Equal(t, []string{"101", "102"}, p.IDs("alice", "orderId"))
	assert.Nil(t, p.IDs("bob", "orderId"))
	assert.True(t, p.HasAll("alice", []string{"orderId", "userId"}))
	assert.False(t, p.HasAll("alice", []string{"orderId", "nope"}))
	assert.True(t, p.HasAll("bob", nil))
	got := p.IDs("alice", "orderId")
	got[0] = "zzz"
	assert.Equal(t, "101", p.IDs("alice", "orderId")[0], "IDs returns a copy")
}

func TestPoolAddDedup(t *testing.T) {
	p := NewPool(testCfg())
	p.Add("alice", "orderId", "102", "103", "103", "")
	assert.Equal(t, []string{"101", "102", "103"}, p.IDs("alice", "orderId"))
	p.Add("bob", "x", "1")
	assert.Equal(t, []string{"1"}, p.IDs("bob", "x"))
}

func TestPoolConcurrent(t *testing.T) {
	p := NewPool(testCfg())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Add("alice", "orderId", "103")
			_ = p.IDs("alice", "orderId")
			_ = p.HasAll("alice", []string{"orderId"})
		}()
	}
	wg.Wait()
	assert.Equal(t, []string{"101", "102", "103"}, p.IDs("alice", "orderId"))
}

func TestExtract(t *testing.T) {
	body := []byte(`{"items":[{"id":101},{"id":102}],"a":{"b":"x"},"n":{"id":5,"c":[{"id":6.5}]},"t":true}`)
	got := Extract(body, map[string]string{
		"orderId": "$.items[*].id",
		"v":       "$.a.b",
		"deep":    "$..id",
		"none":    "$.missing",
		"b":       "$.t",
	})
	assert.Equal(t, []string{"101", "102"}, got["orderId"])
	assert.Equal(t, []string{"x"}, got["v"])
	assert.ElementsMatch(t, []string{"101", "102", "5", "6.5"}, got["deep"])
	assert.NotContains(t, got, "none")
	assert.Equal(t, []string{"true"}, got["b"])
	assert.Empty(t, Extract([]byte("<html>"), map[string]string{"a": "$.a"}))
}
