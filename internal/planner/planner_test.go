package planner

import (
	"encoding/json"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/identity"
	"github.com/ardayesilcayir/authdiff/internal/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pool() *identity.Pool {
	return identity.NewPool(&config.Config{Profiles: map[string]config.Profile{
		"alice": {Name: "alice", Owns: map[string][]string{"orderId": {"101", "102"}, "invoiceId": {"9001"}}},
		"bob":   {Name: "bob", Owns: map[string][]string{"orderId": {"201"}}},
	}})
}

var names = []string{"alice", "bob"}

func TestBuildFillsOwnerIDs(t *testing.T) {
	b := NewBuilder("http://h", nil, pool(), names)
	ep := spec.Endpoint{Method: "GET", Path: "/orders/{orderId}"}
	r, err := b.Build(ep, "", "alice", nil)
	require.NoError(t, err)
	assert.Equal(t, "/orders/101", r.Path)
	assert.Equal(t, "http://h/orders/101", r.URL)
	assert.Equal(t, "GET", r.Method)
	assert.Equal(t, "alice", r.IDSources["orderId"])
	assert.True(t, r.OwnedBy("alice"))
	assert.False(t, r.OwnedBy("bob"))
	assert.Empty(t, r.Body)
}

func TestBuildFallback(t *testing.T) {
	b := NewBuilder("http://h", nil, pool(), names)
	ep := spec.Endpoint{Method: "GET", Path: "/invoices/{invoiceId}"}
	r, err := b.Build(ep, "", "bob", nil)
	require.NoError(t, err)
	assert.Equal(t, "/invoices/9001", r.Path)
	assert.Equal(t, "alice", r.IDSources["invoiceId"])

	ep = spec.Endpoint{Method: "GET", Path: "/things/{thingId}", Params: []spec.Param{{Name: "thingId", In: "path", Example: float64(42)}}}
	r, err = b.Build(ep, "", "bob", nil)
	require.NoError(t, err)
	assert.Equal(t, "/things/42", r.Path)
	assert.Equal(t, "", r.IDSources["thingId"])
	assert.False(t, r.OwnedBy("bob"))

	ep = spec.Endpoint{Method: "GET", Path: "/x/{unknownId}"}
	r, err = b.Build(ep, "", "bob", nil)
	require.NoError(t, err)
	assert.Equal(t, "/x/1", r.Path)
}

func TestBuildNoPathParamsOwned(t *testing.T) {
	b := NewBuilder("http://h", nil, pool(), names)
	r, err := b.Build(spec.Endpoint{Method: "GET", Path: "/me"}, "", "bob", nil)
	require.NoError(t, err)
	assert.True(t, r.OwnedBy("bob"))
	assert.True(t, r.OwnedBy("alice"))
}

func TestBuildBasePath(t *testing.T) {
	ep := spec.Endpoint{Method: "GET", Path: "/orders/{orderId}"}
	for _, base := range []string{"http://h/api", "http://h/api/"} {
		b := NewBuilder(base, nil, pool(), names)
		r, err := b.Build(ep, "", "alice", nil)
		require.NoError(t, err)
		assert.Equal(t, "http://h/api/orders/101", r.URL)
	}
}

func TestBuildEscapesAndQueryHeader(t *testing.T) {
	p := pool()
	p.Add("alice", "name", "a b/c")
	b := NewBuilder("http://h", nil, p, names)
	ep := spec.Endpoint{Method: "GET", Path: "/n/{name}", Params: []spec.Param{
		{Name: "limit", In: "query", Required: true, Example: json.Number("10")},
		{Name: "opt", In: "query", Example: "x"},
		{Name: "flag", In: "query", Required: true, Example: true},
		{Name: "noex", In: "query", Required: true},
		{Name: "X-Req", In: "header", Required: true, Example: "h1"},
		{Name: "X-Opt", In: "header", Example: "h2"},
	}}
	r, err := b.Build(ep, "", "alice", nil)
	require.NoError(t, err)
	assert.Equal(t, "/n/a%20b%2Fc", r.Path)
	assert.Equal(t, "http://h/n/a%20b%2Fc?flag=true&limit=10&noex=1", r.URL)
	assert.Equal(t, "h1", r.Header.Get("X-Req"))
	assert.Empty(t, r.Header.Get("X-Opt"))
}

func TestFormatValue(t *testing.T) {
	assert.Equal(t, "5", formatValue(float64(5)))
	assert.Equal(t, "5.5", formatValue(5.5))
	assert.Equal(t, "7", formatValue(7))
	assert.Equal(t, "abc", formatValue("abc"))
	assert.Equal(t, "false", formatValue(false))
	assert.Equal(t, "[1,2]", formatValue([]any{float64(1), float64(2)}))
}

func TestBuildBodyOverride(t *testing.T) {
	bodies := map[string]any{"PATCH /orders/{orderId}": map[string]any{"status": "shipped", "role": "user"}}
	b := NewBuilder("http://h", bodies, pool(), names)
	ep := spec.Endpoint{Method: "PATCH", Path: "/orders/{orderId}",
		Body: &spec.Body{ContentType: "application/merge-patch+json", Example: map[string]any{"ignored": 1}}}
	r, err := b.Build(ep, "", "alice", map[string]any{"role": "admin"})
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(r.Body, &got))
	assert.Equal(t, map[string]any{"status": "shipped", "role": "admin"}, got)
	assert.Equal(t, "application/merge-patch+json", r.ContentType)
	assert.Equal(t, "application/merge-patch+json", r.Header.Get("Content-Type"))
	assert.Equal(t, "user", bodies["PATCH /orders/{orderId}"].(map[string]any)["role"], "config body not mutated")
}

func TestBuildBodyFromExampleAndMethodOverride(t *testing.T) {
	b := NewBuilder("http://h", nil, pool(), names)
	ep := spec.Endpoint{Method: "POST", Path: "/orders", Body: &spec.Body{Example: map[string]any{"qty": float64(2)}}}
	r, err := b.Build(ep, "", "alice", nil)
	require.NoError(t, err)
	assert.JSONEq(t, `{"qty":2}`, string(r.Body))
	assert.Equal(t, "application/json", r.ContentType)

	r, err = b.Build(ep, "GET", "alice", nil)
	require.NoError(t, err)
	assert.Equal(t, "GET", r.Method)
	assert.Empty(t, r.Body)

	r, err = b.Build(spec.Endpoint{Method: "DELETE", Path: "/orders"}, "", "alice", map[string]any{"a": "b"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":"b"}`, string(r.Body))

	r, err = b.Build(spec.Endpoint{Method: "POST", Path: "/l", Body: &spec.Body{Example: []any{"a"}}}, "", "alice", nil)
	require.NoError(t, err)
	assert.JSONEq(t, `["a"]`, string(r.Body))

	_, err = b.Build(spec.Endpoint{Method: "POST", Path: "/l", Body: &spec.Body{Example: make(chan int)}}, "", "alice", nil)
	assert.Error(t, err)

	r, err = b.Build(spec.Endpoint{Method: "POST", Path: "/e"}, "", "alice", nil)
	require.NoError(t, err)
	assert.Empty(t, r.Body)
}
