package spec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEndpointKeyAndPathParams(t *testing.T) {
	e := Endpoint{Method: "GET", Path: "/orders/{orderId}/items/{itemId}"}
	assert.Equal(t, "GET /orders/{orderId}/items/{itemId}", e.Key())
	assert.Equal(t, []string{"orderId", "itemId"}, e.PathParams())
	assert.Empty(t, Endpoint{Path: "/health"}.PathParams())
}

func TestIsAdminFunction(t *testing.T) {
	matrix := map[string][]string{
		"GET /reports/**": {"admin"},
		"/billing/**":     {"admin"},
		"/shared/**":      {"admin", "user"},
	}
	tests := []struct {
		name string
		e    Endpoint
		m    map[string][]string
		want bool
	}{
		{"admin segment", Endpoint{Method: "GET", Path: "/admin/users"}, nil, true},
		{"admin tag", Endpoint{Method: "GET", Path: "/x", Tags: []string{"Admin"}}, nil, true},
		{"matrix admin only", Endpoint{Method: "GET", Path: "/reports/1"}, matrix, true},
		{"matrix bare path", Endpoint{Method: "POST", Path: "/billing/x"}, matrix, true},
		{"matrix method mismatch", Endpoint{Method: "POST", Path: "/reports/1"}, matrix, false},
		{"matrix multiple roles", Endpoint{Method: "GET", Path: "/shared/a"}, matrix, false},
		{"plain", Endpoint{Method: "GET", Path: "/orders"}, matrix, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.e.IsAdminFunction(tt.m))
		})
	}
}

func TestFilter(t *testing.T) {
	inv := &Inventory{Title: "t", Version: "1", SpecPath: "p", Endpoints: []Endpoint{
		{Method: "GET", Path: "/orders", Tags: []string{"orders"}},
		{Method: "GET", Path: "/orders/{orderId}", Tags: []string{"orders"}},
		{Method: "DELETE", Path: "/admin/users/{userId}", Tags: []string{"admin"}},
		{Method: "GET", Path: "/health"},
	}}
	keys := func(i *Inventory) []string {
		var out []string
		for _, e := range i.Endpoints {
			out = append(out, e.Key())
		}
		return out
	}

	assert.Len(t, inv.Filter(nil, nil, nil).Endpoints, 4)
	assert.Equal(t, []string{"GET /orders", "GET /orders/{orderId}"}, keys(inv.Filter([]string{"/orders/**"}, nil, nil)))
	assert.Equal(t, []string{"GET /orders"}, keys(inv.Filter([]string{"/orders/**"}, []string{"/orders/*"}, nil)))
	assert.Equal(t, []string{"DELETE /admin/users/{userId}"}, keys(inv.Filter(nil, nil, []string{"admin"})))
	assert.Equal(t, []string{"GET /orders/{orderId}"}, keys(inv.Filter([]string{"/orders/**"}, []string{"GET /orders"}, []string{"orders"})))
	assert.Equal(t, []string{"GET /orders", "GET /orders/{orderId}", "GET /health"}, keys(inv.Filter(nil, []string{"/admin/**"}, nil)))
	f := inv.Filter(nil, nil, nil)
	assert.Equal(t, "t", f.Title)
	assert.Equal(t, "p", f.SpecPath)
}
