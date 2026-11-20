package spec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"/orders/**", "/orders/{orderId}/status", true},
		{"/orders/**", "/orders", true},
		{"/orders/*", "/orders/{orderId}/status", false},
		{"/orders/*", "/orders/{orderId}", true},
		{"/orders/*", "/orders", false},
		{"/orders/{orderId}", "/orders/{orderId}", true},
		{"/orders/{orderId}", "/orders/5", false},
		{"/**/status", "/orders/1/status", true},
		{"/**/status", "/status", true},
		{"/**", "/", true},
		{"/a/*/c", "/a/b/c", true},
		{"/a/*/c", "/a/b/d", false},
		{"/pre*", "/prefix", true},
		{"/orders/", "/orders", true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"|"+tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, MatchGlob(tt.pattern, tt.path))
		})
	}
}

func TestMatchEndpoint(t *testing.T) {
	del := Endpoint{Method: "DELETE", Path: "/admin/users/{userId}"}
	get := Endpoint{Method: "GET", Path: "/admin/users/{userId}"}
	assert.False(t, MatchEndpoint("GET /admin/**", del))
	assert.True(t, MatchEndpoint("GET /admin/**", get))
	assert.True(t, MatchEndpoint("get /admin/**", get))
	assert.True(t, MatchEndpoint("/admin/**", del))
	assert.True(t, MatchEndpoint("* /admin/**", del))
}
