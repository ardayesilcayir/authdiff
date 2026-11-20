package transport

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSafeModeBlocksDestructive(t *testing.T) {
	for _, m := range []string{"DELETE", "PUT", "PATCH", "delete", "Patch"} {
		t.Run(m, func(t *testing.T) {
			base, n := countingBase()
			rt := NewSafeMode(false, base)
			_, err := rt.RoundTrip(mustReq(t, m, "http://example.com/x", ""))
			require.ErrorIs(t, err, ErrDestructiveBlocked)
			assert.Contains(t, err.Error(), strings.ToUpper(m))
			assert.Contains(t, err.Error(), "example.com")
			assert.EqualValues(t, 0, atomic.LoadInt32(n))
		})
	}
}

func TestSafeModePassesSafeMethods(t *testing.T) {
	for _, m := range []string{"GET", "POST", "HEAD", "OPTIONS"} {
		base, n := countingBase()
		rt := NewSafeMode(false, base)
		resp, err := rt.RoundTrip(mustReq(t, m, "http://example.com/x", ""))
		require.NoError(t, err, m)
		_ = resp.Body.Close()
		assert.EqualValues(t, 1, atomic.LoadInt32(n), m)
	}
}

func TestSafeModeAllowDestructive(t *testing.T) {
	for _, m := range []string{"GET", "POST", "DELETE", "PUT", "PATCH"} {
		base, n := countingBase()
		rt := NewSafeMode(true, base)
		resp, err := rt.RoundTrip(mustReq(t, m, "http://example.com/x", ""))
		require.NoError(t, err, m)
		_ = resp.Body.Close()
		assert.EqualValues(t, 1, atomic.LoadInt32(n), m)
	}
}

func TestSafeModeBlocksMethodOverride(t *testing.T) {
	for _, hdr := range []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"} {
		base, n := countingBase()
		rt := NewSafeMode(false, base)
		req := mustReq(t, "POST", "http://example.com/x", "")
		req.Header.Set(hdr, "delete")
		_, err := rt.RoundTrip(req)
		require.ErrorIs(t, err, ErrDestructiveBlocked, hdr)
		assert.EqualValues(t, 0, atomic.LoadInt32(n))
	}

	base, n := countingBase()
	rt := NewSafeMode(false, base)
	_, err := rt.RoundTrip(mustReq(t, "POST", "http://example.com/x?_method=PUT", ""))
	require.ErrorIs(t, err, ErrDestructiveBlocked)
	assert.EqualValues(t, 0, atomic.LoadInt32(n))

	// A harmless override value is fine.
	req := mustReq(t, "POST", "http://example.com/x", "")
	req.Header.Set("X-HTTP-Method-Override", "GET")
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
}
