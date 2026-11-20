package transport

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimit(t *testing.T) {
	base, n := countingBase()
	rt := NewRateLimit(20, base)
	const total = 30
	start := time.Now()
	for i := 0; i < total; i++ {
		resp, err := rt.RoundTrip(mustReq(t, "GET", "http://example.com/x", ""))
		require.NoError(t, err)
		_ = resp.Body.Close()
	}
	elapsed := time.Since(start)
	require.EqualValues(t, total, atomic.LoadInt32(n))
	perSec := float64(total) / elapsed.Seconds()
	assert.LessOrEqual(t, perSec, 22.0, "must not exceed the configured rate by more than 10%")
	assert.GreaterOrEqual(t, perSec, 1.0)
}

func TestRateLimitPerHost(t *testing.T) {
	base, _ := countingBase()
	rt := NewRateLimit(0.5, base) // one request every 2s per host
	start := time.Now()
	for _, u := range []string{"http://a.example/", "http://b.example/", "http://c.example/"} {
		resp, err := rt.RoundTrip(mustReq(t, "GET", u, ""))
		require.NoError(t, err)
		_ = resp.Body.Close()
	}
	assert.Less(t, time.Since(start), time.Second, "each host has its own limiter")
}

func TestRateLimitHonoursContext(t *testing.T) {
	base, n := countingBase()
	rt := NewRateLimit(0.5, base)
	resp, err := rt.RoundTrip(mustReq(t, "GET", "http://example.com/", ""))
	require.NoError(t, err)
	_ = resp.Body.Close()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	req := mustReq(t, "GET", "http://example.com/", "").WithContext(ctx)
	start := time.Now()
	_, err = rt.RoundTrip(req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
	assert.Less(t, time.Since(start), time.Second)
	assert.EqualValues(t, 1, atomic.LoadInt32(n))
}

func TestRateLimitDisabled(t *testing.T) {
	base, _ := countingBase()
	rt := NewRateLimit(0, base)
	start := time.Now()
	for i := 0; i < 50; i++ {
		resp, err := rt.RoundTrip(mustReq(t, "GET", "http://example.com/", ""))
		require.NoError(t, err)
		_ = resp.Body.Close()
	}
	assert.Less(t, time.Since(start), time.Second)
}
