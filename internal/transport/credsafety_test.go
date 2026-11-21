package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An https -> http redirect would send Authorization/Cookie in cleartext.
func TestRedirectSchemeDowngradeRefused(t *testing.T) {
	plain, plainN := newCounted(t, ok200)
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/x", http.StatusFound)
	}))
	t.Cleanup(tlsSrv.Close)
	c := newClient(t, Options{AllowHosts: []string{hostOf(tlsSrv), hostOf(plain)}, Insecure: true, Retries: 2})
	req := mustReq(t, "GET", tlsSrv.URL+"/start", "")
	req.Header.Set("Authorization", "Bearer secret-token-123456")
	_, err := c.Do(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect")
	assert.EqualValues(t, 0, atomic.LoadInt32(plainN), "downgraded redirect must not be followed")
	_, _, errs := c.Stats()
	assert.Equal(t, 1, errs)
}

// A redirect to another in-scope host:port would forward custom credential
// headers (X-API-Key, ...) that net/http does not strip.
func TestRedirectCrossHostRefused(t *testing.T) {
	other, otherN := newCounted(t, ok200)
	start, startN := newCounted(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/x", http.StatusFound)
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(start), hostOf(other)}, Retries: 2})
	req := mustReq(t, "GET", start.URL+"/a", "")
	req.Header.Set("X-Custom-Key", "k-1234567890")
	_, err := c.Do(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect")
	assert.EqualValues(t, 0, atomic.LoadInt32(otherN))
	assert.EqualValues(t, 1, atomic.LoadInt32(startN), "refused redirects are not retried")
}

// HTTP(S)_PROXY is ignored unless a proxy is configured explicitly.
func TestProxyOffByDefault(t *testing.T) {
	tr, ok := newBaseTransport(false, nil).(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, tr.Proxy)
}

func TestProxyOptIn(t *testing.T) {
	var seen atomic.Value
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.URL.String())
		_, _ = w.Write([]byte("via proxy"))
	}))
	t.Cleanup(proxy.Close)
	c := newClient(t, Options{AllowHosts: []string{"api.example:8080"}, Proxy: proxy.URL})
	resp, err := c.Do(context.Background(), mustReq(t, "GET", "http://api.example:8080/x", ""))
	require.NoError(t, err)
	assert.Equal(t, "via proxy", string(resp.Body))
	assert.Equal(t, "http://api.example:8080/x", seen.Load())

	_, err = New(Options{AllowHosts: []string{"a.example"}, Proxy: "::not a url"})
	assert.Error(t, err)
}

// dropConn closes the connection without a response: a network error.
func dropConn(w http.ResponseWriter, _ *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("no hijacker")
	}
	conn, _, err := hj.Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

// Network errors are retried only for idempotent methods: a POST may have
// been processed before the connection broke.
func TestNetworkRetriesOnlyIdempotent(t *testing.T) {
	srv, n := newCounted(t, dropConn)
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Retries: 2, AllowDestructive: true})
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		atomic.StoreInt32(n, 0)
		_, err := c.Do(context.Background(), mustReq(t, m, srv.URL, `{"a":1}`))
		require.Error(t, err, m)
		assert.EqualValues(t, 1, atomic.LoadInt32(n), "%s must not be retried after a network error", m)
	}
	atomic.StoreInt32(n, 0)
	_, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
	require.Error(t, err)
	assert.EqualValues(t, 3, atomic.LoadInt32(n), "GET is retried")
}

// 429/503 mean the server did not process the request: any method retries.
func TestStatusRetriesAnyMethod(t *testing.T) {
	var calls atomic.Int32
	srv, _ := newCounted(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Retries: 2})
	resp, err := c.Do(context.Background(), mustReq(t, "POST", srv.URL, `{}`))
	require.NoError(t, err)
	assert.Equal(t, 200, resp.Status)
	assert.True(t, strings.Contains(string(resp.Body), "ok"))
}
