package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopeBlocksOutOfScope(t *testing.T) {
	allowed, allowedN := newCounted(t, ok200)
	other, otherN := newCounted(t, ok200)
	c := newClient(t, Options{AllowHosts: []string{hostOf(allowed)}})

	resp, err := c.Do(context.Background(), mustReq(t, "GET", allowed.URL+"/x", ""))
	require.NoError(t, err)
	assert.Equal(t, 200, resp.Status)
	assert.EqualValues(t, 1, atomic.LoadInt32(allowedN))

	_, err = c.Do(context.Background(), mustReq(t, "GET", other.URL+"/x", ""))
	require.ErrorIs(t, err, ErrOutOfScope)
	assert.EqualValues(t, 0, atomic.LoadInt32(otherN), "out-of-scope server must never see a request")

	requests, blocked, errs := c.Stats()
	assert.Equal(t, 2, requests)
	assert.Equal(t, 1, blocked)
	assert.Equal(t, 0, errs)
}

func TestScopeRedirect(t *testing.T) {
	other, otherN := newCounted(t, ok200)
	allowed, _ := newCounted(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(allowed)}, Retries: 2})

	start := time.Now()
	_, err := c.Do(context.Background(), mustReq(t, "GET", allowed.URL+"/x", ""))
	require.ErrorIs(t, err, ErrOutOfScope)
	assert.EqualValues(t, 0, atomic.LoadInt32(otherN))
	assert.Less(t, time.Since(start), 500*time.Millisecond, "scope errors are never retried")
	_, blocked, _ := c.Stats()
	assert.Equal(t, 1, blocked)
}

func TestRedirectWithinScopeLimited(t *testing.T) {
	srv, n := newCounted(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Retries: 2})
	_, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL+"/loop", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect")
	assert.EqualValues(t, 6, atomic.LoadInt32(n), "initial request plus 5 redirects, no retries")
	_, _, errs := c.Stats()
	assert.Equal(t, 1, errs)
}

func TestRedirectWithinScopeFollowed(t *testing.T) {
	srv, _ := newCounted(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/end", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("end"))
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}})
	resp, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL+"/start", ""))
	require.NoError(t, err)
	assert.Equal(t, "end", string(resp.Body))
}

func TestClientBlocksDestructive(t *testing.T) {
	srv, n := newCounted(t, ok200)
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}})
	for _, m := range []string{"DELETE", "PUT", "PATCH"} {
		_, err := c.Do(context.Background(), mustReq(t, m, srv.URL+"/x", ""))
		require.ErrorIs(t, err, ErrDestructiveBlocked, m)
	}
	assert.EqualValues(t, 0, atomic.LoadInt32(n))
	_, blocked, _ := c.Stats()
	assert.Equal(t, 3, blocked)

	c2 := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, AllowDestructive: true})
	resp, err := c2.Do(context.Background(), mustReq(t, "DELETE", srv.URL+"/x", ""))
	require.NoError(t, err)
	assert.Equal(t, 200, resp.Status)
}

func TestClientTruncates(t *testing.T) {
	srv, _ := newCounted(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 4096)))
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, MaxResponseBytes: 1024})
	resp, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
	require.NoError(t, err)
	assert.Len(t, resp.Body, 1024)
	assert.True(t, resp.Truncated)
	assert.True(t, resp.Exchange.Truncated)

	c = newClient(t, Options{AllowHosts: []string{hostOf(srv)}, MaxResponseBytes: 4096})
	resp, err = c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
	require.NoError(t, err)
	assert.Len(t, resp.Body, 4096)
	assert.False(t, resp.Truncated, "a body exactly at the limit is not truncated")
}

func TestClientRetries(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var attempts int32
	srv, n := newCounted(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		if atomic.AddInt32(&attempts, 1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("fine"))
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Retries: 3})
	start := time.Now()
	resp, err := c.Do(context.Background(), mustReq(t, "POST", srv.URL+"/x", "payload"))
	require.NoError(t, err)
	assert.Equal(t, 200, resp.Status)
	assert.EqualValues(t, 3, atomic.LoadInt32(n))
	assert.GreaterOrEqual(t, time.Since(start), 290*time.Millisecond, "100ms + 200ms backoff")
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"payload", "payload", "payload"}, bodies, "request body is replayed on retry")
}

func TestClientRetries429WithRetryAfter(t *testing.T) {
	var attempts int32
	srv, n := newCounted(t, func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("fine"))
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Retries: 1})
	start := time.Now()
	resp, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
	require.NoError(t, err)
	assert.Equal(t, 200, resp.Status)
	assert.EqualValues(t, 2, atomic.LoadInt32(n))
	assert.Less(t, time.Since(start), 90*time.Millisecond, "Retry-After: 0 replaces the backoff")
}

func TestClientRetriesExhausted(t *testing.T) {
	srv, n := newCounted(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Retries: 1})
	resp, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
	require.NoError(t, err)
	assert.Equal(t, 503, resp.Status)
	assert.EqualValues(t, 2, atomic.LoadInt32(n))
}

func TestClientDoesNotRetryOtherStatuses(t *testing.T) {
	srv, n := newCounted(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Retries: 3})
	resp, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
	require.NoError(t, err)
	assert.Equal(t, 500, resp.Status)
	assert.EqualValues(t, 1, atomic.LoadInt32(n))
}

func TestClientRetriesNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(ok200))
	host := hostOf(srv)
	url := srv.URL
	srv.Close()
	c := newClient(t, Options{AllowHosts: []string{host}, Retries: 2})
	start := time.Now()
	_, err := c.Do(context.Background(), mustReq(t, "GET", url, ""))
	require.Error(t, err)
	assert.GreaterOrEqual(t, time.Since(start), 290*time.Millisecond)
	_, blocked, errs := c.Stats()
	assert.Equal(t, 0, blocked)
	assert.Equal(t, 1, errs)
}

func TestClientContextCancelAbortsWait(t *testing.T) {
	srv, _ := newCounted(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Retries: 3})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err := c.Do(ctx, mustReq(t, "GET", srv.URL, ""))
	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 2*time.Second, "cancellation must not wait out Retry-After")
}

func TestRetryDelay(t *testing.T) {
	h := func(v string) http.Header { return http.Header{"Retry-After": []string{v}} }
	assert.Equal(t, 100*time.Millisecond, retryDelay(0, nil))
	assert.Equal(t, 200*time.Millisecond, retryDelay(1, nil))
	assert.Equal(t, 400*time.Millisecond, retryDelay(2, nil))
	assert.Equal(t, 400*time.Millisecond, retryDelay(7, nil))
	assert.Equal(t, 2*time.Second, retryDelay(0, h("2")))
	assert.Equal(t, 5*time.Second, retryDelay(0, h("99")))
	assert.Equal(t, 5*time.Second, retryDelay(0, h("99999999999999999999")))
	assert.Equal(t, time.Duration(0), retryDelay(0, h("0")))
	assert.Equal(t, 200*time.Millisecond, retryDelay(1, h("-3")))
	assert.Equal(t, 200*time.Millisecond, retryDelay(1, h("Wed, 21 Oct 2026 07:28:00 GMT")))
	assert.Equal(t, 100*time.Millisecond, retryDelay(0, h("")))
}

func TestClientUserAgent(t *testing.T) {
	srv, _ := newCounted(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("User-Agent"))) //nolint:gosec // G705: test server echoing into a test client
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, UserAgent: "authdiff/9.9 (+https://example.test)"})
	resp, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
	require.NoError(t, err)
	assert.Equal(t, "authdiff/9.9 (+https://example.test)", string(resp.Body))
	assert.Equal(t, "authdiff/9.9 (+https://example.test)", resp.Exchange.RequestHeaders["User-Agent"])

	c = newClient(t, Options{AllowHosts: []string{hostOf(srv)}})
	resp, err = c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
	require.NoError(t, err)
	assert.Contains(t, string(resp.Body), "authdiff")
}

func TestClientInsecure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(ok200))
	t.Cleanup(srv.Close)

	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}})
	_, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
	require.Error(t, err, "TLS verification is on by default")

	c = newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Insecure: true})
	resp, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
	require.NoError(t, err)
	assert.Equal(t, 200, resp.Status)
}

func TestClientHTTPSharesChain(t *testing.T) {
	allowed, _ := newCounted(t, ok200)
	other, otherN := newCounted(t, ok200)
	c := newClient(t, Options{AllowHosts: []string{hostOf(allowed)}})
	hc := c.HTTP()
	resp, err := hc.Get(allowed.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	_, err = hc.Get(other.URL)
	require.ErrorIs(t, err, ErrOutOfScope)
	assert.EqualValues(t, 0, atomic.LoadInt32(otherN))
}

func TestNewValidation(t *testing.T) {
	_, err := New(Options{})
	assert.Error(t, err, "empty scope fails closed")
	_, err = New(Options{AllowHosts: []string{"  "}})
	assert.Error(t, err)
	_, err = New(Options{AllowHosts: []string{"a.example"}, Rate: -1})
	assert.Error(t, err)
	_, err = New(Options{AllowHosts: []string{"a.example"}, Retries: -1})
	assert.Error(t, err)
}

func TestClientDoRejectsNilRequest(t *testing.T) {
	c := newClient(t, Options{AllowHosts: []string{"a.example"}})
	_, err := c.Do(context.Background(), nil)
	assert.Error(t, err)
}

func TestClientCustomBase(t *testing.T) {
	base, n := countingBase()
	c := newClient(t, Options{AllowHosts: []string{"a.example"}, Base: base})
	resp, err := c.Do(context.Background(), mustReq(t, "GET", "http://a.example/x", ""))
	require.NoError(t, err)
	assert.Equal(t, 200, resp.Status)
	assert.EqualValues(t, 1, atomic.LoadInt32(n))
	_, err = c.Do(context.Background(), mustReq(t, "GET", "http://b.example/x", ""))
	require.ErrorIs(t, err, ErrOutOfScope)
	assert.EqualValues(t, 1, atomic.LoadInt32(n))
}

func TestClientAppliesRateLimit(t *testing.T) {
	srv, _ := newCounted(t, ok200)
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Rate: 10})
	start := time.Now()
	for i := 0; i < 4; i++ {
		_, err := c.Do(context.Background(), mustReq(t, "GET", srv.URL, ""))
		require.NoError(t, err)
	}
	assert.GreaterOrEqual(t, time.Since(start), 250*time.Millisecond, "3 intervals of 100ms")
}

const (
	secBearer = "tok-ALICE-0123456789"
	secAPIKey = "key-APIKEY-9876543210" //nolint:gosec // G101: test fixture, not a real credential
	secBody   = "pw-BODYSECRET-555555"
	secCookie = "COOKIEVALUE12345"
	secSetCk  = "SETCOOKIEVALUE777"
)

func secretHandler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	w.Header().Set("Location", "http://"+r.Host+"/cb?token="+secBearer)
	w.Header().Add("Set-Cookie", "sid="+secSetCk+"; Path=/")
	_, _ = fmt.Fprintf(w, `{"body":%q,"auth":%q,"url":%q}`, b, r.Header.Get("Authorization"), r.URL.String()) //nolint:gosec // G705: test server echoing into a test client
}

func TestExchangeNeverContainsSecret(t *testing.T) {
	srv, _ := newCounted(t, secretHandler)
	secrets := []string{secBearer, secAPIKey, secBody}
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, Secrets: secrets})

	req := mustReq(t, "POST", srv.URL+"/orders?apikey="+secAPIKey, `{"password":"`+secBody+`"}`)
	req.Header.Set("Authorization", "Bearer "+secBearer)
	req.Header.Set("Cookie", "sid="+secCookie)
	req.Header.Set("X-API-Key", secAPIKey)
	resp, err := c.Do(context.Background(), req)
	require.NoError(t, err)

	raw, err := json.Marshal(resp.Exchange)
	require.NoError(t, err)
	for _, s := range []string{secBearer, secAPIKey, secBody, secCookie, secSetCk} {
		assert.NotContains(t, string(raw), s)
	}
	ex := resp.Exchange
	assert.Equal(t, "POST", ex.Method)
	assert.Equal(t, 200, ex.Status)
	assert.Contains(t, ex.URL, "apikey=****3210")
	assert.Equal(t, "****6789", ex.RequestHeaders["Authorization"])
	assert.Equal(t, "****2345", ex.RequestHeaders["Cookie"])
	assert.Equal(t, "****3210", ex.RequestHeaders["X-Api-Key"])
	assert.Contains(t, ex.RequestBody, "****5555")
	assert.Contains(t, ex.ResponseHeaders["Location"], "token=****6789")
	assert.Equal(t, "****th=/", ex.ResponseHeaders["Set-Cookie"], "whole header value masked, last 4 chars kept")
	assert.Contains(t, ex.ResponseBody, "****")

	// The engine still gets the real response for analysis.
	assert.Contains(t, string(resp.Body), secBody)
}

func TestErrorsAreRedacted(t *testing.T) {
	allowed, _ := newCounted(t, ok200)
	other, _ := newCounted(t, ok200)
	c := newClient(t, Options{AllowHosts: []string{hostOf(allowed)}, Secrets: []string{secAPIKey}})
	_, err := c.Do(context.Background(), mustReq(t, "GET", other.URL+"/x?apikey="+secAPIKey, ""))
	require.ErrorIs(t, err, ErrOutOfScope)
	assert.NotContains(t, err.Error(), secAPIKey)
}

func TestExchangeTruncatesEvidence(t *testing.T) {
	srv, _ := newCounted(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 20000)))
	})
	c := newClient(t, Options{AllowHosts: []string{hostOf(srv)}, MaxResponseBytes: 1 << 20})
	resp, err := c.Do(context.Background(), mustReq(t, "POST", srv.URL, strings.Repeat("y", 20000)))
	require.NoError(t, err)
	assert.Len(t, resp.Body, 20000)
	assert.False(t, resp.Truncated)
	assert.Len(t, resp.Exchange.ResponseBody, 16*1024)
	assert.Len(t, resp.Exchange.RequestBody, 16*1024)
	assert.True(t, resp.Exchange.Truncated)
}

func TestTruncateEvidenceKeepsRuneBoundary(t *testing.T) {
	s := strings.Repeat("a", maxEvidenceBytes-1) + "é" // é straddles the limit
	out, cut := truncateEvidence(s)
	assert.True(t, cut)
	assert.Len(t, out, maxEvidenceBytes-1)
	short, cut := truncateEvidence("abc")
	assert.False(t, cut)
	assert.Equal(t, "abc", short)
}
