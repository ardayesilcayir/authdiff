package transport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// countingBase is a fake base transport that counts the requests that reach it.
func countingBase() (http.RoundTripper, *int32) {
	var n int32
	return rtFunc(func(r *http.Request) (*http.Response, error) {
		atomic.AddInt32(&n, 1)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	}), &n
}

// newCounted starts a test server that counts the requests it receives.
func newCounted(t *testing.T, h http.HandlerFunc) (*httptest.Server, *int32) {
	t.Helper()
	var n int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		h(w, r)
	}))
	t.Cleanup(s.Close)
	return s, &n
}

func ok200(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }

func hostOf(s *httptest.Server) string { return s.Listener.Addr().String() }

func mustReq(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	var r *http.Request
	var err error
	if body == "" {
		r, err = http.NewRequest(method, url, nil)
	} else {
		r, err = http.NewRequest(method, url, strings.NewReader(body))
	}
	require.NoError(t, err)
	return r
}

func newClient(t *testing.T, o Options) *Client {
	t.Helper()
	c, err := New(o)
	require.NoError(t, err)
	return c
}
