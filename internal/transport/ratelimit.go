package transport

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"
)

type rateLimit struct {
	rps  float64
	next http.RoundTripper

	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

// NewRateLimit limits requests per host to rps per second (burst 1). The wait
// is aborted as soon as the request context is cancelled. rps <= 0 disables
// limiting.
func NewRateLimit(rps float64, next http.RoundTripper) http.RoundTripper {
	if rps <= 0 {
		return next
	}
	return &rateLimit{rps: rps, next: next, limiters: make(map[string]*rate.Limiter)}
}

func (r *rateLimit) limiter(host string) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.limiters[host]
	if !ok {
		l = rate.NewLimiter(rate.Limit(r.rps), 1)
		r.limiters[host] = l
	}
	return l
}

// prewaitKey marks a request context whose first hop already took its
// rate-limit token (Client.do waits before starting the timed attempt). The
// value is a *atomic.Bool that the first RoundTrip clears, so redirect hops
// still wait for their own tokens.
type prewaitKey struct{}

// limitKey is the bucket key of u: the same normalization as scope, so
// equivalent forms of one target share a bucket.
func limitKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	if key, err := requestKey(u); err == nil {
		return key
	}
	return strings.ToLower(u.Host)
}

// wait blocks until u's host may send, or ctx is done.
func (r *rateLimit) wait(ctx context.Context, u *url.URL) error {
	return r.limiter(limitKey(u)).Wait(ctx)
}

func (r *rateLimit) RoundTrip(req *http.Request) (*http.Response, error) {
	if pre, ok := req.Context().Value(prewaitKey{}).(*atomic.Bool); ok && pre.CompareAndSwap(true, false) {
		return r.next.RoundTrip(req)
	}
	if err := r.wait(req.Context(), req.URL); err != nil {
		closeBody(req)
		return nil, err
	}
	return r.next.RoundTrip(req)
}
