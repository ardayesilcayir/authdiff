package transport

import (
	"net/http"
	"strings"
	"sync"

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

func (r *rateLimit) RoundTrip(req *http.Request) (*http.Response, error) {
	host := ""
	if req.URL != nil {
		host = strings.ToLower(req.URL.Host)
	}
	if err := r.limiter(host).Wait(req.Context()); err != nil {
		closeBody(req)
		return nil, err
	}
	return r.next.RoundTrip(req)
}
