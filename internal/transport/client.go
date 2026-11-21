package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

const (
	defaultTimeout     = 10 * time.Second
	defaultMaxResponse = 5 * 1024 * 1024
	defaultUserAgent   = "authdiff (+https://github.com/ardayesilcayir/authdiff)"
	maxRedirects       = 5
	maxRetryAfter      = 5 * time.Second
	baseBackoff        = 100 * time.Millisecond
	maxBackoffShift    = 2 // 100ms, 200ms, 400ms, then stays at 400ms
)

var errTooManyRedirects = errors.New("stopped after 5 redirects")

// Options configures a Client.
type Options struct {
	AllowHosts       []string
	Rate             float64 // requests per second per host; 0 disables limiting
	AllowDestructive bool
	Timeout          time.Duration // per attempt; 0 means 10s
	MaxResponseBytes int64         // 0 means 5 MiB
	Insecure         bool          // skip TLS verification (only when true)
	UserAgent        string
	Secrets          []string
	Retries          int
	Base             http.RoundTripper // for tests; nil clones http.DefaultTransport
}

// Response is the outcome of one Client.Do call. Header and Body are the raw
// values for analysis; Exchange is the masked copy that is safe to persist.
type Response struct {
	Status    int
	Header    http.Header
	Body      []byte
	Truncated bool
	Duration  time.Duration
	Exchange  finding.Exchange
}

// Client sends requests through the scope -> safe mode -> rate limit -> base chain.
type Client struct {
	http      *http.Client // no overall timeout: Do bounds each attempt itself
	download  *http.Client // same chain with Options.Timeout, for HTTP()
	scope     *scopeTransport
	safe      *safeMode
	limit     *rateLimit // nil when rate limiting is disabled
	timeout   time.Duration
	red       *redactor
	retries   int
	maxBytes  int64
	userAgent string

	requests atomic.Int64
	blocked  atomic.Int64
	errs     atomic.Int64
}

// New validates o and builds a Client. It fails closed: an empty or entirely
// unparseable allow list is an error.
func New(o Options) (*Client, error) {
	valid := 0
	for _, h := range o.AllowHosts {
		valid += len(allowKeys(h))
	}
	if valid == 0 {
		return nil, errors.New("transport: allowHosts must contain at least one valid host")
	}
	if o.Rate < 0 || math.IsNaN(o.Rate) {
		return nil, fmt.Errorf("transport: rate must not be negative, got %v", o.Rate)
	}
	if o.Retries < 0 {
		return nil, fmt.Errorf("transport: retries must not be negative, got %d", o.Retries)
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.MaxResponseBytes <= 0 {
		o.MaxResponseBytes = defaultMaxResponse
	}
	if o.UserAgent == "" {
		o.UserAgent = defaultUserAgent
	}

	base := o.Base
	if base == nil {
		base = newBaseTransport(o.Insecure)
	}
	limited := NewRateLimit(o.Rate, base)
	limit, _ := limited.(*rateLimit)
	safe := &safeMode{allowDestructive: o.AllowDestructive, next: limited}
	scope := newScope(o.AllowHosts, safe)
	checkRedirect := func(_ *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return errTooManyRedirects
		}
		return nil
	}

	return &Client{
		http:      &http.Client{Transport: scope, CheckRedirect: checkRedirect},
		download:  &http.Client{Transport: scope, CheckRedirect: checkRedirect, Timeout: o.Timeout},
		scope:     scope,
		safe:      safe,
		limit:     limit,
		timeout:   o.Timeout,
		red:       newRedactor(o.Secrets),
		retries:   o.Retries,
		maxBytes:  o.MaxResponseBytes,
		userAgent: o.UserAgent,
	}, nil
}

func newBaseTransport(insecure bool) http.RoundTripper {
	var tr *http.Transport
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = dt.Clone()
	} else {
		tr = &http.Transport{}
	}
	if insecure {
		// #nosec G402 -- verification is skipped only when the user passes --insecure explicitly.
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec
	}
	return tr
}

// HTTP returns the underlying http.Client (same chain, so scope, safe mode and
// rate limit still apply). It is meant for downloading the spec; requests made
// through it are not counted in Stats and get no retries or redaction.
func (c *Client) HTTP() *http.Client { return c.download }

// Stats returns how many Do calls were made, how many were blocked by scope or
// safe mode, and how many failed with another error.
func (c *Client) Stats() (requests, blocked, errors int) {
	return int(c.requests.Load()), int(c.blocked.Load()), int(c.errs.Load())
}

// Do sends req, retrying network errors and 429/503 responses up to
// Options.Retries times. Scope and safe-mode errors are never retried.
func (c *Client) Do(ctx context.Context, req *http.Request) (*Response, error) {
	c.requests.Add(1)
	resp, err := c.do(ctx, req)
	if err != nil {
		if errors.Is(err, ErrOutOfScope) || errors.Is(err, ErrDestructiveBlocked) {
			c.blocked.Add(1)
		} else {
			c.errs.Add(1)
		}
		return nil, c.sanitize(err)
	}
	return resp, nil
}

func (c *Client) do(ctx context.Context, req *http.Request) (*Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("transport: nil request")
	}
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("transport: reading request body: %w", err)
		}
		body = b
	}

	for attempt := 0; ; attempt++ {
		r := req.Clone(ctx)
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		if r.Header.Get("User-Agent") == "" {
			r.Header.Set("User-Agent", c.userAgent)
		}
		if len(body) > 0 {
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		} else {
			r.Body, r.GetBody, r.ContentLength = http.NoBody, nil, 0
		}

		// Scope and safe mode first: a blocked request neither waits for nor
		// consumes a rate-limit token.
		if err := c.scope.check(r.URL); err != nil {
			return nil, err
		}
		if err := c.safe.check(r); err != nil {
			return nil, err
		}
		// The limiter wait uses the caller's context only, so it never counts
		// against the per-attempt timeout.
		if c.limit != nil {
			if err := c.limit.wait(ctx, r.URL); err != nil {
				return nil, err
			}
		}

		start := time.Now()
		hr, data, truncated, err := c.attempt(ctx, r)
		dur := time.Since(start)

		if err != nil {
			if !retryableError(err) || ctx.Err() != nil || attempt >= c.retries {
				return nil, err
			}
			if werr := sleep(ctx, retryDelay(attempt, nil)); werr != nil {
				return nil, werr
			}
			continue
		}
		if (hr.StatusCode == http.StatusTooManyRequests || hr.StatusCode == http.StatusServiceUnavailable) &&
			attempt < c.retries {
			if werr := sleep(ctx, retryDelay(attempt, hr.Header)); werr != nil {
				return nil, werr
			}
			continue
		}
		return &Response{
			Status:    hr.StatusCode,
			Header:    hr.Header,
			Body:      data,
			Truncated: truncated,
			Duration:  dur,
			Exchange:  record(c.red, r, body, hr.StatusCode, hr.Header, data, dur, truncated),
		}, nil
	}
}

// attempt sends r with the per-attempt timeout and reads the body. The first
// hop's rate-limit token was already taken by the caller.
func (c *Client) attempt(ctx context.Context, r *http.Request) (*http.Response, []byte, bool, error) {
	actx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	pre := &atomic.Bool{}
	pre.Store(c.limit != nil)
	hr, err := c.http.Do(r.WithContext(context.WithValue(actx, prewaitKey{}, pre)))
	if err != nil {
		return nil, nil, false, err
	}
	data, truncated, err := c.readBody(hr.Body)
	return hr, data, truncated, err
}

// readBody reads at most maxBytes and reports whether the body was longer.
func (c *Client) readBody(rc io.ReadCloser) ([]byte, bool, error) {
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, c.maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > c.maxBytes {
		return data[:c.maxBytes], true, nil
	}
	return data, false, nil
}

func retryableError(err error) bool {
	return !errors.Is(err, ErrOutOfScope) &&
		!errors.Is(err, ErrDestructiveBlocked) &&
		!errors.Is(err, errTooManyRedirects)
}

// retryDelay is the wait before retry number attempt+1. A Retry-After header
// in whole seconds wins over the exponential backoff, capped at 5s.
func retryDelay(attempt int, h http.Header) time.Duration {
	if h != nil {
		if v := strings.TrimSpace(h.Get("Retry-After")); v != "" {
			n, err := strconv.Atoi(v)
			if errors.Is(err, strconv.ErrRange) && !strings.HasPrefix(v, "-") {
				return maxRetryAfter // an absurdly large integer is still an integer
			}
			if err == nil && n >= 0 {
				if n > int(maxRetryAfter/time.Second) {
					return maxRetryAfter
				}
				return time.Duration(n) * time.Second
			}
		}
	}
	if attempt > maxBackoffShift {
		attempt = maxBackoffShift
	}
	if attempt < 0 {
		attempt = 0
	}
	return baseBackoff << attempt
}

// sleep waits for d or until ctx is done, whichever comes first.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// redactedError hides secrets in the message (net/http embeds the full URL,
// query included) while keeping the original error reachable for errors.Is.
type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

func (c *Client) sanitize(err error) error {
	msg := err.Error()
	if red := c.red.String(msg); red != msg {
		return &redactedError{msg: red, err: err}
	}
	return err
}
