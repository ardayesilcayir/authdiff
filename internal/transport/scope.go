// Package transport is the only place where authdiff touches the network.
//
// Every safety control (scope, safe mode, rate limit, redaction) lives in
// this layer so that detection engines cannot bypass it. The RoundTripper
// chain, from the outside in, is: scope -> safe mode -> rate limit -> base.
package transport

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ErrOutOfScope is returned (wrapped) when a request targets a host that is
// not in the allow list. Match it with errors.Is.
var ErrOutOfScope = errors.New("request target is out of scope")

type scopeTransport struct {
	allowed map[string]struct{}
	next    http.RoundTripper
}

// NewScope returns a RoundTripper that refuses any request whose host:port is
// not in allowHosts. Matching is exact on the normalized host:port: host names
// are lower-cased, a trailing dot is dropped, IPv6 literals are canonicalized,
// and an entry without a port matches the scheme default (80 for http, 443 for
// https). Entries that cannot be parsed are ignored, so a bad entry can only
// shrink the scope, never widen it. Because redirects are re-sent through the
// transport, they are subject to the same check.
func NewScope(allowHosts []string, next http.RoundTripper) http.RoundTripper {
	allowed := make(map[string]struct{})
	for _, e := range allowHosts {
		for _, k := range allowKeys(e) {
			allowed[k] = struct{}{}
		}
	}
	return &scopeTransport{allowed: allowed, next: next}
}

func (s *scopeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key, err := requestKey(req.URL)
	if err != nil {
		closeBody(req)
		return nil, err
	}
	if _, ok := s.allowed[key]; !ok {
		closeBody(req)
		// Only host:port is reported; the URL may carry secrets in its query.
		return nil, fmt.Errorf("%w: %s is not in scope.allowHosts", ErrOutOfScope, key)
	}
	return s.next.RoundTrip(req)
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// normHost lower-cases a host, drops a trailing dot and canonicalizes IP literals.
func normHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return h
}

func normPort(p string) (string, bool) {
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", false
	}
	return strconv.Itoa(n), true
}

// allowKeys expands one allowHosts entry into normalized host:port keys.
func allowKeys(entry string) []string {
	e := strings.TrimSpace(entry)
	if e == "" || strings.ContainsAny(e, "/@?# \t") {
		return nil
	}
	host, port := e, ""
	if h, p, err := net.SplitHostPort(e); err == nil {
		if p == "" {
			return nil
		}
		host, port = h, p
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(e, "["), "]")
	}
	host = normHost(host)
	if host == "" {
		return nil
	}
	if port != "" {
		p, ok := normPort(port)
		if !ok {
			return nil
		}
		return []string{net.JoinHostPort(host, p)}
	}
	return []string{net.JoinHostPort(host, "80"), net.JoinHostPort(host, "443")}
}

// requestKey returns the normalized host:port a request will connect to.
func requestKey(u *url.URL) (string, error) {
	if u == nil || u.Hostname() == "" {
		return "", fmt.Errorf("%w: request has no host", ErrOutOfScope)
	}
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("%w: unsupported scheme %q", ErrOutOfScope, u.Scheme)
		}
	}
	p, ok := normPort(port)
	if !ok {
		return "", fmt.Errorf("%w: invalid port %q", ErrOutOfScope, port)
	}
	return net.JoinHostPort(normHost(u.Hostname()), p), nil
}
