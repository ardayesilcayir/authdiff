package transport

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrDestructiveBlocked is returned (wrapped) when a destructive method is
// attempted without --allow-destructive. Match it with errors.Is.
var ErrDestructiveBlocked = errors.New("destructive method blocked (use --allow-destructive to permit)")

var destructiveMethods = map[string]struct{}{
	http.MethodDelete: {},
	http.MethodPut:    {},
	http.MethodPatch:  {},
}

// Headers that make many frameworks treat a POST as another method.
var overrideHeaders = []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}

type safeMode struct {
	allowDestructive bool
	next             http.RoundTripper
}

// NewSafeMode blocks DELETE, PUT and PATCH unless allowDestructive is set.
// Method-override headers and the _method query parameter are checked too, so
// a POST cannot smuggle a destructive method past the filter.
func NewSafeMode(allowDestructive bool, next http.RoundTripper) http.RoundTripper {
	return &safeMode{allowDestructive: allowDestructive, next: next}
}

func (s *safeMode) RoundTrip(req *http.Request) (*http.Response, error) {
	if !s.allowDestructive {
		if m := destructiveIn(req); m != "" {
			closeBody(req)
			host := ""
			if req.URL != nil {
				host = req.URL.Host
			}
			return nil, fmt.Errorf("%w: %s %s", ErrDestructiveBlocked, m, host)
		}
	}
	return s.next.RoundTrip(req)
}

// destructiveIn returns the destructive method the request would perform, or "".
func destructiveIn(req *http.Request) string {
	if m := strings.ToUpper(req.Method); isDestructive(m) {
		return m
	}
	for _, h := range overrideHeaders {
		for _, v := range req.Header.Values(h) {
			if m := firstDestructive(v); m != "" {
				return m
			}
		}
	}
	if req.URL != nil {
		for _, v := range req.URL.Query()["_method"] {
			if m := firstDestructive(v); m != "" {
				return m
			}
		}
	}
	return ""
}

func firstDestructive(v string) string {
	for _, part := range strings.Split(v, ",") {
		if m := strings.ToUpper(strings.TrimSpace(part)); isDestructive(m) {
			return m
		}
	}
	return ""
}

func isDestructive(m string) bool {
	_, ok := destructiveMethods[m]
	return ok
}
