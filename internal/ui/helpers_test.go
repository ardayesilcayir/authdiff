package ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testPort = 7465

// testServer builds a Server whose lab check points at an unreachable
// address unless o.LabURL is set.
func testServer(t *testing.T, o Options) *Server {
	t.Helper()
	if o.Port == 0 {
		o.Port = testPort
	}
	if o.LabURL == "" {
		o.LabURL = "http://127.0.0.1:1"
	}
	if o.ProjectsDir == "" {
		o.ProjectsDir = t.TempDir()
	}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// req builds a request with a valid Host header and, if authed, the session
// cookie.
func req(s *Server, method, target string, body io.Reader, authed bool) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.Host = "127.0.0.1:7465"
	if authed {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.key}) //nolint:gosec // G124: request cookie in a test
	}
	return r
}

// postForm builds an authenticated same-origin POST carrying the CSRF token.
func postForm(s *Server, target string, form url.Values) *http.Request {
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf", s.csrf)
	r := req(s, http.MethodPost, target, strings.NewReader(form.Encode()), true)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://127.0.0.1:7465")
	return r
}

func do(s *Server, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
