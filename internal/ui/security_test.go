package ui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const wantCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

func TestNoSessionIs401(t *testing.T) {
	s := testServer(t, Options{})
	for _, p := range []string{"/", "/healthz", "/static/app.css", "/nope"} {
		w := do(s, req(s, http.MethodGet, p, nil, false))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", p, w.Code)
		}
	}
	w := do(s, req(s, http.MethodGet, "/", nil, false))
	if strings.Contains(w.Body.String(), s.csrf) {
		t.Error("401 page leaks the CSRF token")
	}
	// A wrong cookie is no session either.
	r := req(s, http.MethodGet, "/", nil, false)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: strings.Repeat("0", 64)}) //nolint:gosec // G124: request cookie in a test
	if w := do(s, r); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong cookie: status %d", w.Code)
	}
}

func TestKeyLoginSetsCookieAndRedirects(t *testing.T) {
	s := testServer(t, Options{})
	w := do(s, req(s, http.MethodGet, "/?key=deadbeef", nil, false))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong key: status %d, want 401", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("wrong key set a cookie")
	}

	w = do(s, req(s, http.MethodGet, "/?key="+s.key+"&x=1", nil, false))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("right key: status %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/?x=1" {
		t.Errorf("Location = %q, want /?x=1", loc)
	}
	set := w.Header().Get("Set-Cookie")
	for _, want := range []string{sessionCookie + "=" + s.key, "Path=/", "HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(set, want) {
			t.Errorf("Set-Cookie %q lacks %q", set, want)
		}
	}
	w = do(s, req(s, http.MethodGet, "/healthz?key="+s.key, nil, false))
	if loc := w.Header().Get("Location"); loc != "/healthz" {
		t.Errorf("Location = %q, want /healthz", loc)
	}
	// With the cookie the page is served.
	if w := do(s, req(s, http.MethodGet, "/healthz", nil, true)); w.Code != http.StatusOK {
		t.Errorf("healthz with cookie: %d", w.Code)
	}
}

func TestBadHostIs421(t *testing.T) {
	s := testServer(t, Options{})
	for _, h := range []string{"evil.com:7465", "127.0.0.1.nip.io:7465", "127.0.0.1:7466", "127.0.0.1", "localhost", "[::1]:7465", ""} {
		r := req(s, http.MethodGet, "/", nil, true)
		r.Host = h
		if w := do(s, r); w.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: status %d, want 421", h, w.Code)
		}
	}
	for _, h := range []string{"127.0.0.1:7465", "localhost:7465", "LOCALHOST:7465"} {
		r := req(s, http.MethodGet, "/", nil, true)
		r.Host = h
		if w := do(s, r); w.Code != http.StatusOK {
			t.Errorf("Host %q: status %d, want 200", h, w.Code)
		}
	}
}

func TestPostWithoutCSRFIs403(t *testing.T) {
	s := testServer(t, Options{})
	form := url.Values{"lang": {"tr"}}
	r := req(s, http.MethodPost, "/lang", strings.NewReader(form.Encode()), true)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://127.0.0.1:7465")
	if w := do(s, r); w.Code != http.StatusForbidden {
		t.Errorf("no token: status %d, want 403", w.Code)
	}
	form.Set("csrf", "wrong")
	r = req(s, http.MethodPost, "/lang", strings.NewReader(form.Encode()), true)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://127.0.0.1:7465")
	if w := do(s, r); w.Code != http.StatusForbidden {
		t.Errorf("wrong token: status %d, want 403", w.Code)
	}
	// Header token works.
	r = req(s, http.MethodPost, "/lang", strings.NewReader("lang=tr"), true)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://localhost:7465")
	r.Header.Set("X-CSRF-Token", s.csrf)
	if w := do(s, r); w.Code != http.StatusSeeOther {
		t.Errorf("header token: status %d, want 303", w.Code)
	}
	// Without a session, POST is 401 regardless of the token.
	r = postForm(s, "/lang", url.Values{"lang": {"tr"}})
	r.Header.Del("Cookie")
	if w := do(s, r); w.Code != http.StatusUnauthorized {
		t.Errorf("no session: status %d, want 401", w.Code)
	}
}

func TestPostForeignOriginIs403(t *testing.T) {
	s := testServer(t, Options{})
	cases := []struct {
		name, origin, referer string
		want                  int
	}{
		{"foreign origin", "http://evil.com", "", http.StatusForbidden},
		{"other port", "http://127.0.0.1:8000", "", http.StatusForbidden},
		{"null origin", "null", "", http.StatusForbidden},
		{"https origin", "https://127.0.0.1:7465", "", http.StatusForbidden},
		{"neither", "", "", http.StatusForbidden},
		{"foreign referer", "", "http://evil.com/x", http.StatusForbidden},
		{"lookalike referer", "", "http://127.0.0.1:7465.evil.com/", http.StatusForbidden},
		{"own referer", "", "http://127.0.0.1:7465/somewhere", http.StatusSeeOther},
		{"own origin", "http://127.0.0.1:7465", "", http.StatusSeeOther},
	}
	for _, c := range cases {
		r := postForm(s, "/lang", url.Values{"lang": {"en"}})
		r.Header.Del("Origin")
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if c.referer != "" {
			r.Header.Set("Referer", c.referer)
		}
		if w := do(s, r); w.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, w.Code, c.want)
		}
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	s := testServer(t, Options{})
	badHost := req(s, http.MethodGet, "/", nil, true)
	badHost.Host = "evil.com:7465"
	cases := map[string]*http.Request{
		"home":     req(s, http.MethodGet, "/", nil, true),
		"static":   req(s, http.MethodGet, "/static/app.css", nil, true),
		"js":       req(s, http.MethodGet, "/static/app.js", nil, true),
		"401":      req(s, http.MethodGet, "/", nil, false),
		"404":      req(s, http.MethodGet, "/no/such/page", nil, true),
		"421":      badHost,
		"403":      req(s, http.MethodPost, "/lang", nil, true),
		"redirect": req(s, http.MethodGet, "/?key="+s.key, nil, false),
	}
	for name, r := range cases {
		w := do(s, r)
		h := w.Header()
		if got := h.Get("Content-Security-Policy"); got != wantCSP {
			t.Errorf("%s (%d): CSP = %q", name, w.Code, got)
		}
		for k, v := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy":        "same-origin",
			"Cache-Control":          "no-store",
		} {
			if got := h.Get(k); got != v {
				t.Errorf("%s (%d): %s = %q, want %q", name, w.Code, k, got, v)
			}
		}
	}
	if w := do(s, cases["404"]); w.Code != http.StatusNotFound {
		t.Errorf("404 case: status %d", w.Code)
	}
	if w := do(s, req(s, http.MethodGet, "/static/app.css", nil, true)); w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") {
		t.Errorf("app.css: status %d type %q", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestStaticDirectoryListingIs404(t *testing.T) {
	s := testServer(t, Options{})
	for _, p := range []string{"/static/", "/static/missing.js"} {
		if w := do(s, req(s, http.MethodGet, p, nil, true)); w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, w.Code)
		}
	}
}

// TestReferrerPolicyIsSameOrigin pins the exact Referrer-Policy. It must not
// be "no-referrer": with that policy browsers serialize the Origin of a
// form-submission navigation as "null" (Fetch: "serializing a request
// origin") and send no Referer, so every HTML form POST failed the Origin
// check with 403 in a real browser. "same-origin" still sends nothing to
// other origins, and the session key is already stripped from the URL by
// the login redirect.
func TestReferrerPolicyIsSameOrigin(t *testing.T) {
	s := testServer(t, Options{})
	w := do(s, req(s, http.MethodGet, "/", nil, true))
	if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy = %q, want same-origin", got)
	}
	// What a browser sends for a form POST under same-origin: a same-origin
	// Referer (and Origin). It must pass; Origin "null" must still fail.
	r := postForm(s, "/lang", url.Values{"lang": {"en"}})
	r.Header.Del("Origin")
	r.Header.Set("Referer", "http://127.0.0.1:7465/")
	if w := do(s, r); w.Code != http.StatusSeeOther {
		t.Errorf("form POST with same-origin Referer: status %d, want 303", w.Code)
	}
	r = postForm(s, "/lang", url.Values{"lang": {"en"}})
	r.Header.Set("Origin", "null")
	r.Header.Set("Referer", "http://127.0.0.1:7465/")
	if w := do(s, r); w.Code != http.StatusForbidden {
		t.Errorf("Origin null: status %d, want 403", w.Code)
	}
}
