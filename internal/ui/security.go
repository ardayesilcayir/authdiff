package ui

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	// sessionCookiePrefix + the port is the session cookie's name: cookies
	// are not separated by port, so two instances need distinct names.
	sessionCookiePrefix = "authdiff_session_"
	// cspHeader is the exact policy from the design (§7, rule 4).
	cspHeader = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
	// maxRequestBody caps every request body: a 10 MiB spec upload plus
	// form overhead.
	maxRequestBody = 12 << 20
)

type ctxKey int

const authedKey ctxKey = 0

// authed reports whether secure() accepted r's session.
func authed(r *http.Request) bool {
	v, _ := r.Context().Value(authedKey).(bool)
	return v
}

func setSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", cspHeader)
	h.Set("X-Content-Type-Options", "nosniff")
	// same-origin, not no-referrer: under no-referrer browsers send Origin
	// "null" and no Referer on form POSTs, which the Origin check rejects.
	// Other origins still get no Referer.
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
}

// secure wraps every route, in this order: security headers on every
// response; Host must be 127.0.0.1 or localhost on our port (421, DNS
// rebinding); ?key= on a GET logs in (cookie + 303 to the URL without the
// key) or fails with 401; no valid session cookie is 401; a state-changing
// method needs our Origin (or Referer) and the CSRF token (403).
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w.Header())
		if !s.validHost(r.Host) {
			s.renderError(w, r, http.StatusMisdirectedRequest)
			return
		}
		q := r.URL.Query()
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && q.Has("key") {
			s.login(w, r, q)
			return
		}
		if !s.validSession(r) {
			s.renderError(w, r, http.StatusUnauthorized)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), authedKey, true))
		if !safeMethod(r.Method) {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
			if !s.sameOrigin(r) {
				s.opts.Log.Warn("blocked cross-origin request", "method", r.Method, "path", r.URL.Path)
				s.renderError(w, r, http.StatusForbidden)
				return
			}
			ok, err := s.validCSRF(r)
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			if !ok {
				s.opts.Log.Warn("blocked request without a valid CSRF token", "method", r.Method, "path", r.URL.Path)
				s.renderError(w, r, http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// validHost accepts exactly 127.0.0.1:<port> and localhost:<port>.
func (s *Server) validHost(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || port != fmt.Sprint(s.port.Load()) {
		return false
	}
	return host == "127.0.0.1" || strings.EqualFold(host, "localhost")
}

// login checks the key from the terminal URL, sets the session cookie and
// redirects to the same URL without the key so it leaves the address bar
// and history.
func (s *Server) login(w http.ResponseWriter, r *http.Request, q url.Values) {
	if !equalSecret(q.Get("key"), s.key) {
		s.opts.Log.Warn("rejected a wrong session key")
		s.renderError(w, r, http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: plain-http loopback server; Secure would drop the cookie
		Name:     s.cookieName(),
		Value:    s.key,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	q.Del("key")
	loc := r.URL.EscapedPath()
	if enc := q.Encode(); enc != "" {
		loc += "?" + enc
	}
	http.Redirect(w, r, localPath(loc), http.StatusSeeOther) //nolint:gosec // G710: localPath allows only paths on this server
}

// cookieName is the session cookie's name, authdiff_session_<port>.
func (s *Server) cookieName() string {
	return fmt.Sprintf("%s%d", sessionCookiePrefix, s.port.Load())
}

func (s *Server) validSession(r *http.Request) bool {
	c, err := r.Cookie(s.cookieName())
	return err == nil && equalSecret(c.Value, s.key)
}

// sameOrigin requires the Origin header, or the Referer's origin when the
// browser sent no Origin, to be this server.
func (s *Server) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		ref, err := url.Parse(r.Header.Get("Referer"))
		if err != nil || ref.Scheme == "" || ref.Host == "" {
			return false
		}
		origin = ref.Scheme + "://" + ref.Host
	}
	origin = strings.ToLower(origin)
	p := s.port.Load()
	return origin == fmt.Sprintf("http://127.0.0.1:%d", p) || origin == fmt.Sprintf("http://localhost:%d", p)
}

// validCSRF checks the X-CSRF-Token header or the csrf form field. It
// parses the form (in memory, bounded by maxRequestBody) so handlers can
// read r.PostForm / r.MultipartForm afterwards.
func (s *Server) validCSRF(r *http.Request) (bool, error) {
	if tok := r.Header.Get("X-CSRF-Token"); tok != "" {
		return equalSecret(tok, s.csrf), nil
	}
	var err error
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		err = r.ParseMultipartForm(maxRequestBody) //nolint:gosec // G120: body capped by MaxBytesReader in secure()
	} else {
		err = r.ParseForm()
	}
	if err != nil {
		return false, err
	}
	return equalSecret(r.PostFormValue("csrf"), s.csrf), nil
}

func equalSecret(got, want string) bool {
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
