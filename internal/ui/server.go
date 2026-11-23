// Package ui implements `authdiff ui`: a local web interface served on
// 127.0.0.1 that drives the same engine as the CLI. Every request needs the
// session cookie obtained from the key printed in the terminal; see
// security.go for the request checks.
package ui

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults for Options.
const (
	DefaultPort   = 7465
	DefaultLabURL = "http://127.0.0.1:8000"
	// maxPortTries is how many consecutive ports Listen tries.
	maxPortTries = 10
	// shutdownGrace bounds how long Serve waits for open requests.
	shutdownGrace = 5 * time.Second
)

// Options configure a Server.
type Options struct {
	Port        int    // first port to try; 0 means DefaultPort
	ProjectsDir string // "" means DefaultProjectsDir()
	Version     string
	LabURL      string // demo lab base URL; "" means DefaultLabURL
	Log         *slog.Logger
}

// Server is the UI web server. Create it with New, bind with Listen, run
// with Serve.
type Server struct {
	opts    Options
	key     string // session key (hex), printed once in the terminal
	csrf    string // CSRF token bound to the session key
	port    atomic.Int64
	cat     catalog
	pages   map[string]*pageTemplate
	mux     *http.ServeMux
	handler http.Handler
	ln      net.Listener

	store   *Store
	secrets *Secrets

	mu       sync.Mutex
	onStop   []func(context.Context)
	checkLab func(ctx context.Context, labURL string) bool
}

// DefaultProjectsDir is <user config dir>/authdiff/projects, or a directory
// next to the working directory if the config dir is unknown.
func DefaultProjectsDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "authdiff", "projects")
}

// New prepares a Server: generates the session key, loads translations and
// templates and registers the routes. It does not touch the network.
func New(o Options) (*Server, error) {
	if o.Port == 0 {
		o.Port = DefaultPort
	}
	if o.Port < 0 || o.Port > 65535 {
		return nil, fmt.Errorf("port %d out of range", o.Port)
	}
	if o.LabURL == "" {
		o.LabURL = DefaultLabURL
	}
	if o.ProjectsDir == "" {
		o.ProjectsDir = DefaultProjectsDir()
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("session key: %w", err)
	}
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte("authdiff-ui csrf"))

	cat, err := loadCatalog()
	if err != nil {
		return nil, err
	}
	pages, err := loadPages()
	if err != nil {
		return nil, err
	}
	s := &Server{
		opts:      o,
		key:       hex.EncodeToString(raw),
		csrf:      hex.EncodeToString(mac.Sum(nil)),
		cat:       cat,
		pages:     pages,
		mux:       http.NewServeMux(),
		checkLab: CheckLab,
		// The projects directory is created on the first save, so New has
		// no side effect on disk.
		store:   &Store{root: o.ProjectsDir},
		secrets: NewSecrets(),
	}
	s.port.Store(int64(o.Port))
	s.routes()
	s.handler = s.secure(s.mux)
	return s, nil
}

// routes registers this package's handlers. Later handlers use the same
// method-aware ServeMux patterns, e.g. "GET /p/{name}/target".
func (s *Server) routes() {
	s.mux.HandleFunc("GET /{$}", s.handleHome)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /static/", s.handleStatic)
	s.mux.HandleFunc("POST /lang", s.handleLang)
	s.mux.HandleFunc("POST /demo", s.handleDemo)
	s.mux.HandleFunc("GET /projects", s.handleProjects)
	s.mux.HandleFunc("GET /projects/new", s.handleNewProjectForm)
	s.mux.HandleFunc("POST /projects/new", s.handleNewProject)
	s.mux.HandleFunc("GET /p/{name}", s.handleProject)
	s.mux.HandleFunc("POST /p/{name}/delete", s.handleDeleteProject)
	s.mux.HandleFunc("GET /p/{name}/target", s.handleTargetForm)
	s.mux.HandleFunc("POST /p/{name}/target", s.handleTarget)
	s.mux.HandleFunc("GET /p/{name}/endpoints", s.handleEndpointsForm)
	s.mux.HandleFunc("POST /p/{name}/endpoints", s.handleEndpoints)
	s.mux.HandleFunc("GET /p/{name}/profiles", s.handleProfilesForm)
	s.mux.HandleFunc("POST /p/{name}/profiles", s.handleProfiles)
	s.mux.HandleFunc("GET /p/{name}/settings", s.handleSettingsForm)
	s.mux.HandleFunc("POST /p/{name}/settings", s.handleSettings)
	s.mux.HandleFunc("/", s.handleNotFound)
}

// Handler returns the full handler including the security checks.
func (s *Server) Handler() http.Handler { return s.handler }

// OnShutdown registers f to run when Serve's context is cancelled, before
// the HTTP server closes (e.g. to cancel a running scan and write its
// partial results).
func (s *Server) OnShutdown(f func(context.Context)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onStop = append(s.onStop, f)
}

// Listen binds 127.0.0.1 on the configured port, or the next free one (up to
// maxPortTries ports), and returns the session URL including the key.
func (s *Server) Listen() (string, error) {
	first := s.opts.Port
	var lastErr error
	for p := first; p < first+maxPortTries && p <= 65535; p++ {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(p)))
		if err != nil {
			lastErr = err
			continue
		}
		s.ln = ln
		s.port.Store(int64(ln.Addr().(*net.TCPAddr).Port))
		if p != first {
			s.opts.Log.Info("port busy, using the next free one", "wanted", first, "port", p)
		}
		return s.URL(), nil
	}
	return "", fmt.Errorf("no free port in %d-%d on 127.0.0.1: %w", first, first+maxPortTries-1, lastErr)
}

// URL is the session URL with the key, valid once Listen succeeded.
func (s *Server) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/?key=%s", s.port.Load(), s.key)
}

// Serve answers requests until ctx is cancelled, then runs the shutdown
// hooks and closes the server. It calls Listen if that was not done yet.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		if _, err := s.Listen(); err != nil {
			return err
		}
	}
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.opts.Log.Handler(), slog.LevelDebug),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(s.ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	s.mu.Lock()
	hooks := append([]func(context.Context){}, s.onStop...)
	s.mu.Unlock()
	for _, h := range hooks {
		h(stopCtx)
	}
	if err := srv.Shutdown(stopCtx); err != nil {
		_ = srv.Close()
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// recentProject is one row of the home page's project list.
type recentProject struct {
	Name    string
	Updated string
}

// maxRecent is how many projects the home page lists.
const maxRecent = 5

type homeData struct {
	LabOK    bool
	LabURL   string
	Projects []recentProject
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	pd := s.newPage(r, "home.title")
	pd.Nav = "home"
	var recent []recentProject
	rows, err := s.projectRows()
	if err != nil {
		s.opts.Log.Warn("list projects", "err", err)
	}
	for i, row := range rows {
		if i == maxRecent {
			break
		}
		recent = append(recent, recentProject{Name: row.Name, Updated: row.Updated})
	}
	pd.Data = homeData{
		LabOK:    s.checkLab(r.Context(), s.opts.LabURL),
		LabURL:   s.opts.LabURL,
		Projects: recent,
	}
	s.render(w, http.StatusOK, "home", pd)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = fmt.Fprintf(w, `{"status":"ok","version":%q}`, s.opts.Version)
}

// handleStatic serves embedded files only; no directory listings.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/static/")
	if f, err := fs.Stat(staticRoot, name); err != nil || f.IsDir() || strings.HasSuffix(r.URL.Path, "/") {
		s.renderError(w, r, http.StatusNotFound)
		return
	}
	http.ServeFileFS(w, r, staticRoot, name) //nolint:gosec // G703: read-only embedded FS, name is path.Clean-ed
}

// handleLang stores the chosen language in a cookie and returns to the page
// the form was on (a local path only).
func (s *Server) handleLang(w http.ResponseWriter, r *http.Request) {
	lang := r.PostFormValue("lang")
	if !supportedLang(lang) {
		s.renderError(w, r, http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: plain-http loopback server; Secure would drop the cookie
		Name:     langCookie,
		Value:    lang,
		Path:     "/",
		MaxAge:   365 * 24 * 3600,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, localPath(r.PostFormValue("next")), http.StatusSeeOther) //nolint:gosec // G710: localPath allows only paths on this server
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, http.StatusNotFound)
}

// localPath returns p if it is a path on this server, otherwise "/". It
// rejects scheme-relative ("//host") and backslash tricks browsers treat as
// such, and control characters, which browsers strip (a tab between two
// slashes is dropped, giving "//host").
func localPath(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.Contains(p, `\`) {
		return "/"
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return p
}
