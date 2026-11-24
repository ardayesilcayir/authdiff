package ui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed templates
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// staticRoot is staticFS without the "static/" prefix.
var staticRoot = func() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return sub
}()

const (
	layoutFile = "templates/layout.html.tmpl"
	// partialsGlob holds shared {{define}} blocks parsed into every page.
	partialsGlob = "templates/partials/*.tmpl"
)

// pageTemplate is one page parsed together with the shared layout.
type pageTemplate struct{ t *template.Template }

// pageData is what every template receives. Pages put their own data in
// Data; T translates in the request's language.
type pageData struct {
	T       func(key string, args ...any) string
	Lang    string
	CSRF    string // empty when the request has no session
	Title   string
	Flash   string
	Version string
	Path    string // request path and query, for the language form's next
	Nav     string // which top-level nav entry is current: "home", "projects"
	Data    any
}

// templateFuncs are the helpers available to every template. pair passes
// the page data together with an item to a {{template}} block:
// {{template "card" (pair $ .)}}, then {{index . 0}} / {{index . 1}}.
var templateFuncs = template.FuncMap{
	"pair": func(a, b any) []any { return []any{a, b} },
}

// loadPages parses every templates/*.html.tmpl except the layout as its own
// page: page "home" is home.html.tmpl + layout + the partials.
func loadPages() (map[string]*pageTemplate, error) {
	files, err := fs.Glob(templateFS, "templates/*.html.tmpl")
	if err != nil {
		return nil, err
	}
	pages := map[string]*pageTemplate{}
	for _, f := range files {
		if f == layoutFile {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(f, "templates/"), ".html.tmpl")
		t, err := template.New("layout.html.tmpl").Funcs(templateFuncs).ParseFS(templateFS, layoutFile, partialsGlob, f)
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		pages[name] = &pageTemplate{t: t}
	}
	return pages, nil
}

// newPage builds the shared page data for r with a translated title.
func (s *Server) newPage(r *http.Request, titleKey string) *pageData {
	lang := negotiateLang(r)
	pd := &pageData{
		T:       translator(s.cat[lang]),
		Lang:    lang,
		Version: s.opts.Version,
		Path:    r.URL.RequestURI(),
	}
	if authed(r) {
		pd.CSRF = s.csrf
	}
	pd.Title = pd.T(titleKey)
	return pd
}

// render executes page into a buffer first so a template error becomes a
// clean 500 instead of a half-written page.
func (s *Server) render(w http.ResponseWriter, status int, page string, pd *pageData) {
	pt, ok := s.pages[page]
	var buf bytes.Buffer
	if !ok {
		s.opts.Log.Error("unknown page template", "page", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := pt.t.ExecuteTemplate(&buf, "layout.html.tmpl", pd); err != nil {
		s.opts.Log.Error("render", "page", page, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

type errorData struct {
	Status   int
	TitleKey string
	BodyKey  string
	Href     string // optional local link shown with the message (e.g. the running scan)
}

// errorPages holds the message keys per status; other statuses use 500's.
var errorPages = map[int]errorData{
	http.StatusBadRequest:          {TitleKey: "error.400.title", BodyKey: "error.400.body"},
	http.StatusUnauthorized:        {TitleKey: "error.401.title", BodyKey: "error.401.body"},
	http.StatusForbidden:           {TitleKey: "error.403.title", BodyKey: "error.403.body"},
	http.StatusNotFound:            {TitleKey: "error.404.title", BodyKey: "error.404.body"},
	http.StatusConflict:            {TitleKey: "error.409.title", BodyKey: "error.409.body"},
	http.StatusMisdirectedRequest:  {TitleKey: "error.421.title", BodyKey: "error.421.body"},
	http.StatusInternalServerError: {TitleKey: "error.500.title", BodyKey: "error.500.body"},
}

// renderError writes the error page for status. It never carries the CSRF
// token unless the request had a valid session.
func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int) {
	d, ok := errorPages[status]
	if !ok {
		d = errorPages[http.StatusInternalServerError]
	}
	d.Status = status
	pd := s.newPage(r, d.TitleKey)
	pd.Data = d
	s.render(w, status, "error", pd)
}
