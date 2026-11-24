package ui

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/report"
)

const (
	// maxBodyShown caps each evidence body on the finding page; the full
	// (already redacted) body stays in results.json.
	maxBodyShown = 16 << 10
	// maxHistory is how many past runs the project page lists.
	maxHistory = 50
	// ruleDocBase is where each built-in rule's guidance lives.
	ruleDocBase = "https://github.com/ardayesilcayir/authdiff/blob/main/docs/rules/"
	resultsFile = "results.json"
)

// ruleIDRe is the rule ID shape (same as internal/rules).
var ruleIDRe = regexp.MustCompile(`^[A-Z]+(-[A-Z0-9]+)+$`)

// downloads are the run files offered for download, with their types.
var downloads = map[string]string{
	"results.json":  "application/json",
	"results.sarif": "application/sarif+json",
	"report.html":   "text/html; charset=utf-8",
}

// severities in display order.
var severities = []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info}

// ruleDocURL is the guidance page of rule id, or "" for an ID that does
// not have the rule ID shape.
func ruleDocURL(id string) string {
	if !ruleIDRe.MatchString(id) {
		return ""
	}
	return ruleDocBase + id + ".md"
}

// capBody returns s cut to at most n bytes on a rune boundary, and whether
// it was cut.
func capBody(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

// --- Loading a run ------------------------------------------------------------

// ignoreList reads the project's .authdiff-ignore: the baseline to apply
// and each ID's reason. A missing file is an empty list.
func (s *Server) ignoreList(project string) (*finding.Baseline, map[string]string, error) {
	path := filepath.Join(s.store.Dir(project), ignoreFile)
	b, err := finding.LoadBaseline(path)
	if err != nil {
		return nil, nil, err
	}
	reasons := map[string]string{}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: fixed file name in the validated project dir
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		id, reason, _ := strings.Cut(line, "#")
		if id = strings.TrimSpace(id); findingIDRe.MatchString(id) {
			reasons[id] = strings.TrimSpace(reason)
		}
	}
	return b, reasons, nil
}

// readResults decodes runs/<id>/results.json of project as written at scan
// time. It returns an error wrapping os.ErrNotExist when the run has no
// results.
func (s *Server) readResults(project, id string) (*finding.Result, error) {
	if !ValidName(project) || !validRunID(id) {
		return nil, os.ErrNotExist
	}
	f, err := os.Open(filepath.Join(s.store.RunsDir(project), id, resultsFile)) //nolint:gosec // G304: name and id are validated (nameRe, runIDRe)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return report.ReadJSON(f)
}

// readRun is readResults with the project's current ignore list applied,
// so triage shows at once, plus each ignored ID's reason.
func (s *Server) readRun(project, id string) (*finding.Result, map[string]string, error) {
	res, err := s.readResults(project, id)
	if err != nil {
		return nil, nil, err
	}
	base, reasons, err := s.ignoreList(project)
	if err != nil {
		return nil, nil, err
	}
	base.Apply(res.Findings)
	return res, reasons, nil
}

// loadRun loads the {name} project and its {id} run, answering 404 for an
// unknown project or run and 500 for an unreadable one.
func (s *Server) loadRun(w http.ResponseWriter, r *http.Request) (*Project, string, *finding.Result, map[string]string, bool) {
	p, ok := s.project(w, r)
	if !ok {
		return nil, "", nil, nil, false
	}
	id := r.PathValue("id")
	res, reasons, err := s.readRun(p.Name, id)
	if errors.Is(err, os.ErrNotExist) {
		s.renderError(w, r, http.StatusNotFound)
		return nil, "", nil, nil, false
	}
	if err != nil {
		s.opts.Log.Error("read run", "project", p.Name, "run", id, "err", err)
		s.renderError(w, r, http.StatusInternalServerError)
		return nil, "", nil, nil, false
	}
	return p, id, res, reasons, true
}

// --- Results page -----------------------------------------------------------

type tally struct {
	Severity finding.Severity
	Count    int
	Href     string // filter link
	Current  bool
}

type suppressedRow struct {
	F      finding.Finding
	Reason string
}

type resultsData struct {
	P          *Project
	RunID      string
	Base       string // /p/<name>/runs/<id>
	R          *finding.Result
	Started    string
	Duration   string
	Tallies    []tally
	Heatmap    template.HTML
	Rules      []string // rule IDs among the active findings, for the filter
	Sev, Rule  string   // current filter
	Filtered   bool
	Total      int // active findings
	Findings   []finding.Finding
	Suppressed []suppressedRow
	Status     runStatus // how the run ended; zero for runs before status.json
	NoResponse bool      // no request got an HTTP response
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	p, id, res, reasons, ok := s.loadRun(w, r)
	if !ok {
		return
	}
	d := resultsData{
		P: p, RunID: id, Base: "/p/" + p.Name + "/runs/" + id, R: res,
		Started:  res.StartedAt.Local().Format("2006-01-02 15:04:05"),
		Duration: res.FinishedAt.Sub(res.StartedAt).Round(100 * time.Millisecond).String(),
		Status:   readRunStatus(filepath.Join(s.store.RunsDir(p.Name), id)),
	}
	d.NoResponse = d.Status.NoResponse || noResponse(res.Stats)
	if sev, err := finding.ParseSeverity(r.URL.Query().Get("sev")); err == nil {
		d.Sev = string(sev)
	}
	active := res.Active()
	d.Total = len(active)
	rules := map[string]bool{}
	for _, f := range active {
		rules[f.RuleID] = true
	}
	if rule := r.URL.Query().Get("rule"); rules[rule] {
		d.Rule = rule
	}
	for id := range rules {
		d.Rules = append(d.Rules, id)
	}
	sort.Strings(d.Rules)
	d.Filtered = d.Sev != "" || d.Rule != ""
	for _, sev := range severities {
		t := tally{Severity: sev, Href: d.Base + "/results?sev=" + string(sev), Current: d.Sev == string(sev)}
		for _, f := range active {
			if f.Severity == sev {
				t.Count++
			}
		}
		d.Tallies = append(d.Tallies, t)
	}
	for _, f := range active {
		if (d.Sev == "" || string(f.Severity) == d.Sev) && (d.Rule == "" || f.RuleID == d.Rule) {
			d.Findings = append(d.Findings, f)
		}
	}
	for _, f := range res.Findings {
		if f.Suppressed {
			d.Suppressed = append(d.Suppressed, suppressedRow{F: f, Reason: reasons[f.ID]})
		}
	}
	hm, err := report.Heatmap(res)
	if err != nil {
		s.opts.Log.Error("render heatmap", "run", id, "err", err)
		s.renderError(w, r, http.StatusInternalServerError)
		return
	}
	d.Heatmap = hm
	pd := s.newPage(r, "results.title")
	pd.Nav = "projects"
	pd.Data = d
	s.render(w, http.StatusOK, "results", pd)
}

// --- Finding detail and triage ------------------------------------------------

type headerLine struct{ Name, Value string }

type exchangeView struct {
	finding.Exchange
	ReqHeaders, RespHeaders []headerLine
	ReqBody, RespBody       string
	ReqCut, RespCut         bool
}

type findingData struct {
	P       *Project
	RunID   string
	Base    string
	F       finding.Finding
	DocURL  string
	Reason  string // why it is suppressed, if it is
	Ex      []exchangeView
	Input   string // the reason typed, kept after an error
	Errors  formErrors
	CapKiB  int
	Percent string
}

func headerLines(h map[string]string) []headerLine {
	out := make([]headerLine, 0, len(h))
	for k, v := range h {
		out = append(out, headerLine{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// findingOf finds the {fid} finding in res, answering 404 if it is absent.
func (s *Server) findingOf(w http.ResponseWriter, r *http.Request, res *finding.Result) (finding.Finding, bool) {
	fid := r.PathValue("fid")
	if findingIDRe.MatchString(fid) {
		for _, f := range res.Findings {
			if f.ID == fid {
				return f, true
			}
		}
	}
	s.renderError(w, r, http.StatusNotFound)
	return finding.Finding{}, false
}

func (s *Server) renderFinding(w http.ResponseWriter, r *http.Request, status int, p *Project, id string, f finding.Finding, reasons map[string]string, input string, errs formErrors) {
	d := findingData{
		P: p, RunID: id, Base: "/p/" + p.Name + "/runs/" + id, F: f, DocURL: ruleDocURL(f.RuleID),
		Input: input, Errors: errs, CapKiB: maxBodyShown >> 10,
		Percent: fmt.Sprintf("%.0f%%", f.Similarity*100),
	}
	if errs == nil {
		d.Errors = formErrors{}
	}
	if f.Suppressed {
		d.Reason = reasons[f.ID]
	}
	for _, ex := range f.Evidence {
		v := exchangeView{Exchange: ex, ReqHeaders: headerLines(ex.RequestHeaders), RespHeaders: headerLines(ex.ResponseHeaders)}
		v.ReqBody, v.ReqCut = capBody(ex.RequestBody, maxBodyShown)
		v.RespBody, v.RespCut = capBody(ex.ResponseBody, maxBodyShown)
		d.Ex = append(d.Ex, v)
	}
	pd := s.newPage(r, "finding.title")
	pd.Nav = "projects"
	pd.Title = f.Title
	pd.Data = d
	s.render(w, status, "finding", pd)
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	p, id, res, reasons, ok := s.loadRun(w, r)
	if !ok {
		return
	}
	f, ok := s.findingOf(w, r, res)
	if !ok {
		return
	}
	s.renderFinding(w, r, http.StatusOK, p, id, f, reasons, "", nil)
}

// maxReason bounds the stored reason.
const maxReason = 500

// handleIgnore marks a finding as a false positive: it appends
// "<id> # <reason>" to the project's .authdiff-ignore, so the finding is
// suppressed on every results page and in later scans.
func (s *Server) handleIgnore(w http.ResponseWriter, r *http.Request) {
	p, id, res, reasons, ok := s.loadRun(w, r)
	if !ok {
		return
	}
	f, ok := s.findingOf(w, r, res)
	if !ok {
		return
	}
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if reason == "" {
		s.renderFinding(w, r, http.StatusUnprocessableEntity, p, id, f, reasons, "", formErrors{"reason": "finding.err.reason"})
		return
	}
	reason, _ = capBody(reason, maxReason)
	if err := s.store.AppendIgnore(p.Name, f.ID, reason); err != nil {
		s.opts.Log.Error("ignore finding", "project", p.Name, "finding", f.ID, "err", err)
		s.renderError(w, r, http.StatusInternalServerError)
		return
	}
	s.opts.Log.Info("finding ignored", "project", p.Name, "finding", f.ID)
	redirect(w, r, "/p/"+p.Name+"/runs/"+id+"/results#suppressed")
}

// --- Downloads ----------------------------------------------------------------

// handleDownload serves a run file as written at scan time (the ignore
// list of that moment), as an attachment.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	id, file := r.PathValue("id"), r.PathValue("file")
	ctype, known := downloads[file]
	if !validRunID(id) || !known {
		s.renderError(w, r, http.StatusNotFound)
		return
	}
	b, err := os.ReadFile(filepath.Join(s.store.RunsDir(p.Name), id, file)) //nolint:gosec // G304: name, id and file are validated (nameRe, runIDRe, fixed list)
	if errors.Is(err, os.ErrNotExist) {
		s.renderError(w, r, http.StatusNotFound)
		return
	}
	if err != nil {
		s.opts.Log.Error("download", "project", p.Name, "run", id, "file", file, "err", err)
		s.renderError(w, r, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+file+`"`)
	_, _ = w.Write(b) //nolint:gosec // G705: a run file sent as an attachment with a fixed type, nosniff and the CSP
}

// handleExport sends the project as a zip for the CLI (WriteExportZip). A
// project whose settings do not form a config yet gets its overview page
// with the reason (422).
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	var buf bytes.Buffer
	if err := WriteExportZip(&buf, s.store, p); err != nil {
		s.opts.Log.Info("export not possible", "project", p.Name, "err", err)
		s.render(w, http.StatusUnprocessableEntity, "project", s.overview(r, p, formErrors{"export": "project.export.err"}))
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+p.Name+`-authdiff.zip"`)
	_, _ = w.Write(buf.Bytes())
}

// --- History --------------------------------------------------------------------

// historyRow is one past run on the project page.
type historyRow struct {
	ID       string
	Started  string
	Findings int    // active, with the current ignore list
	Status   string // "stopped", "failed" or "" (completed or unknown)
	Href     string
}

// history lists the project's runs that have results, newest first, at
// most maxHistory. Unreadable runs are skipped.
func (s *Server) history(project string) []historyRow {
	entries, err := os.ReadDir(s.store.RunsDir(project))
	if err != nil {
		return nil
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() && validRunID(e.Name()) {
			ids = append(ids, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	base, _, err := s.ignoreList(project)
	if err != nil {
		s.opts.Log.Warn("read ignore file", "project", project, "err", err)
		base = &finding.Baseline{}
	}
	var rows []historyRow
	for _, id := range ids {
		if len(rows) == maxHistory {
			break
		}
		res, err := s.readResults(project, id)
		if err != nil {
			continue
		}
		base.Apply(res.Findings)
		row := historyRow{
			ID: id, Started: res.StartedAt.Local().Format("2006-01-02 15:04"),
			Findings: len(res.Active()), Href: "/p/" + project + "/runs/" + id + "/results",
		}
		if st := readRunStatus(filepath.Join(s.store.RunsDir(project), id)).Status; st == "stopped" || st == "failed" {
			row.Status = st
		}
		rows = append(rows, row)
	}
	return rows
}
