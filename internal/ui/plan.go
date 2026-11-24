package ui

import (
	"context"
	"errors"

	"math"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/engine"
	"github.com/ardayesilcayir/authdiff/pkg/authdiff"
)

// planGroup is the plan of one rule.
type planGroup struct {
	RuleID      string
	Rows        []engine.PlannedRequest
	Destructive int
}

type planData struct {
	P           *Project
	Groups      []planGroup
	Total       int
	Destructive int
	Rate        float64
	ETA         string
	Missing     []string
	Err         string // why there is no plan; the page then has no scan button
	Active      string // path of the running scan, if any
}

// estimate is how long n requests take at rate requests per second,
// rounded up to whole seconds; 0 if the rate is unknown.
func estimate(n int, rate float64) time.Duration {
	if n <= 0 || rate <= 0 {
		return 0
	}
	return time.Duration(math.Ceil(float64(n)/rate)) * time.Second
}

// groupPlan groups the plan by rule, in order of each rule's first request.
func groupPlan(plan []engine.PlannedRequest) []planGroup {
	var out []planGroup
	index := map[string]int{}
	for _, pr := range plan {
		i, ok := index[pr.RuleID]
		if !ok {
			i = len(out)
			index[pr.RuleID] = i
			out = append(out, planGroup{RuleID: pr.RuleID})
		}
		out[i].Rows = append(out[i].Rows, pr)
		if pr.Destructive {
			out[i].Destructive++
		}
	}
	return out
}

// buildPlan runs the dry run for p with placeholder credentials, so the
// plan works before the tokens are entered. No request reaches the target;
// a URL spec is downloaded.
func (s *Server) buildPlan(ctx context.Context, p *Project) (planData, error) {
	d := planData{P: p, Missing: s.secrets.Missing(p), Active: s.activePath()}
	cfg, err := PlaceholderConfig(p)
	if err != nil {
		return d, err
	}
	ctx, cancel := context.WithTimeout(ctx, inventoryTimeout)
	defer cancel()
	plan, err := authdiff.PlanContext(ctx, authdiff.ScanOptions{
		Config: cfg, BaseDir: s.store.Dir(p.Name), Version: s.opts.Version, Log: s.opts.Log,
	})
	if err != nil {
		return d, err
	}
	d.Groups = groupPlan(plan)
	d.Total = len(plan)
	for _, g := range d.Groups {
		d.Destructive += g.Destructive
	}
	d.Rate = cfg.Safety.Rate
	if eta := estimate(d.Total, d.Rate); eta > 0 {
		d.ETA = eta.String()
	}
	return d, nil
}

// renderPlan shows the plan, or with err the reason there is none (422,
// with a link back to the target step and no scan button).
func (s *Server) renderPlan(w http.ResponseWriter, r *http.Request, d planData, err error) {
	pd := s.newPage(r, "plan.title")
	pd.Nav = "projects"
	status := http.StatusOK
	if err != nil {
		status = http.StatusUnprocessableEntity
		d.Err = err.Error()
		d.Groups, d.Total, d.Destructive = nil, 0, 0
	}
	pd.Data = d
	s.render(w, status, "plan", pd)
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	d, err := s.buildPlan(r.Context(), p)
	if err != nil {
		s.opts.Log.Info("no plan", "project", p.Name, "err", err)
	}
	s.renderPlan(w, r, d, err)
}

// activePath is the live page of the running scan, or "".
func (s *Server) activePath() string {
	if s.runs == nil {
		return ""
	}
	if id, project := s.runs.active(); id != "" {
		return "/p/" + project + "/runs/" + id
	}
	return ""
}

// handleScan starts a scan of the project: missing credentials go to the
// profiles step, invalid settings get the plan page's error (422), a
// running scan a 409 page.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	if len(s.secrets.Missing(p)) > 0 {
		redirect(w, r, "/p/"+p.Name+"/profiles?missing=1")
		return
	}
	cfg, err := BuildConfig(p, s.secrets, s.store.Dir(p.Name))
	var miss ErrMissingSecrets
	if errors.As(err, &miss) {
		redirect(w, r, "/p/"+p.Name+"/profiles?missing=1")
		return
	}
	if err != nil {
		s.renderPlan(w, r, planData{P: p, Active: s.activePath()}, err)
		return
	}
	id, err := s.runs.Start(p, cfg, s.store.Dir(p.Name))
	if errors.Is(err, ErrBusy) {
		s.renderBusy(w, r)
		return
	}
	if err != nil {
		s.opts.Log.Error("start scan", "project", p.Name, "err", err)
		s.renderError(w, r, http.StatusInternalServerError)
		return
	}
	redirect(w, r, "/p/"+p.Name+"/runs/"+id)
}

// renderBusy is the 409 page for a second scan, linking the running one.
func (s *Server) renderBusy(w http.ResponseWriter, r *http.Request) {
	pd := s.newPage(r, "error.409.title")
	pd.Data = errorData{Status: http.StatusConflict, TitleKey: "error.409.title", BodyKey: "error.409.body", Href: s.activePath()}
	s.render(w, http.StatusConflict, "error", pd)
}

type runPageData struct {
	P      *Project
	Run    runView
	Events string // SSE path
}

// handleRun is the live page of a run. A finished run, or one only on
// disk from an earlier session, goes to its results.
func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !validRunID(id) {
		s.renderError(w, r, http.StatusNotFound)
		return
	}
	results := "/p/" + p.Name + "/runs/" + id + "/results"
	v, ok := s.runs.view(id)
	if !ok {
		if _, err := os.Stat(filepath.Join(s.store.RunsDir(p.Name), id, "results.json")); err == nil { //nolint:gosec // G703: name and id are validated (nameRe, runIDRe)
			redirect(w, r, results)
			return
		}
		s.renderError(w, r, http.StatusNotFound)
		return
	}
	if v.Project != p.Name {
		s.renderError(w, r, http.StatusNotFound)
		return
	}
	if v.Final == "done" {
		redirect(w, r, results)
		return
	}
	pd := s.newPage(r, "run.title")
	pd.Nav = "projects"
	pd.Data = runPageData{P: p, Run: v, Events: "/api/runs/" + id + "/events"}
	s.render(w, http.StatusOK, "run", pd)
}
