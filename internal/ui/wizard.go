package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/spec"
	"github.com/ardayesilcayir/authdiff/pkg/authdiff"
)

// inventoryTimeout bounds loading the spec for the endpoints and profiles
// pages (a URL spec is downloaded each time).
const inventoryTimeout = 30 * time.Second

// Wizard step IDs, in order. "plan" follows the last one.
var wizardSteps = []struct{ ID, Key string }{
	{"target", "wizard.step.target"},
	{"endpoints", "wizard.step.endpoints"},
	{"profiles", "wizard.step.profiles"},
	{"settings", "wizard.step.settings"},
}

func stepIndex(id string) int {
	for i, s := range wizardSteps {
		if s.ID == id {
			return i
		}
	}
	if id == "plan" {
		return len(wizardSteps)
	}
	return 0
}

// nextStep is the step after id ("plan" after settings).
func nextStep(id string) string {
	if i := stepIndex(id) + 1; i < len(wizardSteps) {
		return wizardSteps[i].ID
	}
	return "plan"
}

type stepItem struct {
	ID, Key, Href string
	Current, Done bool
}

// wizardData is what every wizard page gets; Form holds the step's own data.
type wizardData struct {
	P      *Project
	Steps  []stepItem
	Errors formErrors
	Form   any
}

// stepsFor lists the wizard steps for p with step marked current.
func stepsFor(p *Project, step string) []stepItem {
	reached := stepIndex(p.Step)
	items := make([]stepItem, 0, len(wizardSteps))
	for i, st := range wizardSteps {
		items = append(items, stepItem{
			ID: st.ID, Key: st.Key, Href: "/p/" + p.Name + "/" + st.ID,
			Current: st.ID == step, Done: i < reached && st.ID != step,
		})
	}
	return items
}

func (s *Server) wizardPage(r *http.Request, p *Project, step string, errs formErrors, form any) *pageData {
	pd := s.newPage(r, "wizard.step."+step)
	pd.Nav = "projects"
	if errs == nil {
		errs = formErrors{}
	}
	pd.Data = wizardData{P: p, Steps: stepsFor(p, step), Errors: errs, Form: form}
	return pd
}

// redirect sends a 303 to a local path.
func redirect(w http.ResponseWriter, r *http.Request, p string) {
	http.Redirect(w, r, localPath(p), http.StatusSeeOther) //nolint:gosec // G710: localPath allows only paths on this server
}

// project loads the {name} project, answering 404 for an invalid or
// unknown name and 500 for other errors.
func (s *Server) project(w http.ResponseWriter, r *http.Request) (*Project, bool) {
	name := r.PathValue("name")
	if !ValidName(name) {
		s.renderError(w, r, http.StatusNotFound)
		return nil, false
	}
	p, err := s.store.Get(name)
	if errors.Is(err, os.ErrNotExist) {
		s.renderError(w, r, http.StatusNotFound)
		return nil, false
	}
	if err != nil {
		s.opts.Log.Error("load project", "project", name, "err", err)
		s.renderError(w, r, http.StatusInternalServerError)
		return nil, false
	}
	return p, true
}

// saveAndContinue saves p with Step advanced past step (never moved
// backwards) and redirects to the next step.
func (s *Server) saveAndContinue(w http.ResponseWriter, r *http.Request, p *Project, step string) {
	next := nextStep(step)
	if stepIndex(next) > stepIndex(p.Step) {
		p.Step = next
	}
	if !s.save(w, r, p) {
		return
	}
	redirect(w, r, "/p/"+p.Name+"/"+next)
}

func (s *Server) save(w http.ResponseWriter, r *http.Request, p *Project) bool {
	if err := s.store.Save(p); err != nil {
		s.opts.Log.Error("save project", "project", p.Name, "err", err)
		s.renderError(w, r, http.StatusInternalServerError)
		return false
	}
	return true
}

// --- Projects -------------------------------------------------------------

type projectRow struct {
	Name    string
	Demo    bool
	Updated string
	Step    string
}

// projectRows lists the saved projects; a projects directory that does not
// exist yet is an empty list.
func (s *Server) projectRows() ([]projectRow, error) {
	list, err := s.store.List()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows := make([]projectRow, 0, len(list))
	for _, p := range list {
		rows = append(rows, projectRow{Name: p.Name, Demo: p.Demo, Updated: p.UpdatedAt.Local().Format("2006-01-02 15:04"), Step: p.Step})
	}
	return rows, nil
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	rows, err := s.projectRows()
	if err != nil {
		s.opts.Log.Error("list projects", "err", err)
		s.renderError(w, r, http.StatusInternalServerError)
		return
	}
	pd := s.newPage(r, "projects.title")
	pd.Nav = "projects"
	pd.Data = rows
	s.render(w, http.StatusOK, "projects", pd)
}

type newProjectData struct {
	Name   string
	Errors formErrors
}

func (s *Server) handleNewProjectForm(w http.ResponseWriter, r *http.Request) {
	pd := s.newPage(r, "newproject.title")
	pd.Nav = "projects"
	pd.Data = newProjectData{Errors: formErrors{}}
	s.render(w, http.StatusOK, "newproject", pd)
}

func (s *Server) handleNewProject(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	errs := formErrors{}
	if !ValidName(name) {
		errs.add("name", msg{Key: "newproject.err.name"})
	} else if _, err := s.store.Get(name); err == nil {
		errs.add("name", msg{Key: "newproject.err.exists"})
	}
	if len(errs) > 0 {
		pd := s.newPage(r, "newproject.title")
		pd.Nav = "projects"
		pd.Data = newProjectData{Name: name, Errors: errs}
		s.render(w, http.StatusUnprocessableEntity, "newproject", pd)
		return
	}
	p := &Project{Name: name, Step: "target", Safety: SafetyDef{Rate: 5, Concurrency: 4, TimeoutSec: 10}}
	if !s.save(w, r, p) {
		return
	}
	redirect(w, r, "/p/"+name+"/target")
}

type overviewData struct {
	P       *Project
	Spec    string
	Next    string
	Missing []string
	Steps   []stepItem
	Errors  formErrors
}

func (s *Server) overview(r *http.Request, p *Project, errs formErrors) *pageData {
	pd := s.newPage(r, "project.title")
	pd.Nav = "projects"
	pd.Title = p.Name
	next := p.Step
	if next == "" {
		next = "target"
	}
	if errs == nil {
		errs = formErrors{}
	}
	pd.Data = overviewData{
		P: p, Spec: specLabel(p), Next: next, Missing: s.secrets.Missing(p),
		Steps: stepsFor(p, ""), Errors: errs,
	}
	return pd
}

// specLabel is the spec location shown to the user, URLs redacted.
func specLabel(p *Project) string {
	if p.SpecURL != "" {
		return authdiff.RedactURL(p.SpecURL)
	}
	return p.SpecFile
}

func (s *Server) handleProject(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	s.render(w, http.StatusOK, "project", s.overview(r, p, nil))
}

func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	if r.PostFormValue("sure") != "yes" {
		s.render(w, http.StatusUnprocessableEntity, "project", s.overview(r, p, formErrors{"sure": "project.err.sure"}))
		return
	}
	if err := os.RemoveAll(s.store.Dir(p.Name)); err != nil {
		s.opts.Log.Error("delete project", "project", p.Name, "err", err)
		s.renderError(w, r, http.StatusInternalServerError)
		return
	}
	s.secrets.forget(p.Name)
	s.opts.Log.Info("project deleted", "project", p.Name)
	redirect(w, r, "/projects")
}

func (s *Server) handleDemo(w http.ResponseWriter, r *http.Request) {
	p, err := EnsureDemo(s.store, s.secrets, s.opts.LabURL)
	if err != nil {
		s.opts.Log.Error("demo project", "err", err)
		s.renderError(w, r, http.StatusInternalServerError)
		return
	}
	redirect(w, r, "/p/"+p.Name+"/plan")
}

// --- Target ---------------------------------------------------------------

func (s *Server) handleTargetForm(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	f := targetForm{BaseURL: p.BaseURL, SpecURL: p.SpecURL, AllowHosts: strings.Join(p.AllowHosts, "\n"), Ack: p.Acknowledged, SpecFile: p.SpecFile}
	s.render(w, http.StatusOK, "wizard_target", s.wizardPage(r, p, "target", nil, f))
}

func (s *Server) handleTarget(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	f, in, errs := parseTarget(r, p)
	if len(errs) > 0 {
		s.render(w, http.StatusUnprocessableEntity, "wizard_target", s.wizardPage(r, p, "target", errs, f))
		return
	}
	if in.upload != nil {
		file, err := in.upload.Open()
		if err != nil {
			s.renderError(w, r, http.StatusBadRequest)
			return
		}
		name, err := s.store.SaveSpec(p.Name, file, extOf(in.upload.Filename))
		_ = file.Close()
		if err != nil {
			errs.add("specFile", msg{Key: "target.err.spec_save"})
			s.render(w, http.StatusUnprocessableEntity, "wizard_target", s.wizardPage(r, p, "target", errs, f))
			return
		}
		p.SpecFile, p.SpecURL = name, ""
	} else if in.specURL != "" {
		p.SpecURL, p.SpecFile = in.specURL, ""
	}
	p.BaseURL = in.baseURL
	p.AllowHosts = in.allowHosts
	p.Acknowledged = true
	s.saveAndContinue(w, r, p, "target")
}

func extOf(name string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i:]
	}
	return ""
}

// --- Endpoints ------------------------------------------------------------

// errNoTarget means the target step is not complete.
var errNoTarget = errors.New("target step incomplete")

// inventoryConfig is a minimal config for loading p's spec: target, scope
// and transport settings plus an anonymous profile, never real secrets.
func inventoryConfig(p *Project) *config.Config {
	c := &config.Config{
		Version: 1,
		Target:  config.Target{BaseURL: p.BaseURL, Spec: p.SpecURL},
		Scope:   config.Scope{AllowHosts: cloneStrs(p.AllowHosts), AcknowledgeAuthorization: p.Acknowledged},
		Safety: config.Safety{
			Timeout:  time.Duration(p.Safety.TimeoutSec) * time.Second,
			Insecure: p.Safety.Insecure,
			Proxy:    p.Safety.Proxy,
		},
		Profiles: map[string]config.Profile{"anonymous": {Name: "anonymous", Role: "none", Auth: config.Auth{Type: "none"}}},
	}
	if p.SpecFile != "" {
		c.Target.Spec = p.SpecFile
	}
	return c
}

// inventory loads p's full (unfiltered) endpoint inventory. Errors are
// already redacted by pkg/authdiff; the spec URL is redacted again here in
// case it appears verbatim.
func (s *Server) inventory(ctx context.Context, p *Project) (*spec.Inventory, error) {
	if p.BaseURL == "" || (p.SpecURL == "" && p.SpecFile == "") || !p.Acknowledged {
		return nil, errNoTarget
	}
	ctx, cancel := context.WithTimeout(ctx, inventoryTimeout)
	defer cancel()
	inv, err := authdiff.LoadInventoryConfig(ctx, inventoryConfig(p), s.store.Dir(p.Name), s.opts.Version)
	if err != nil {
		text := err.Error()
		if p.SpecURL != "" {
			text = strings.ReplaceAll(text, p.SpecURL, authdiff.RedactURL(p.SpecURL))
		}
		return nil, errors.New(text)
	}
	return inv, nil
}

type endpointRow struct {
	Key, Method, Path, OperationID, Params, Tags string
	Secured, Checked                             bool
}

type tagItem struct {
	Name    string
	Checked bool
}

type endpointsForm struct {
	Title, Spec string
	Rows        []endpointRow
	Tags        []tagItem
	LoadErr     string // redacted load error
	NoTarget    bool
}

func endpointsFormFor(p *Project, inv *spec.Inventory, selected map[string]bool, tags []string) endpointsForm {
	f := endpointsForm{Title: inv.Title, Spec: specLabel(p)}
	allTags := map[string]bool{}
	for _, e := range inv.Endpoints {
		var params []string
		for _, pa := range e.Params {
			params = append(params, pa.In+":"+pa.Name)
		}
		for _, t := range e.Tags {
			allTags[t] = true
		}
		checked := !matchAnyPattern(p.Exclude, e)
		if selected != nil {
			checked = selected[e.Key()]
		}
		f.Rows = append(f.Rows, endpointRow{
			Key: e.Key(), Method: e.Method, Path: e.Path, OperationID: e.OperationID,
			Params: strings.Join(params, ", "), Tags: strings.Join(e.Tags, ", "), Secured: e.Secured, Checked: checked,
		})
	}
	for t := range allTags {
		f.Tags = append(f.Tags, tagItem{Name: t, Checked: oneOf(t, tags)})
	}
	sort.Slice(f.Tags, func(i, j int) bool { return f.Tags[i].Name < f.Tags[j].Name })
	return f
}

func matchAnyPattern(patterns []string, e spec.Endpoint) bool {
	for _, pat := range patterns {
		if spec.MatchEndpoint(pat, e) {
			return true
		}
	}
	return false
}

// escapeGlob escapes the glob metacharacters of an endpoint key so an
// exclude entry matches exactly that operation.
func escapeGlob(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\*?[]`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *Server) loadErrForm(p *Project, err error) endpointsForm {
	if errors.Is(err, errNoTarget) {
		return endpointsForm{NoTarget: true, Spec: specLabel(p)}
	}
	return endpointsForm{LoadErr: err.Error(), Spec: specLabel(p)}
}

func (s *Server) handleEndpointsForm(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	inv, err := s.inventory(r.Context(), p)
	if err != nil {
		s.render(w, http.StatusUnprocessableEntity, "wizard_endpoints", s.wizardPage(r, p, "endpoints", nil, s.loadErrForm(p, err)))
		return
	}
	s.render(w, http.StatusOK, "wizard_endpoints", s.wizardPage(r, p, "endpoints", nil, endpointsFormFor(p, inv, nil, p.Tags)))
}

func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	inv, err := s.inventory(r.Context(), p)
	if err != nil {
		s.render(w, http.StatusUnprocessableEntity, "wizard_endpoints", s.wizardPage(r, p, "endpoints", nil, s.loadErrForm(p, err)))
		return
	}
	selected := map[string]bool{}
	for _, k := range r.PostForm["ep"] {
		selected[k] = true
	}
	var exclude []string
	n := 0
	for _, e := range inv.Endpoints {
		if selected[e.Key()] {
			n++
		} else {
			exclude = append(exclude, escapeGlob(e.Key()))
		}
	}
	var tags []string
	for _, t := range r.PostForm["tag"] {
		if t = strings.TrimSpace(t); t != "" && !oneOf(t, tags) {
			tags = append(tags, t)
		}
	}
	if n == 0 {
		errs := formErrors{"ep": "endpoints.err.none"}
		s.render(w, http.StatusUnprocessableEntity, "wizard_endpoints", s.wizardPage(r, p, "endpoints", errs, endpointsFormFor(p, inv, selected, tags)))
		return
	}
	p.Exclude, p.Tags = exclude, tags
	s.saveAndContinue(w, r, p, "endpoints")
}

// --- Profiles -------------------------------------------------------------

type ownsField struct {
	Param, Value string
}

type profileCardView struct {
	Index       int
	Orig        string
	Def         ProfileDef
	Identifiers string
	Owns        []ownsField
	OwnsParam   string
	OwnsIDs     string
	Masked      map[string]string
	Missing     bool
}

type profilesForm struct {
	Cards        []profileCardView
	Blank        profileCardView
	Roles        []string
	AuthTypes    []string
	SameRoleWarn bool
	Missing      []string
}

// ownsParams suggests owned-ID parameters: the inventory's path parameters
// (if the spec loads) plus every parameter a profile already lists.
func (s *Server) ownsParams(ctx context.Context, p *Project, cards []profileCard) []string {
	set := map[string]bool{}
	if inv, err := s.inventory(ctx, p); err == nil {
		for _, e := range inv.Endpoints {
			for _, pp := range e.PathParams() {
				if paramNameRe.MatchString(pp) {
					set[pp] = true
				}
			}
		}
	}
	for _, c := range cards {
		for k := range c.Def.Owns {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func cardsOf(p *Project) []profileCard {
	cards := make([]profileCard, 0, len(p.Profiles))
	for i, d := range p.Profiles {
		cards = append(cards, profileCard{Index: i, Orig: d.Name, Def: d, Identifiers: strings.Join(d.Identifiers, ", ")})
	}
	return cards
}

func (s *Server) profilesView(ctx context.Context, p *Project, cards []profileCard) profilesForm {
	params := s.ownsParams(ctx, p, cards)
	f := profilesForm{Roles: roles, AuthTypes: authTypes, Missing: s.secrets.Missing(p)}
	missing := map[string]bool{}
	for _, m := range f.Missing {
		missing[m] = true
	}
	view := func(c profileCard) profileCardView {
		v := profileCardView{
			Index: c.Index, Orig: c.Orig, Def: c.Def, Identifiers: c.Identifiers,
			OwnsParam: c.OwnsParam, OwnsIDs: c.OwnsIDs, Missing: missing[c.Orig],
		}
		if c.Orig != "" {
			v.Masked = s.secrets.Masked(p.Name, c.Orig)
		}
		for _, pp := range params {
			v.Owns = append(v.Owns, ownsField{Param: pp, Value: strings.Join(c.Def.Owns[pp], ", ")})
		}
		return v
	}
	next := 0
	var defs []ProfileDef
	for _, c := range cards {
		f.Cards = append(f.Cards, view(c))
		defs = append(defs, c.Def)
		if c.Index >= next {
			next = c.Index + 1
		}
	}
	f.Blank = view(profileCard{Index: next, Def: ProfileDef{Role: "user", AuthType: "bearer"}})
	f.SameRoleWarn = needsSameRoleWarning(defs)
	return f
}

func (s *Server) handleProfilesForm(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	s.render(w, http.StatusOK, "wizard_profiles", s.wizardPage(r, p, "profiles", nil, s.profilesView(r.Context(), p, cardsOf(p))))
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	cards, errs := parseProfiles(r)
	template := r.PostFormValue("action") == "template"
	if len(cards) == 0 && !template {
		errs.add("profiles", msg{Key: "profiles.err.none"})
	}
	candidate := *p
	candidate.Profiles = nil
	for _, c := range cards {
		candidate.Profiles = append(candidate.Profiles, c.Def)
	}
	if template {
		for _, t := range templateProfiles() {
			if !hasProfile(candidate.Profiles, t.Name) {
				candidate.Profiles = append(candidate.Profiles, t)
			}
		}
	}
	if len(errs) == 0 {
		if err := ValidateProfileNames(&candidate); err != nil {
			errs.add("profiles", msg{Key: "profiles.err.env"})
		}
	}
	if len(errs) > 0 {
		s.render(w, http.StatusUnprocessableEntity, "wizard_profiles", s.wizardPage(r, p, "profiles", errs, s.profilesView(r.Context(), p, cards)))
		return
	}

	// New credentials: a submitted field wins, a blank one keeps the stored
	// value (followed through a rename).
	newSecrets := map[string]Secret{}
	for _, c := range cards {
		old, _ := s.secrets.Get(p.Name, c.Orig)
		var sec Secret
		for _, f := range secretFields(c.Def.AuthType) {
			v := c.secret.field(f)
			if v == "" {
				v = old.field(f)
			}
			sec.setField(f, v)
		}
		newSecrets[c.Def.Name] = sec
	}
	for _, old := range p.Profiles {
		if _, kept := newSecrets[old.Name]; !kept {
			s.secrets.Set(p.Name, old.Name, Secret{})
		}
	}
	for name, sec := range newSecrets {
		s.secrets.Set(p.Name, name, sec)
	}

	p.Profiles = candidate.Profiles
	if template || r.PostFormValue("action") == "stay" {
		if s.save(w, r, p) {
			redirect(w, r, "/p/"+p.Name+"/profiles")
		}
		return
	}
	s.saveAndContinue(w, r, p, "profiles")
}

func hasProfile(defs []ProfileDef, name string) bool {
	for _, d := range defs {
		if d.Name == name {
			return true
		}
	}
	return false
}

// --- Settings -------------------------------------------------------------

type settingsView struct {
	settingsForm
	Columns []string
	Rows    []matrixRowView
	Demo    bool
	// AlreadyDestructive is true when destructive mode was confirmed before.
	AlreadyDestructive bool
}

type matrixCell struct {
	Value   string
	Checked bool
}

type matrixRowView struct {
	Index   int
	Pattern string
	Cells   []matrixCell
}

func settingsFormOf(p *Project) settingsForm {
	f := settingsForm{
		Rate: fmtFloat(p.Safety.Rate, 5), Concurrency: fmtInt(p.Safety.Concurrency, 4), Timeout: fmtInt(p.Safety.TimeoutSec, 10),
		Destructive: p.Safety.AllowDestructive, IgnoreFields: strings.Join(p.IgnoreFields, "\n"),
		Proxy: p.Safety.Proxy, Insecure: p.Safety.Insecure,
	}
	if p.Threshold > 0 {
		f.Threshold = fmtFloat(p.Threshold, 0)
	}
	keys := make([]string, 0, len(p.Matrix))
	for k := range p.Matrix {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		f.Matrix = append(f.Matrix, matrixRow{Index: i, Pattern: k, Allow: p.Matrix[k]})
	}
	return f
}

func fmtFloat(v, def float64) string {
	if v <= 0 {
		v = def
	}
	return fmt.Sprint(v)
}

func fmtInt(v, def int) string {
	if v <= 0 {
		v = def
	}
	return fmt.Sprint(v)
}

func settingsViewOf(p *Project, f settingsForm) settingsView {
	v := settingsView{settingsForm: f, Columns: matrixColumns(p), Demo: p.Demo, AlreadyDestructive: p.Safety.AllowDestructive}
	next := 0
	row := func(index int, pattern string, allow []string) matrixRowView {
		rv := matrixRowView{Index: index, Pattern: pattern}
		for _, c := range v.Columns {
			rv.Cells = append(rv.Cells, matrixCell{Value: c, Checked: oneOf(c, allow)})
		}
		return rv
	}
	for _, m := range f.Matrix {
		v.Rows = append(v.Rows, row(m.Index, m.Pattern, m.Allow))
		if m.Index >= next {
			next = m.Index + 1
		}
	}
	v.Rows = append(v.Rows, row(next, "", nil))
	return v
}

func (s *Server) handleSettingsForm(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	s.render(w, http.StatusOK, "wizard_settings", s.wizardPage(r, p, "settings", nil, settingsViewOf(p, settingsFormOf(p))))
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	p, ok := s.project(w, r)
	if !ok {
		return
	}
	f, out, errs := parseSettings(r, p)
	if len(errs) > 0 {
		s.render(w, http.StatusUnprocessableEntity, "wizard_settings", s.wizardPage(r, p, "settings", errs, settingsViewOf(p, f)))
		return
	}
	if out.Safety.AllowDestructive && !p.Safety.AllowDestructive {
		s.opts.Log.Warn("destructive mode turned on", "project", p.Name)
	}
	if r.PostFormValue("action") == "stay" {
		if s.save(w, r, out) {
			redirect(w, r, "/p/"+out.Name+"/settings")
		}
		return
	}
	s.saveAndContinue(w, r, out, "settings")
}

// forget drops every credential held for project.
func (s *Secrets) forget(project string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, project)
}
