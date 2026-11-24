package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/report"
	"github.com/ardayesilcayir/authdiff/pkg/authdiff"
)

// Errors of the RunManager.
var (
	ErrBusy       = errors.New("a scan is already running")
	ErrNotRunning = errors.New("no such running scan")
)

const (
	runIDLayout = "20060102-150405"
	// hookBuffer holds engine progress events until the pump applies them;
	// the hook drops events when it is full.
	hookBuffer = 1024
	// subBuffer is each subscriber's buffer; a slow subscriber loses
	// events (the counters are cumulative, the final event is never lost).
	subBuffer = 64
	// progressEvery throttles progress events to subscribers.
	progressEvery = 200 * time.Millisecond
	// maxLiveFindings is how many preliminary findings a run keeps.
	maxLiveFindings = 200
	// keepRuns is how many finished runs stay in memory for their pages.
	keepRuns = 20
	// stopWait bounds how long Stop waits for the partial results.
	stopWait = 10 * time.Second
)

// runFormats are the files written into each run directory.
var runFormats = []string{"json", "sarif", "html"}

var runIDRe = regexp.MustCompile(`^\d{8}-\d{6}(-\d+)?$`)

// validRunID reports whether s has the shape of a run ID
// (20060102-150405, optionally followed by -N).
func validRunID(s string) bool { return runIDRe.MatchString(s) }

// Event is one message to a run's subscribers. Type is "progress"
// (RunProgress), "finding" (RunFinding), "done" (RunDone) or "error"
// (RunError); done and error are the last event.
type Event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// RunProgress are a run's live counters. Percent is Sent/Planned capped at
// 99 until the run is done; Planned is the dry-run estimate.
type RunProgress struct {
	Phase     int            `json:"phase"`
	PhaseName string         `json:"phaseName"`
	Sent      int            `json:"sent"`
	Planned   int            `json:"planned"`
	Blocked   int            `json:"blocked"`
	Errors    int            `json:"errors"`
	Findings  int            `json:"findings"`
	Severity  map[string]int `json:"severity"`
	Percent   int            `json:"percent"`
}

// RunFinding is a preliminary finding as it was reported during the scan.
// The final, merged list is in results.json.
type RunFinding struct {
	Time     string `json:"time"`
	ID       string `json:"id"`
	Severity string `json:"severity"`
	RuleID   string `json:"ruleId"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Victim   string `json:"victim,omitempty"`
	Attacker string `json:"attacker,omitempty"`
}

// RunDone ends a run that produced results. Status is "done", "stopped"
// (cancelled; partial results) or "failed" (the scan stopped on an error
// after sending requests; partial results, Message says why).
type RunDone struct {
	Status   string `json:"status"`
	Sent     int    `json:"sent"`
	Blocked  int    `json:"blocked"`
	Errors   int    `json:"errors"`
	Findings int    `json:"findings"`
	Results  string `json:"results"`
	Message  string `json:"message,omitempty"`
}

// RunError ends a run without results.
type RunError struct {
	Message string `json:"message"`
}

// scanFunc is authdiff.Scan; tests may replace it.
type scanFunc func(context.Context, authdiff.ScanOptions) (*authdiff.Result, error)

// RunManager runs at most one scan at a time, in the background context of
// the server (not of the HTTP request that started it), and fans its
// progress out to subscribers.
type RunManager struct {
	ctx     context.Context
	cancel  context.CancelFunc
	version string
	log     *slog.Logger
	scan    scanFunc
	now     func() time.Time

	mu   sync.Mutex
	runs map[string]*run
	cur  *run
}

// run is one scan, running or finished. Fields below mu are guarded by it.
type run struct {
	id, project, dir string
	started          time.Time
	cancel           context.CancelFunc
	done             chan struct{}
	hook             chan authdiff.Progress

	mu       sync.Mutex
	prog     RunProgress
	seen     map[string]bool
	findings []RunFinding
	final    *Event
	subs     map[chan Event]struct{}
	lastProg time.Time
}

func newRunManager(version string, log *slog.Logger) *RunManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &RunManager{
		ctx: ctx, cancel: cancel, version: version, log: log,
		scan: authdiff.Scan, now: time.Now, runs: map[string]*run{},
	}
}

// Start begins scanning p with cfg (credentials included; never written to
// disk) in the background. Results go to <projectDir>/runs/<runID>/. It
// returns ErrBusy while another scan runs.
func (m *RunManager) Start(p *Project, cfg *config.Config, projectDir string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur != nil {
		return "", ErrBusy
	}
	if p == nil || cfg == nil {
		return "", errors.New("start scan: no project or config")
	}
	if m.ctx.Err() != nil {
		return "", errors.New("start scan: the server is shutting down")
	}
	id, dir, err := m.newRunDir(filepath.Join(projectDir, runsDir))
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithCancel(m.ctx)
	r := &run{
		id: id, project: p.Name, dir: dir, started: m.now(), cancel: cancel,
		done: make(chan struct{}), hook: make(chan authdiff.Progress, hookBuffer),
		prog: RunProgress{Severity: map[string]int{}}, seen: map[string]bool{},
		subs: map[chan Event]struct{}{},
	}
	m.runs[id] = r
	m.cur = r
	m.prune()
	opts := authdiff.ScanOptions{
		Config: cfg, BaseDir: projectDir, OnProgress: r.onProgress,
		IgnoreFile: filepath.Join(projectDir, ignoreFile), Version: m.version, Log: m.log,
	}
	m.log.Info("scan started", "project", p.Name, "run", id)
	go m.execute(ctx, r, opts)
	return id, nil
}

// newRunDir creates runs/<ID> (0700) for a new run; an ID already on disk
// or in memory gets a -2, -3... suffix. Called with m.mu held.
func (m *RunManager) newRunDir(root string) (string, string, error) {
	if err := os.MkdirAll(root, dirPerm); err != nil {
		return "", "", fmt.Errorf("runs dir: %w", err)
	}
	base := m.now().Format(runIDLayout)
	for n := 1; n < 1000; n++ {
		id := base
		if n > 1 {
			id = fmt.Sprintf("%s-%d", base, n)
		}
		if m.runs[id] != nil {
			continue
		}
		dir := filepath.Join(root, id)
		err := os.Mkdir(dir, dirPerm)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", "", fmt.Errorf("run dir: %w", err)
		}
		return id, dir, nil
	}
	return "", "", errors.New("run dir: too many runs in one second")
}

// prune forgets the oldest finished runs beyond keepRuns. Called with m.mu
// held.
func (m *RunManager) prune() {
	if len(m.runs) <= keepRuns {
		return
	}
	var old []*run
	for _, r := range m.runs {
		if r != m.cur {
			old = append(old, r)
		}
	}
	sort.Slice(old, func(i, j int) bool { return old[i].started.Before(old[j].started) })
	for _, r := range old[:len(m.runs)-keepRuns] {
		delete(m.runs, r.id)
	}
}

// execute runs the scan, writes the results and sends the final event.
func (m *RunManager) execute(ctx context.Context, r *run, opts authdiff.ScanOptions) {
	scanDone, pumpDone := make(chan struct{}), make(chan struct{})
	go r.pump(scanDone, pumpDone)
	res, err := m.safeScan(ctx, opts)
	close(scanDone)
	<-pumpDone
	r.cancel()

	ev := m.persist(r, res, err)
	r.finish(ev)
	m.mu.Lock()
	if m.cur == r {
		m.cur = nil
	}
	m.mu.Unlock()
	m.log.Info("scan finished", "project", r.project, "run", r.id, "event", ev.Type)
	close(r.done)
}

// safeScan turns a panic in the scan into an error so the server lives on.
func (m *RunManager) safeScan(ctx context.Context, opts authdiff.ScanOptions) (res *authdiff.Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			m.log.Error("scan panicked", "panic", p)
			res, err = nil, errors.New("internal error during the scan; see the terminal log")
		}
	}()
	return m.scan(ctx, opts)
}

// persist writes the result files and builds the final event. A run
// without a result leaves no directory behind.
func (m *RunManager) persist(r *run, res *authdiff.Result, scanErr error) Event {
	if res == nil {
		if scanErr == nil {
			scanErr = errors.New("the scan returned no result")
		}
		_ = os.Remove(r.dir) // only if empty
		return Event{Type: "error", Data: RunError{Message: scanErr.Error()}}
	}
	if _, err := report.Write(r.dir, runFormats, res, io.Discard, false); err != nil {
		m.log.Error("write scan results", "run", r.id, "err", err)
		return Event{Type: "error", Data: RunError{Message: "could not save the results: " + err.Error()}}
	}
	d := RunDone{
		Status: "done", Sent: res.Stats.Requests, Blocked: res.Stats.Blocked, Errors: res.Stats.Errors,
		Findings: len(res.Active()), Results: "/p/" + r.project + "/runs/" + r.id + "/results",
	}
	switch {
	case errors.Is(scanErr, context.Canceled):
		d.Status = "stopped"
	case scanErr != nil:
		d.Status, d.Message = "failed", scanErr.Error()
	}
	return Event{Type: "done", Data: d}
}

// onProgress is the engine hook. It is called serialized from engine
// goroutines and must never block or panic: it only offers the event to
// the pump and drops it when the buffer is full.
func (r *run) onProgress(p authdiff.Progress) {
	defer func() { _ = recover() }()
	select {
	case r.hook <- p:
	default:
	}
}

// pump applies hook events until the scan returned, then drains the rest.
func (r *run) pump(scanDone <-chan struct{}, pumpDone chan<- struct{}) {
	defer close(pumpDone)
	for {
		select {
		case p := <-r.hook:
			r.apply(p)
		case <-scanDone:
			for {
				select {
				case p := <-r.hook:
					r.apply(p)
				default:
					return
				}
			}
		}
	}
}

// apply updates the counters with p and tells the subscribers: every new
// finding at once, progress at most every progressEvery or on a phase
// change.
func (r *run) apply(p authdiff.Progress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.final != nil {
		return
	}
	phaseChanged := p.Phase != r.prog.Phase
	r.prog.Phase, r.prog.PhaseName = p.Phase, p.PhaseName
	r.prog.Sent, r.prog.Planned, r.prog.Blocked, r.prog.Errors = p.Sent, p.Planned, p.Blocked, p.Errors
	r.prog.Percent = percent(p.Sent, p.Planned)
	newFinding := false
	if f := p.Finding; f != nil && !r.seen[f.ID] {
		r.seen[f.ID] = true
		rf := RunFinding{
			Time: time.Now().Format("15:04:05"), ID: f.ID, Severity: string(f.Severity), RuleID: f.RuleID,
			Method: f.Method, Path: f.Path, Victim: f.Victim, Attacker: f.Attacker,
		}
		r.findings = append(r.findings, rf)
		if len(r.findings) > maxLiveFindings {
			r.findings = r.findings[len(r.findings)-maxLiveFindings:]
		}
		r.prog.Findings++
		r.prog.Severity[rf.Severity]++
		r.broadcast(Event{Type: "finding", Data: rf})
		newFinding = true
	}
	if now := time.Now(); newFinding || phaseChanged || now.Sub(r.lastProg) >= progressEvery {
		r.lastProg = now
		r.broadcast(Event{Type: "progress", Data: r.snapshot()})
	}
}

// percent is min(sent/planned, 99%) as a whole number.
func percent(sent, planned int) int {
	if planned <= 0 || sent <= 0 {
		return 0
	}
	if pc := sent * 100 / planned; pc < 99 {
		return pc
	}
	return 99
}

// snapshot copies the counters. Called with r.mu held.
func (r *run) snapshot() RunProgress {
	s := r.prog
	s.Severity = make(map[string]int, len(r.prog.Severity))
	for k, v := range r.prog.Severity {
		s.Severity[k] = v
	}
	return s
}

// broadcast offers ev to every subscriber, dropping it for a full one.
// Called with r.mu held.
func (r *run) broadcast(ev Event) {
	for ch := range r.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// finish records the final event, delivers it to every subscriber (making
// room by dropping their oldest event if needed) and closes them.
func (r *run) finish(ev Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d, ok := ev.Data.(RunDone); ok {
		r.prog.Sent, r.prog.Blocked, r.prog.Errors = d.Sent, d.Blocked, d.Errors
		r.prog.Percent = 100
	}
	r.final = &ev
	for ch := range r.subs {
		select {
		case ch <- ev:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- ev:
			default:
			}
		}
		close(ch)
	}
	r.subs = map[chan Event]struct{}{}
}

// Subscribe returns the events of run runID: first the current counters
// and the preliminary findings so far, then live events; the channel is
// closed after the final event or by the returned cancel function. An
// unknown run gives a nil channel.
func (m *RunManager) Subscribe(runID string) (<-chan Event, func()) {
	r := m.get(runID)
	if r == nil {
		return nil, func() {}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ch := make(chan Event, subBuffer)
	ch <- Event{Type: "progress", Data: r.snapshot()}
	fs := r.findings
	if limit := subBuffer - 2; len(fs) > limit {
		fs = fs[len(fs)-limit:]
	}
	for _, f := range fs {
		ch <- Event{Type: "finding", Data: f}
	}
	if r.final != nil {
		ch <- *r.final
		close(ch)
		return ch, func() {}
	}
	r.subs[ch] = struct{}{}
	return ch, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if _, ok := r.subs[ch]; ok {
			delete(r.subs, ch)
			close(ch)
		}
	}
}

// Stop cancels run runID and waits (bounded) until its partial results are
// written. A finished or unknown run gives ErrNotRunning.
func (m *RunManager) Stop(runID string) error {
	r := m.get(runID)
	if r == nil {
		return ErrNotRunning
	}
	select {
	case <-r.done:
		return ErrNotRunning
	default:
	}
	m.log.Info("scan stop requested", "run", runID)
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(stopWait):
	}
	return nil
}

func (m *RunManager) get(id string) *run {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runs[id]
}

// runView is what the live page shows of a run.
type runView struct {
	ID, Project string
	Finished    bool
	Progress    RunProgress
	Findings    []RunFinding // newest first
}

// view returns run id's current state for its page.
func (m *RunManager) view(id string) (runView, bool) {
	r := m.get(id)
	if r == nil {
		return runView{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v := runView{ID: r.id, Project: r.project, Finished: r.final != nil, Progress: r.snapshot()}
	for i := len(r.findings) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, r.findings[i])
	}
	return v, true
}

// active returns the running scan's ID and project, or "".
func (m *RunManager) active() (id, project string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur == nil {
		return "", ""
	}
	return m.cur.id, m.cur.project
}

// Active is the running scan's ID, or "".
func (m *RunManager) Active() string {
	id, _ := m.active()
	return id
}

// doneCh is closed when run id has finished; nil for an unknown run.
func (m *RunManager) doneCh(id string) <-chan struct{} {
	if r := m.get(id); r != nil {
		return r.done
	}
	return nil
}

// Shutdown cancels the running scan and waits, until ctx ends, for its
// partial results to be written. No scan starts afterwards.
func (m *RunManager) Shutdown(ctx context.Context) {
	m.cancel()
	m.mu.Lock()
	a := m.cur
	m.mu.Unlock()
	if a == nil {
		return
	}
	select {
	case <-a.done:
	case <-ctx.Done():
		m.log.Warn("scan did not stop in time; its results may be incomplete", "run", a.id)
	}
}
