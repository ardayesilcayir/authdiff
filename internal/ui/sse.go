package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// sseHeartbeat is how often an event stream gets a comment line, so
// proxies and browsers keep an idle connection open.
var sseHeartbeat = 15 * time.Second

// handleRunEvents streams a run's events as Server-Sent Events:
// "event: <type>\ndata: <json>\n\n". A late subscriber first gets the
// current state; the stream ends after the done or error event. Leaving
// the page only ends the stream, never the scan.
func (s *Server) handleRunEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validRunID(id) {
		s.renderError(w, r, http.StatusNotFound)
		return
	}
	ch, unsubscribe := s.runs.Subscribe(id)
	if ch == nil {
		s.renderError(w, r, http.StatusNotFound)
		return
	}
	defer unsubscribe()
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	tick := time.NewTicker(sseHeartbeat)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if err := writeEvent(w, ev); err != nil {
				s.opts.Log.Debug("event stream", "run", id, "err", err)
				return
			}
			if ev.Type == "done" || ev.Type == "error" {
				_ = rc.Flush()
				return
			}
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}

// writeEvent writes one SSE message; JSON has no raw newlines, so the data
// fits one line.
func writeEvent(w http.ResponseWriter, ev Event) error {
	b, err := json.Marshal(ev.Data)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, b)
	return err
}

// handleStopRun cancels a run and waits for its partial results. A script
// (X-CSRF-Token header) gets {"results": path}; a plain form goes back to
// the run page, which forwards to the results.
func (s *Server) handleStopRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validRunID(id) {
		s.renderError(w, r, http.StatusNotFound)
		return
	}
	v, ok := s.runs.view(id)
	if !ok {
		s.renderError(w, r, http.StatusNotFound)
		return
	}
	// A run that finished meanwhile is not an error: its page shows the
	// outcome (results or the reason it failed).
	if err := s.runs.Stop(id); err != nil && !errors.Is(err, ErrNotRunning) {
		s.renderError(w, r, http.StatusInternalServerError)
		return
	}
	runPath := "/p/" + v.Project + "/runs/" + id
	if r.Header.Get("X-CSRF-Token") != "" {
		next := runPath
		if v, _ := s.runs.view(id); v.Final == "done" {
			next = runPath + "/results"
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{"results": next})
		return
	}
	redirect(w, r, runPath)
}
