package report

import (
	"bytes"
	"strings"
	"testing"
)

// Scan notes (e.g. disabled TLS verification) appear in the HTML header and
// the terminal output.
func TestNotesRendered(t *testing.T) {
	r := fixture()
	r.Notes = []string{"TLS verification disabled (insecure)"}
	var h bytes.Buffer
	if err := WriteHTML(&h, r); err != nil {
		t.Fatal(err)
	}
	head := h.String()
	if i := strings.Index(head, "</header>"); i < 0 || !strings.Contains(head[:i], "TLS verification disabled") {
		t.Errorf("HTML header lacks the note")
	}
	var term bytes.Buffer
	if err := WriteTerminal(&term, r, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(term.String(), "TLS verification disabled") {
		t.Errorf("terminal lacks the note: %q", term.String())
	}
}
