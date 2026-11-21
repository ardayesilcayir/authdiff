package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

var sevColor = map[finding.Severity]lipgloss.Color{
	finding.Critical: "9", finding.High: "1", finding.Medium: "3", finding.Low: "4", finding.Info: "8",
}

// CleanTerminal removes C0 and C1 control characters (and DEL) from s, so
// strings that come from a spec or a target cannot inject terminal escape
// sequences.
func CleanTerminal(s string) string {
	if strings.IndexFunc(s, isControl) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isControl(r) {
			return -1
		}
		return r
	}, s)
}

func isControl(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) }

// WriteTerminal prints a findings table and a one-line summary.
func WriteTerminal(w io.Writer, r *finding.Result, color bool) error {
	paint := func(s string, st lipgloss.Style) string {
		if !color {
			return s
		}
		return st.Render(s)
	}
	active := r.Active()
	suppressed := len(r.Findings) - len(active)

	if len(active) == 0 {
		if _, err := fmt.Fprintln(w, "No findings."); err != nil {
			return err
		}
	} else {
		header := []string{"SEVERITY", "RULE", "ENDPOINT", "ATTACKER→VICTIM", "CONF"}
		rows := make([][]string, 0, len(active))
		for _, f := range active {
			rows = append(rows, []string{
				CleanTerminal(strings.ToUpper(string(f.Severity))), CleanTerminal(f.RuleID),
				CleanTerminal(f.Method + " " + f.Path),
				CleanTerminal(f.Attacker) + "→" + CleanTerminal(f.Victim), CleanTerminal(string(f.Confidence)),
			})
		}
		widths := make([]int, len(header))
		for i, h := range header {
			widths[i] = lipgloss.Width(h)
		}
		for _, row := range rows {
			for i, c := range row {
				if cw := lipgloss.Width(c); cw > widths[i] {
					widths[i] = cw
				}
			}
		}
		line := func(cells []string, style func(i int, s string) string) string {
			parts := make([]string, len(cells))
			for i, c := range cells {
				pad := strings.Repeat(" ", widths[i]-lipgloss.Width(c))
				parts[i] = style(i, c) + pad
			}
			return strings.TrimRight(strings.Join(parts, "  "), " ")
		}
		bold := lipgloss.NewStyle().Bold(true)
		if _, err := fmt.Fprintln(w, line(header, func(_ int, s string) string { return paint(s, bold) })); err != nil {
			return err
		}
		sep := make([]string, len(header))
		for i := range sep {
			sep[i] = strings.Repeat("─", widths[i])
		}
		if _, err := fmt.Fprintln(w, strings.Join(sep, "  ")); err != nil {
			return err
		}
		for k, row := range rows {
			sev := active[k].Severity
			l := line(row, func(i int, s string) string {
				if i == 0 {
					return paint(s, lipgloss.NewStyle().Bold(true).Foreground(sevColor[sev]))
				}
				return s
			})
			if _, err := fmt.Fprintln(w, l); err != nil {
				return err
			}
		}
	}
	for _, n := range r.Notes {
		if _, err := fmt.Fprintf(w, "\nWarning: %s\n", CleanTerminal(n)); err != nil {
			return err
		}
	}
	dur := r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond)
	_, err := fmt.Fprintf(w, "\n%d findings (%d suppressed) · %d requests · %d blocked · %d errors · %s\n",
		len(active), suppressed, r.Stats.Requests, r.Stats.Blocked, r.Stats.Errors, dur)
	return err
}
