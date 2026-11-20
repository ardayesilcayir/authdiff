package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

//go:embed templates/report.html.tmpl
var htmlTmplSrc string

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
	"pct":   func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) },
	"helpURL": func(id string) string {
		return ruleHelpBase + id + ".md"
	},
}).Parse(htmlTmplSrc))

type hmCell struct {
	Class  string
	Glyph  string
	Label  string
	Status int
}

type hmRow struct {
	Endpoint string
	Cells    []hmCell
}

type sevCount struct {
	Severity finding.Severity
	Count    int
}

type htmlView struct {
	R          *finding.Result
	Counts     []sevCount
	Duration   string
	Profiles   []string
	Rows       []hmRow
	Active     []finding.Finding
	Suppressed []finding.Finding
	Legend     []hmCell
}

var glyphs = map[finding.Outcome]string{
	finding.Allowed: "✓", finding.Denied: "✕", finding.Unexpected: "!", finding.Skipped: "–", finding.Errored: "?",
}

func buildHeatmap(r *finding.Result) ([]string, []hmRow) {
	profiles := append([]string(nil), r.Profiles...)
	seenP := map[string]bool{}
	for _, p := range profiles {
		seenP[p] = true
	}
	var eps []string
	seenE := map[string]bool{}
	cells := map[[2]string]finding.MatrixCell{}
	for _, c := range r.Matrix {
		if !seenP[c.Profile] {
			seenP[c.Profile] = true
			profiles = append(profiles, c.Profile)
		}
		if !seenE[c.Endpoint] {
			seenE[c.Endpoint] = true
			eps = append(eps, c.Endpoint)
		}
		cells[[2]string{c.Endpoint, c.Profile}] = c
	}
	rows := make([]hmRow, 0, len(eps))
	for _, e := range eps {
		row := hmRow{Endpoint: e}
		for _, p := range profiles {
			c, ok := cells[[2]string{e, p}]
			if !ok {
				row.Cells = append(row.Cells, hmCell{Class: "skipped", Glyph: "·", Label: "n/a"})
				continue
			}
			class := string(c.Outcome)
			if _, known := glyphs[c.Outcome]; !known {
				class = "skipped"
			}
			label := string(c.Outcome)
			if c.Status > 0 {
				label = fmt.Sprintf("%d %s", c.Status, c.Outcome)
			}
			row.Cells = append(row.Cells, hmCell{Class: class, Glyph: glyphs[finding.Outcome(class)], Label: label, Status: c.Status})
		}
		rows = append(rows, row)
	}
	return profiles, rows
}

// WriteHTML writes a single-file, script-free HTML report.
func WriteHTML(w io.Writer, r *finding.Result) error {
	v := htmlView{R: r, Active: r.Active()}
	for _, f := range r.Findings {
		if f.Suppressed {
			v.Suppressed = append(v.Suppressed, f)
		}
	}
	for _, s := range []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info} {
		n := 0
		for _, f := range v.Active {
			if f.Severity == s {
				n++
			}
		}
		v.Counts = append(v.Counts, sevCount{s, n})
	}
	v.Duration = r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond).String()
	v.Profiles, v.Rows = buildHeatmap(r)
	for _, o := range []finding.Outcome{finding.Allowed, finding.Denied, finding.Unexpected, finding.Skipped, finding.Errored} {
		v.Legend = append(v.Legend, hmCell{Class: string(o), Glyph: glyphs[o], Label: string(o)})
	}
	return htmlTmpl.Execute(w, v)
}
