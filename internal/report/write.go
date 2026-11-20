package report

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

// Write renders r in each requested format ("json", "sarif", "html",
// "terminal"). File formats go to dir (created if needed); terminal goes to
// stdout. It returns the file paths written.
func Write(dir string, formats []string, r *finding.Result, stdout io.Writer, color bool) ([]string, error) {
	files := map[string]struct {
		name string
		fn   func(io.Writer, *finding.Result) error
	}{
		"json":  {"results.json", WriteJSON},
		"sarif": {"results.sarif", WriteSARIF},
		"html":  {"report.html", WriteHTML},
	}
	var paths []string
	for _, f := range formats {
		if f == "terminal" {
			if err := WriteTerminal(stdout, r, color); err != nil {
				return paths, err
			}
			continue
		}
		spec, ok := files[f]
		if !ok {
			return paths, fmt.Errorf("unknown report format %q (want json, sarif, html or terminal)", f)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return paths, fmt.Errorf("create report dir: %w", err)
		}
		p := filepath.Join(dir, spec.name)
		if err := writeFile(p, spec.fn, r); err != nil {
			return paths, err
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func writeFile(p string, fn func(io.Writer, *finding.Result) error, r *finding.Result) (err error) {
	out, err := os.Create(p)
	if err != nil {
		return fmt.Errorf("create %s: %w", p, err)
	}
	defer func() {
		if cerr := out.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	return fn(out, r)
}
