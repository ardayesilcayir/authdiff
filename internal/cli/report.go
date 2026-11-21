package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ardayesilcayir/authdiff/internal/report"
)

var knownFormats = map[string]bool{"terminal": true, "json": true, "sarif": true, "html": true}

// checkFormats rejects unknown formats before anything is written.
func checkFormats(formats []string) error {
	if len(formats) == 0 {
		return fmt.Errorf("no report format given (want terminal, json, sarif or html)")
	}
	for _, f := range formats {
		if !knownFormats[f] {
			return fmt.Errorf("unknown report format %q (want terminal, json, sarif or html)", f)
		}
	}
	return nil
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (a *app) reportCmd() *cobra.Command {
	var input, output string
	var formats []string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render a saved results.json in other formats",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			formats = trimAll(formats)
			if err := checkFormats(formats); err != nil {
				return err
			}
			f, err := os.Open(input) // #nosec G304 -- user-supplied input path
			if err != nil {
				return err
			}
			res, err := report.ReadJSON(f)
			_ = f.Close()
			if err != nil {
				return err
			}
			paths, err := report.Write(output, formats, res, a.stdout, a.color())
			for _, p := range paths {
				a.log.Info("report written", "path", p)
			}
			return err
		},
	}
	cmd.Flags().StringVarP(&input, "input", "i", "", "results.json written by a scan")
	cmd.Flags().StringSliceVarP(&formats, "format", "f", []string{"html"}, "formats, comma separated: terminal,json,sarif,html")
	cmd.Flags().StringVarP(&output, "output", "o", "./authdiff-out", "output directory")
	_ = cmd.MarkFlagRequired("input")
	return cmd
}
