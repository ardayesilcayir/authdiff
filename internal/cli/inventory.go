package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ardayesilcayir/authdiff/internal/spec"
	"github.com/ardayesilcayir/authdiff/pkg/authdiff"
)

type paramView struct {
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required"`
}

type endpointView struct {
	Method      string      `json:"method"`
	Path        string      `json:"path"`
	OperationID string      `json:"operationId,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	Secured     bool        `json:"secured"`
	Params      []paramView `json:"params"`
	HasBody     bool        `json:"hasBody"`
	Line        int         `json:"line,omitempty"`
}

func viewOf(e spec.Endpoint) endpointView {
	v := endpointView{
		Method: e.Method, Path: e.Path, OperationID: e.OperationID, Tags: e.Tags,
		Secured: e.Secured, Params: []paramView{}, HasBody: e.Body != nil, Line: e.Line,
	}
	for _, p := range e.Params {
		v.Params = append(v.Params, paramView{Name: p.Name, In: p.In, Required: p.Required})
	}
	return v
}

func (a *app) inventoryCmd() *cobra.Command {
	var cfgPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "List the endpoints found in the spec (sends no requests)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			inv, err := authdiff.LoadInventory(cmd.Context(), cfgPath, authdiff.Overrides{}, a.version)
			if err != nil {
				return err
			}
			views := make([]endpointView, 0, len(inv.Endpoints))
			for _, e := range inv.Endpoints {
				views = append(views, viewOf(e))
			}
			if asJSON {
				enc := json.NewEncoder(a.stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(views)
			}
			tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "METHOD\tPATH\tOPERATION\tSECURED\tPARAMS")
			for _, v := range views {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", v.Method, v.Path, dash(v.OperationID), yesNo(v.Secured), paramList(v.Params))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "authdiff.yaml", "config file")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON instead of a table")
	return cmd
}

func paramList(ps []paramView) string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		parts = append(parts, p.Name+"("+p.In+")")
	}
	return dash(strings.Join(parts, ","))
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
