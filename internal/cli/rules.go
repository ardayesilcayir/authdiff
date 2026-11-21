package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/pkg/authdiff"
)

func (a *app) rulesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "List or validate rule templates"}

	var dirs []string
	list := &cobra.Command{
		Use:   "list",
		Short: "List built-in (and custom) rules",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			rs, err := authdiff.LoadRules(dirs, nil)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tSEVERITY\tOWASP\tNAME")
			for _, r := range rs {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.OWASP, r.Name)
			}
			return tw.Flush()
		},
	}
	list.Flags().StringArrayVar(&dirs, "rules", nil, "directory of custom rule templates (repeatable)")

	validate := &cobra.Command{
		Use:   "validate <file>",
		Short: "Validate a custom rule file",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, err := rules.LoadFile(args[0])
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(a.stdout, "OK", r.ID)
			return err
		},
	}
	cmd.AddCommand(list, validate)
	return cmd
}
