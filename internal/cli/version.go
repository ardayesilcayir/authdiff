package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit and build date",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			_, err := fmt.Fprintf(a.stdout, "authdiff %s (commit %s, built %s)\n", a.version, a.commit, a.date)
			return err
		},
	}
}
