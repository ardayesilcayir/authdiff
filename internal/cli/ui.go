package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ardayesilcayir/authdiff/internal/ui"
)

func (a *app) uiCmd() *cobra.Command {
	var (
		port        int
		noOpen      bool
		projectsDir string
	)
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Open the local web interface (127.0.0.1 only)",
		Long: `Start the authdiff web interface on 127.0.0.1 and open it in the browser.

The printed link carries a one-time session key; only a browser that opened
it can use the interface. If the port is busy the next free one is used.
Ctrl-C stops a running scan (partial results are kept) and the server.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if port < 1 || port > 65535 {
				return &codeError{code: exitError, err: fmt.Errorf("--port must be 1-65535, got %d", port)}
			}
			s, err := ui.New(ui.Options{
				Port:        port,
				ProjectsDir: projectsDir,
				Version:     a.version,
				Log:         a.log,
			})
			if err != nil {
				return &codeError{code: exitError, err: err}
			}
			url, err := s.Listen()
			if err != nil {
				return &codeError{code: exitError, err: err}
			}
			_, _ = fmt.Fprintf(a.stdout, "authdiff ui is running at:\n\n  %s\n\nThe link contains this session's key; do not share it. Press Ctrl-C to stop.\n", url)
			if !noOpen {
				if err := openBrowser(url); err != nil {
					a.log.Warn("could not open the browser; open the link above manually", "err", err)
				}
			}
			if err := s.Serve(cmd.Context()); err != nil {
				return &codeError{code: exitError, err: err}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.IntVar(&port, "port", ui.DefaultPort, "first port to try on 127.0.0.1 (the next free one is used if busy)")
	f.BoolVar(&noOpen, "no-open", false, "do not open the browser; just print the link")
	f.StringVar(&projectsDir, "projects-dir", "", "where projects are saved (default <user config dir>/authdiff/projects)")
	return cmd
}
