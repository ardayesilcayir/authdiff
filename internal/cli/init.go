package cli

import (
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

//go:embed templates/authdiff.yaml
var configTemplate []byte

//go:embed templates/authdiff-ignore
var ignoreTemplate []byte

func (a *app) initCmd() *cobra.Command {
	var dir string
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create an authdiff.yaml template and an empty .authdiff-ignore",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			files := []struct {
				name string
				data []byte
			}{
				{"authdiff.yaml", configTemplate},
				{".authdiff-ignore", ignoreTemplate},
			}
			// Check everything first so a refusal never leaves half the files.
			if !force {
				for _, f := range files {
					p := filepath.Join(dir, f.name)
					_, err := os.Stat(p)
					if err == nil {
						return fmt.Errorf("%s already exists (use --force to overwrite)", p)
					}
					if !errors.Is(err, fs.ErrNotExist) {
						return err
					}
				}
			}
			for _, f := range files {
				p := filepath.Join(dir, f.name)
				if err := os.WriteFile(p, f.data, 0o644); err != nil { // #nosec G306 -- config templates are not secret
					return err
				}
				fmt.Fprintln(a.stdout, "created", p)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", ".", "directory to write the files to")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files")
	return cmd
}
