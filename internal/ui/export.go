package ui

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	examplesfs "github.com/ardayesilcayir/authdiff/examples"
	"github.com/ardayesilcayir/authdiff/internal/config"
)

// WriteExportZip writes p as a zip for the CLI, all files at the top level:
// authdiff.yaml (credentials as ${env:...} placeholders, an uploaded spec as
// the relative spec.<ext>), the spec file if one was uploaded,
// .authdiff-ignore, .env.example (one NAME= line per variable, sorted) and,
// for the demo project only, the lab's fake tokens as vuln-lab.env.
func WriteExportZip(w io.Writer, st *Store, p *Project) error {
	c, err := PlaceholderConfig(p)
	if err != nil {
		return err
	}
	yml, err := config.Marshal(c)
	if err != nil {
		return err
	}
	dir := st.Dir(p.Name)

	type entry struct {
		name string
		data []byte
	}
	files := []entry{{"authdiff.yaml", yml}}
	if p.SpecFile != "" {
		b, err := readProjectFile(dir, p.SpecFile)
		if err != nil {
			return fmt.Errorf("export spec: %w", err)
		}
		files = append(files, entry{p.SpecFile, b})
	}
	ign, err := readProjectFile(dir, ignoreFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("export ignore file: %w", err)
	}
	files = append(files, entry{ignoreFile, ign})

	vars := envVars(p)
	sort.Strings(vars)
	var env strings.Builder
	for _, v := range vars {
		env.WriteString(v + "=\n")
	}
	files = append(files, entry{".env.example", []byte(env.String())})
	if p.Demo {
		lab, err := examplesfs.FS.ReadFile(demoEnvFile)
		if err != nil {
			return err
		}
		files = append(files, entry{demoEnvFile, lab})
	}

	zw := zip.NewWriter(w)
	now := time.Now()
	for _, f := range files {
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: now})
		if err != nil {
			return fmt.Errorf("export: %w", err)
		}
		if _, err := fw.Write(f.data); err != nil {
			return fmt.Errorf("export: %w", err)
		}
	}
	return zw.Close()
}

// readProjectFile reads the ignore file or an uploaded spec (spec.yaml,
// spec.json) of a project directory; any other name is refused.
func readProjectFile(dir, name string) ([]byte, error) {
	if name != ignoreFile {
		if err := checkSpecFile(name); err != nil || name == "" {
			return nil, fmt.Errorf("invalid file name %q", name)
		}
	}
	return os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: name is one of three fixed file names
}
