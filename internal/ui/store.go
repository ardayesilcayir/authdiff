package ui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	projectFile = "project.json"
	ignoreFile  = ".authdiff-ignore"
	runsDir     = "runs"
	// maxSpecBytes is the largest accepted spec upload (same as the engine).
	maxSpecBytes = 10 << 20
	dirPerm      = 0o700
	filePerm     = 0o600
)

var (
	nameRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	findingIDRe = regexp.MustCompile(`^[0-9a-f]{12}$`)
)

// ValidName reports whether s is an allowed project name: lower-case
// letters, digits and '-', starting with a letter or digit, at most 63
// characters. Names never contain path separators or dots.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// Store keeps projects as <root>/<name>/project.json.
type Store struct {
	root string
	mu   sync.Mutex
}

// NewStore creates dir (0700) if needed and returns a Store rooted there.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("projects dir: %w", err)
	}
	return &Store{root: dir}, nil
}

// Dir is the directory of project name. It does not check the name.
func (s *Store) Dir(name string) string { return filepath.Join(s.root, name) }

// RunsDir is the directory holding a project's scan runs.
func (s *Store) RunsDir(name string) string { return filepath.Join(s.Dir(name), runsDir) }

func checkName(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid project name %q (use a-z, 0-9 and -)", name)
	}
	return nil
}

// List returns every readable project, most recently updated first.
// Directories without a valid name or a readable project.json are skipped.
func (s *Store) List() ([]Project, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	var out []Project
	for _, e := range entries {
		if !e.IsDir() || !ValidName(e.Name()) {
			continue
		}
		p, err := s.Get(e.Name())
		if err != nil {
			continue
		}
		out = append(out, *p)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

// Get reads project name. A missing project yields an error wrapping
// os.ErrNotExist.
func (s *Store) Get(name string) (*Project, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(s.Dir(name), projectFile))
	if err != nil {
		return nil, fmt.Errorf("project %q: %w", name, err)
	}
	var p Project
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("project %q: %w", name, err)
	}
	p.Name = name
	return &p, nil
}

// Save writes p atomically to its project.json (0600), creating the project
// directory (0700). It sets CreatedAt on first save and UpdatedAt always.
func (s *Store) Save(p *Project) error {
	if err := checkName(p.Name); err != nil {
		return err
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("encode project: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir(p.Name), dirPerm); err != nil {
		return fmt.Errorf("project dir: %w", err)
	}
	return writeFileAtomic(filepath.Join(s.Dir(p.Name), projectFile), b)
}

// specName maps an upload's extension to the stored file name.
func specName(ext string) (string, error) {
	switch strings.ToLower(strings.TrimPrefix(ext, ".")) {
	case "yaml", "yml":
		return "spec.yaml", nil
	case "json":
		return "spec.json", nil
	}
	return "", fmt.Errorf("unsupported spec extension %q (want .json, .yaml or .yml)", ext)
}

// SaveSpec stores an uploaded spec (at most 10 MiB) in the project
// directory as spec.yaml or spec.json, by ext, removes the other one, and
// returns the stored file name.
func (s *Store) SaveSpec(name string, r io.Reader, ext string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	file, err := specName(ext)
	if err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(r, maxSpecBytes+1))
	if err != nil {
		return "", fmt.Errorf("read spec: %w", err)
	}
	if len(data) > maxSpecBytes {
		return "", fmt.Errorf("spec is larger than %d MiB", maxSpecBytes>>20)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.Dir(name)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return "", fmt.Errorf("project dir: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, file), data); err != nil {
		return "", err
	}
	for _, other := range []string{"spec.yaml", "spec.json"} {
		if other != file {
			if err := os.Remove(filepath.Join(dir, other)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("remove old spec: %w", err)
			}
		}
	}
	return file, nil
}

// AppendIgnore adds "<id> # <reason>" to the project's .authdiff-ignore
// (the finding baseline format). An ID already listed is not added again;
// line breaks and '#' in reason are replaced by spaces.
func (s *Store) AppendIgnore(name, id, reason string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if !findingIDRe.MatchString(id) {
		return fmt.Errorf("invalid finding ID %q (want 12 hex characters)", id)
	}
	reason = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r == '#' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, reason)), " ")

	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.Dir(name)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("project dir: %w", err)
	}
	path := filepath.Join(dir, ignoreFile)
	old, err := os.ReadFile(path) //nolint:gosec // G304: path is inside the validated project dir
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read ignore file: %w", err)
	}
	for _, line := range strings.Split(string(old), "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == id {
			return nil
		}
	}
	var buf bytes.Buffer
	buf.Write(old)
	if len(old) > 0 && !bytes.HasSuffix(old, []byte("\n")) {
		buf.WriteByte('\n')
	}
	buf.WriteString(id)
	if reason != "" {
		buf.WriteString(" # " + reason)
	}
	buf.WriteByte('\n')
	return writeFileAtomic(path, buf.Bytes())
}

// writeFileAtomic writes data to path (0600) through a temp file in the same
// directory and a rename, so readers never see a half-written file.
func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(filePerm); err != nil && !isWindows() {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		if !isWindows() {
			return fmt.Errorf("write %s: %w", filepath.Base(path), err)
		}
		// Windows may refuse to replace a file another process has open.
		_ = os.Remove(path)
		if err := os.Rename(tmp, path); err != nil {
			return fmt.Errorf("write %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}
