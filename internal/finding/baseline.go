package finding

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

// Baseline is a set of finding IDs that are acknowledged and suppressed.
type Baseline struct {
	ids map[string]bool
}

// LoadBaseline reads a baseline file. A missing file yields an empty baseline.
// Line format: "<12-hex-id> [# comment]"; blank and "#" lines are ignored.
func LoadBaseline(path string) (*Baseline, error) {
	b := &Baseline{ids: map[string]bool{}}
	f, err := os.Open(path) // #nosec G304 -- user-supplied baseline path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return b, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id := line
		if i := strings.Index(line, "#"); i >= 0 {
			id = strings.TrimSpace(line[:i])
		}
		if !idPattern.MatchString(id) {
			return nil, fmt.Errorf("%s:%d: invalid finding ID %q (want 12 hex characters)", path, n, id)
		}
		b.ids[id] = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return b, nil
}

// Apply marks findings whose ID is in the baseline as suppressed.
func (b *Baseline) Apply(fs []Finding) []Finding {
	for i := range fs {
		if b.ids[fs[i].ID] {
			fs[i].Suppressed = true
		}
	}
	return fs
}
