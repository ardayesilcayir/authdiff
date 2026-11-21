package engine

import (
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/rules"
)

// builtinRules returns the built-in rules with the given IDs, of any kind.
func builtinRules(t *testing.T, ids ...string) []rules.Rule {
	t.Helper()
	all, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []rules.Rule
	for _, r := range all {
		if want[r.ID] {
			out = append(out, r)
		}
	}
	if len(out) != len(ids) {
		t.Fatalf("rules %v: found %d", ids, len(out))
	}
	return out
}

func TestNewChecksAllBuiltin(t *testing.T) {
	all, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	cs, err := NewChecks(all)
	if err != nil {
		t.Fatalf("NewChecks(builtin): %v", err)
	}
	if len(cs) != 8 {
		t.Fatalf("checks = %d, want 8", len(cs))
	}
	kinds := map[string]bool{}
	for _, c := range cs {
		kinds[c.Rule().Kind] = true
	}
	for _, k := range []string{rules.KindMassAssign, rules.KindMethodSwap, rules.KindMatrix, rules.KindLeak} {
		if !kinds[k] {
			t.Errorf("kind %s missing", k)
		}
	}
}
