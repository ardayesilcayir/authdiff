package finding

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestNewIDStable(t *testing.T) {
	a := NewID("AD-BOLA-001", "GET", "/orders/{orderId}", "alice", "bob")
	b := NewID("AD-BOLA-001", "GET", "/orders/{orderId}", "alice", "bob")
	if a != b {
		t.Fatalf("ID not stable: %s vs %s", a, b)
	}
	if len(a) != 12 || !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(a) {
		t.Fatalf("ID must be 12 hex chars, got %q", a)
	}
	if c := NewID("AD-BOLA-001", "GET", "/orders/{orderId}", "bob", "alice"); c == a {
		t.Fatal("swapping victim/attacker must change the ID")
	}
}

func TestParseSeverity(t *testing.T) {
	s, err := ParseSeverity("HIGH")
	if err != nil || s != High {
		t.Fatalf("got %v, %v", s, err)
	}
	if _, err := ParseSeverity("x"); err == nil {
		t.Fatal("expected error for unknown severity")
	}
}

func TestSeverityHelpers(t *testing.T) {
	if Critical.Rank() != 5 || Info.Rank() != 1 {
		t.Fatal("bad rank")
	}
	if DefaultCVSS(Critical) != 9.1 || DefaultCVSS(High) != 8.1 || DefaultCVSS(Medium) != 6.5 ||
		DefaultCVSS(Low) != 3.7 || DefaultCVSS(Info) != 0.0 {
		t.Fatal("bad cvss")
	}
	want := map[Severity]string{Critical: "error", High: "error", Medium: "warning", Low: "note", Info: "note"}
	for s, l := range want {
		if s.SARIFLevel() != l {
			t.Errorf("%s: got %s want %s", s, s.SARIFLevel(), l)
		}
	}
}

func TestSortOrder(t *testing.T) {
	fs := []Finding{
		{RuleID: "B", Severity: Low, Method: "GET", Path: "/a"},
		{RuleID: "A", Severity: High, Method: "POST", Path: "/a"},
		{RuleID: "A", Severity: High, Method: "GET", Path: "/b"},
		{RuleID: "A", Severity: High, Method: "GET", Path: "/a", Victim: "z"},
		{RuleID: "A", Severity: High, Method: "GET", Path: "/a", Victim: "a", Attacker: "y"},
		{RuleID: "A", Severity: High, Method: "GET", Path: "/a", Victim: "a", Attacker: "x"},
		{RuleID: "C", Severity: Critical, Method: "GET", Path: "/z"},
	}
	Sort(fs)
	got := []string{}
	for _, f := range fs {
		got = append(got, strings.Join([]string{string(f.Severity), f.RuleID, f.Method, f.Path, f.Victim, f.Attacker}, "|"))
	}
	want := []string{
		"critical|C|GET|/z||",
		"high|A|GET|/a|a|x",
		"high|A|GET|/a|a|y",
		"high|A|GET|/a|z|",
		"high|A|GET|/b||",
		"high|A|POST|/a||",
		"low|B|GET|/a||",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pos %d: got %s want %s", i, got[i], want[i])
		}
	}
}

func TestFailsAt(t *testing.T) {
	r := &Result{Findings: []Finding{{Severity: High, Suppressed: true}}}
	if r.FailsAt(High) {
		t.Fatal("suppressed finding must not trigger")
	}
	if len(r.Active()) != 0 {
		t.Fatal("Active must exclude suppressed")
	}
	r.Findings = append(r.Findings, Finding{Severity: Medium})
	if r.FailsAt(High) {
		t.Fatal("medium must not fail at high")
	}
	if !r.FailsAt(Medium) {
		t.Fatal("medium must fail at medium")
	}
}

func TestBaselineApply(t *testing.T) {
	dir := t.TempDir()
	b, err := LoadBaseline(filepath.Join(dir, "missing.txt"))
	if err != nil || b == nil {
		t.Fatalf("missing file must give empty baseline: %v", err)
	}

	bad := filepath.Join(dir, "bad.txt")
	_ = os.WriteFile(bad, []byte("# c\n\nnot-an-id\n"), 0o600)
	if _, err := LoadBaseline(bad); err == nil || !strings.Contains(err.Error(), "3") {
		t.Fatalf("expected error with line number 3, got %v", err)
	}

	good := filepath.Join(dir, "good.txt")
	_ = os.WriteFile(good, []byte("# header\n\nabcdef012345 # known issue\n"), 0o600)
	b, err = LoadBaseline(good)
	if err != nil {
		t.Fatal(err)
	}
	fs := b.Apply([]Finding{{ID: "abcdef012345"}, {ID: "000000000000"}})
	if !fs[0].Suppressed || fs[1].Suppressed {
		t.Fatalf("bad suppression: %+v", fs)
	}
}
