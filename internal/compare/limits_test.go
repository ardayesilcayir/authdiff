package compare

import (
	"fmt"
	"strings"
	"testing"
)

// A response with more than 50,000 leaves is cut off with a "<leaf-limit>"
// marker instead of exhausting memory.
func TestFlattenLeafLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 60000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%d", i)
	}
	b.WriteString("]")
	flat, ok := Flatten([]byte(b.String()))
	if !ok {
		t.Fatal("not JSON")
	}
	if len(flat) > maxLeaves+1 {
		t.Errorf("leaves = %d, want <= %d", len(flat), maxLeaves+1)
	}
	marked := false
	for _, v := range flat {
		if v == leafLimitLeaf {
			marked = true
		}
	}
	if !marked {
		t.Error("no <leaf-limit> marker")
	}
	// Deterministic: the same leaves are kept every time.
	again, _ := Flatten([]byte(b.String()))
	for k, v := range flat {
		if again[k] != v {
			t.Fatalf("flatten not deterministic at %s", k)
		}
	}
}

// Keys longer than 256 characters are truncated in paths.
func TestFlattenLongKeysTruncated(t *testing.T) {
	long := strings.Repeat("k", 5000)
	flat, ok := Flatten([]byte(`{"` + long + `":{"` + long + `":1}}`))
	if !ok {
		t.Fatal("not JSON")
	}
	for p := range flat {
		if len(p) > 1+2*(maxKeyLen+1) {
			t.Errorf("path length %d not truncated", len(p))
		}
	}
	if len(flat) != 1 {
		t.Errorf("flat = %d leaves", len(flat))
	}
}
