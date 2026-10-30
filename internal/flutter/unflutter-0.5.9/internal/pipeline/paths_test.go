package pipeline

import (
	"strings"
	"testing"
)

func TestFuncRelPathIsFlat(t *testing.T) {
	got := FuncRelPath("Duration", "dyn_-", 0x1435fa4)
	want := "Duration.dyn_-_1435fa4"
	if got != want {
		t.Fatalf("FuncRelPath = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, `/\`) {
		t.Fatalf("FuncRelPath leaked a path separator: %q", got)
	}
}

func TestFuncRelPathSanitizesSlashesInNames(t *testing.T) {
	got := FuncRelPath("Duration/dyn", "method", 0x1)
	want := "Duration_dyn.method_1"
	if got != want {
		t.Fatalf("FuncRelPath = %q, want %q", got, want)
	}
}

// TestFuncRelPathRoundTrip guarantees the read-side reconstruction
// (FuncRelPathFromQualified, used by signal/decompile) resolves exactly the
// file the write side (FuncRelPath) named.
func TestFuncRelPathRoundTrip(t *testing.T) {
	cases := []struct {
		owner, fn string
		pc        uint32
	}{
		{"Duration", "dyn_-", 0x1435fa4},
		{"", "topLevel", 0x10},
		{"Owner", "", 0x20}, // empty func name -> "sub_<pc>"
		{"A/B", "c:d", 0x30},
		{"Owner", "VeryLongFunction" + strings.Repeat("x", 500), 0x40},
	}
	for _, c := range cases {
		qualified := QualifiedName(c.owner, c.fn, c.pc)
		writePath := FuncRelPath(c.owner, c.fn, c.pc)
		readPath := FuncRelPathFromQualified(qualified, c.owner)
		if writePath != readPath {
			t.Errorf("owner=%q func=%q: write path %q != read path %q",
				c.owner, c.fn, writePath, readPath)
		}
		if strings.ContainsAny(writePath, `/\`) {
			t.Errorf("owner=%q func=%q: path contains a separator: %q", c.owner, c.fn, writePath)
		}
	}
}

func TestFuncRelPathTruncatesLongNames(t *testing.T) {
	longFn := strings.Repeat("x", 500)
	a := FuncRelPath("Owner", longFn, 0x1)
	b := FuncRelPath("Owner", longFn, 0x2)

	if len(a) > 200 || len(b) > 200 {
		t.Fatalf("paths exceed 200 bytes: %d, %d", len(a), len(b))
	}
	if a == b {
		t.Fatalf("different symbols collided to the same path: %q", a)
	}
	if FuncRelPath("Owner", longFn, 0x1) != a {
		t.Fatalf("FuncRelPath is not deterministic")
	}
}

func TestSanitizeFilenameDelegates(t *testing.T) {
	if got := SanitizeFilename("Duration/dyn_-_1435fa4"); got != "Duration_dyn_-_1435fa4" {
		t.Fatalf("SanitizeFilename = %q", got)
	}
}
