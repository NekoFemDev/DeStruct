package hexedit

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestParseSearchPattern(t *testing.T) {
	for _, tc := range []struct {
		in   string
		data string
		wild []bool
		mode string
	}{
		{`"Hello"`, "Hello", []bool{false, false, false, false, false}, "ascii"},
		{"48 45 4c", "HEL", []bool{false, false, false}, "hex"},
		{"48656c", "Hel", []bool{false, false, false}, "hex"},
		{"48 ?? 6c", "H\x00l", []bool{false, true, false}, "hex"},
		{"hello", "hello", []bool{false, false, false, false, false}, "ascii"},
		{"abc", "abc", []bool{false, false, false}, "ascii"}, // odd length: not hex
	} {
		got, err := parseSearchPattern(tc.in)
		if err != nil {
			t.Errorf("parseSearchPattern(%q): %v", tc.in, err)
			continue
		}
		if string(got.data) != tc.data || got.mode != tc.mode {
			t.Errorf("parseSearchPattern(%q) = %q %s, want %q %s", tc.in, got.data, got.mode, tc.data, tc.mode)
		}
		if len(got.wild) != len(tc.wild) {
			t.Fatalf("parseSearchPattern(%q) wildcard mask len = %d, want %d", tc.in, len(got.wild), len(tc.wild))
		}
		for i := range tc.wild {
			if got.wild[i] != tc.wild[i] {
				t.Errorf("parseSearchPattern(%q) wildcard[%d] = %v, want %v", tc.in, i, got.wild[i], tc.wild[i])
			}
		}
	}
}

func TestParseSearchPatternErrors(t *testing.T) {
	for _, in := range []string{``, `""`, "hello world", "he??o", "48 6"} {
		if got, err := parseSearchPattern(in); err == nil {
			t.Errorf("parseSearchPattern(%q) = %+v, want error", in, got)
		}
	}
}

func TestSearchLiteralAndWildcard(t *testing.T) {
	data := []byte("xxHELLOxxHiLLOxxhello")
	s, _ := openBufferSession(t, data)

	pat, err := parseSearchPattern(`"HELLO"`)
	if err != nil {
		t.Fatal(err)
	}
	hits, total, err := s.search(context.Background(), pat, searchLimit)
	if err != nil || total != 1 || len(hits) != 1 || hits[0] != 2 {
		t.Fatalf("ascii search: hits=%v total=%d err=%v", hits, total, err)
	}

	pat, _ = parseSearchPattern("48 ?? 4c 4c 4f")
	hits, total, err = s.search(context.Background(), pat, searchLimit)
	if err != nil || total != 2 || len(hits) != 2 || hits[0] != 2 || hits[1] != 9 {
		t.Fatalf("wildcard search: hits=%v total=%d err=%v", hits, total, err)
	}

	pat, _ = parseSearchPattern("48454c4c4f")
	if _, total, _ := s.search(context.Background(), pat, searchLimit); total != 1 {
		t.Fatalf("contiguous hex search total = %d, want 1", total)
	}

	pat, _ = parseSearchPattern(`"zzz"`)
	if _, total, _ := s.search(context.Background(), pat, searchLimit); total != 0 {
		t.Fatalf("no-match search total = %d", total)
	}
}

// TestSearchCrossBlock places a match straddling the streaming block
// boundary: a match starting in one block and ending in the next.
func TestSearchCrossBlock(t *testing.T) {
	data := bytes.Repeat([]byte{0xAA}, searchBlockBytes+16)
	at := searchBlockBytes - 3
	copy(data[at:], "MAGIC")
	s, _ := openBufferSession(t, data)

	pat, err := parseSearchPattern(`"MAGIC"`)
	if err != nil {
		t.Fatal(err)
	}
	hits, total, err := s.search(context.Background(), pat, searchLimit)
	if err != nil || total != 1 || len(hits) != 1 || hits[0] != int64(at) {
		t.Fatalf("cross-block search: hits=%v total=%d err=%v (want %d)", hits, total, err, at)
	}
}

func TestSearchLimitAndCancellation(t *testing.T) {
	data := bytes.Repeat([]byte("AB_"), 100)
	s, _ := openBufferSession(t, data)
	pat, _ := parseSearchPattern("4142")

	hits, total, err := s.search(context.Background(), pat, 64)
	if err != nil {
		t.Fatal(err)
	}
	if total != 100 || len(hits) != 64 {
		t.Fatalf("limited search: hits=%d total=%d", len(hits), total)
	}
	if hits[63] != int64(3*63) {
		t.Fatalf("last hit = %d", hits[63])
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.search(ctx, pat, 64); err == nil {
		t.Fatal("cancelled search: expected error")
	}
}

func TestExecSearch(t *testing.T) {
	s, buf := openBufferSession(t, []byte("...HELLO..."))
	if _, err := execLine(t, s, `search "HELLO"`); err != nil {
		t.Fatalf("search: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "; search: ascii, 5 byte(s)") {
		t.Fatalf("missing search header:\n%s", out)
	}
	if !strings.Contains(out, "f:0x00000003") {
		t.Fatalf("missing hit address:\n%s", out)
	}

	buf.Reset()
	if _, err := execLine(t, s, `search "nope"`); err != nil {
		t.Fatalf("search miss: %v", err)
	}
	if !strings.Contains(buf.String(), "no matches") {
		t.Fatalf("missing no-match output:\n%s", buf.String())
	}

	if _, err := execLine(t, s, "search"); err == nil {
		t.Fatal("search without pattern: expected error")
	}
}
