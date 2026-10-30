package output

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeFileNameIllegalChars(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Duration/dyn_-_1435fa4", "Duration_dyn_-_1435fa4"},
		{`back\slash`, "back_slash"},
		{`co:lon`, "co_lon"},
		{`star*`, "star_"},
		{`quest?`, "quest_"},
		{`quo"te`, "quo_te"},
		{`less<`, "less_"},
		{`greater>`, "greater_"},
		{`pipe|`, "pipe_"},
		{`with space`, "with_space"},
		{"plain_Owner.Func_1a2b3c", "plain_Owner.Func_1a2b3c"},
	}
	for _, c := range cases {
		if got := SanitizeFileName(c.in); got != c.want {
			t.Errorf("SanitizeFileName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeFileNameNonPrintable(t *testing.T) {
	got := SanitizeFileName("a\nb\x00c\td")
	want := "a_b_c_d"
	if got != want {
		t.Errorf("SanitizeFileName(control chars) = %q, want %q", got, want)
	}
}

func TestSanitizeFileNameDotSegments(t *testing.T) {
	for _, in := range []string{"", ".", ".."} {
		if got := SanitizeFileName(in); got != "_" {
			t.Errorf("SanitizeFileName(%q) = %q, want %q", in, got, "_")
		}
	}
}

func TestSanitizeFileNameTruncation(t *testing.T) {
	long := strings.Repeat("A", 400)
	got := SanitizeFileName(long)

	if len(got) != MaxFileNameLen {
		t.Fatalf("len(SanitizeFileName(long)) = %d, want %d", len(got), MaxFileNameLen)
	}
	if !strings.HasPrefix(got, strings.Repeat("A", MaxFileNameLen-len("-0123456789abcdef"))) {
		t.Errorf("truncated name lost its prefix: %q", got)
	}
	if got[len(got)-17] != '-' {
		t.Errorf("truncated name missing hash suffix: %q", got)
	}

	// The hash must depend on the full name, not just the retained prefix,
	// so two symbols sharing a prefix do not collide.
	sibling := long + "B"
	if SanitizeFileName(sibling) == got {
		t.Errorf("names sharing a 400-byte prefix collided: %q", got)
	}

	// Same input must always produce the same name.
	if SanitizeFileName(long) != got {
		t.Errorf("SanitizeFileName is not deterministic")
	}
}

func TestSanitizeFileNameIdempotent(t *testing.T) {
	inputs := []string{
		"Duration/dyn_-_1435fa4",
		"Owner.Func_1a2b3c",
		strings.Repeat("A", 400),
		strings.Repeat("界", 250),
	}
	for _, in := range inputs {
		once := SanitizeFileName(in)
		twice := SanitizeFileName(once)
		if once != twice {
			t.Errorf("not idempotent for input of len %d: %q -> %q -> %q", len(in), in, once, twice)
		}
	}
}

func TestSanitizeFileNameRuneSafe(t *testing.T) {
	// 250 three-byte runes: truncation must not split a rune.
	got := SanitizeFileName(strings.Repeat("界", 250))
	if len(got) > MaxFileNameLen {
		t.Errorf("len = %d, want <= %d", len(got), MaxFileNameLen)
	}
	if !utf8.ValidString(got) {
		t.Errorf("truncation produced invalid UTF-8: %q", got)
	}
}

func TestSanitizeFileNameKeepsUnicode(t *testing.T) {
	got := SanitizeFileName("Klasse.Метод_1a2b")
	if got != "Klasse.Метод_1a2b" {
		t.Errorf("printable Unicode was altered: %q", got)
	}
}
