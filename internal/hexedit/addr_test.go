package hexedit

import (
	"strings"
	"testing"
)

func TestParseAddr(t *testing.T) {
	for _, tc := range []struct {
		in    string
		value uint64
		space Space
	}{
		{"0x1234", 0x1234, SpaceFile},
		{"1234", 0x1234, SpaceFile},
		{"deadbeef", 0xdeadbeef, SpaceFile},
		{"f:0x10", 0x10, SpaceFile},
		{"F:10", 0x10, SpaceFile},
		{"v:0x10", 0x10, SpaceVirtual},
		{"V:10", 0x10, SpaceVirtual},
		{"0d10", 10, SpaceFile},
		{"0D255", 255, SpaceFile},
		{"f:0d16", 16, SpaceFile},
		{"  0x20  ", 0x20, SpaceFile},
	} {
		got, err := ParseAddr(tc.in)
		if err != nil {
			t.Errorf("ParseAddr(%q): %v", tc.in, err)
			continue
		}
		if got.Value != tc.value || got.Space != tc.space {
			t.Errorf("ParseAddr(%q) = %+v, want value=%#x space=%v", tc.in, got, tc.value, tc.space)
		}
	}
}

func TestParseAddrErrors(t *testing.T) {
	for _, in := range []string{"", "z:1", "v:", "f:", "0x", "0d", "0xzz", "12g4", ":10", "f:0d"} {
		if got, err := ParseAddr(in); err == nil {
			t.Errorf("ParseAddr(%q) = %+v, want error", in, got)
		}
	}
}

func TestAddrString(t *testing.T) {
	if got := (Addr{Value: 0x1234, Space: SpaceFile}).String(); got != "f:0x00001234" {
		t.Errorf("file addr string = %q", got)
	}
	if got := (Addr{Value: 0xabcd, Space: SpaceVirtual}).String(); got != "v:0x0000abcd" {
		t.Errorf("virtual addr string = %q", got)
	}
}

func TestParseAddrErrorMentionsHex(t *testing.T) {
	_, err := ParseAddr("0xzz")
	if err == nil || !strings.Contains(err.Error(), "hex") {
		t.Errorf("expected hex hint in error, got %v", err)
	}
}
