package pipeline

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/native"
)

// TestWithDiscoveredFunctions covers the fix for a real (if minor)
// output-consistency bug: a call from one .eh_frame_hdr-discovered,
// unnamed function to another was resolving through buildCall's own
// generic "func_<address>" placeholder instead of the SAME
// "sub_<address>" name that function is actually decompiled under as
// its own top-level entry - two different spellings for the identical
// "no real name" situation. Deliberately tested in isolation (no real
// ELF file needed at all) rather than only via a full end-to-end
// decompile, since a real fixture large enough to exercise this path
// (test/arm64.sh, a fully stripped ~9000-function executable) is slow
// to run repeatedly.
func TestWithDiscoveredFunctions(t *testing.T) {
	base := func(addr uint64) (string, bool) {
		if addr == 0x100 {
			return "real_symbol", true
		}
		return "", false
	}
	discovered := []native.DiscoveredFunction{
		{Addr: 0x200, Size: 16},
		{Addr: 0x300, Size: 32},
	}

	candidates, resolver := withDiscoveredFunctions(discovered, base)

	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d: %v", len(candidates), candidates)
	}
	if candidates[0].addr != 0x200 || candidates[0].name != "sub_200" || candidates[0].size != 16 {
		t.Errorf("expected candidate 0 to be {addr:0x200, size:16, name:\"sub_200\"}, got %+v", candidates[0])
	}
	if candidates[1].addr != 0x300 || candidates[1].name != "sub_300" || candidates[1].size != 32 {
		t.Errorf("expected candidate 1 to be {addr:0x300, size:32, name:\"sub_300\"}, got %+v", candidates[1])
	}

	if name, ok := resolver(0x100); !ok || name != "real_symbol" {
		t.Errorf("expected a real symbol to still take priority over a discovered one, got %q, ok=%v", name, ok)
	}
	if name, ok := resolver(0x200); !ok || name != "sub_200" {
		t.Errorf("expected the discovered function's own \"sub_<address>\" name (matching its declaration), got %q, ok=%v", name, ok)
	}
	if name, ok := resolver(0x300); !ok || name != "sub_300" {
		t.Errorf("expected the discovered function's own \"sub_<address>\" name (matching its declaration), got %q, ok=%v", name, ok)
	}
	if _, ok := resolver(0x999); ok {
		t.Errorf("expected an address that's neither a real symbol nor a discovered function to remain unresolved")
	}
}

func TestExtractLibappArchiveLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversize.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	entry, err := w.Create("lib/arm64-v8a/libapp.so")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	central := bytes.LastIndex(data, []byte("PK\x01\x02"))
	if central < 0 {
		t.Fatal("missing zip central directory")
	}
	binary.LittleEndian.PutUint32(data[central+24:], 0xffffffff)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	p := New(Options{Input: path})
	if _, err := p.extractLibapp(path); err == nil {
		t.Fatal("extract accepted oversized entry")
	}
}

func TestWriteFunctionLocation(t *testing.T) {
	var out bytes.Buffer
	writeFunctionLocation(&out, funcCandidate{addr: 0x7f123400}, []native.DetailedInstruction{
		{Address: 0x7f123404},
	})
	if got, want := out.String(), "// ELF function entry VA: 0x7f123400\n// First decoded instruction VA: 0x7f123404\n"; got != want {
		t.Fatalf("location comments = %q, want %q", got, want)
	}
	out.Reset()
	writeFunctionLocation(&out, funcCandidate{addr: 0}, nil)
	if got := out.String(); got != "// ELF function entry VA: 0x0\n" {
		t.Fatalf("zero-address function location = %q", got)
	}
}

func TestEnhancementPreservesRenderedLines(t *testing.T) {
	dir := t.TempDir()
	input := "sample.so"
	original := "// name\nif (x) {\n    return 1;\n}\n"
	path := filepath.Join(dir, input+".decompiled.c")
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	p := New(Options{Input: input, Output: dir, SourceLocations: true})
	if err := p.ApplyARM64DecompilationEnhancements(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path + ".enhanced")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original || strings.Contains(string(got), "0x400000") {
		t.Fatalf("enhancement invented locations or changed rendered output: %q", got)
	}
}
