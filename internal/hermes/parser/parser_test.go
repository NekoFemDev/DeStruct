package parser

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/destruct/destruct/internal/hermes/ir"
)

// sampleHBCPath points at the shared package fixture. The file is a large
// (~8 MB) real React Native bundle, so it is allowed to be absent
// (fresh clones, source tarballs without test data): TestMain notes its
// absence and every fixture test skips instead of failing.
const sampleHBCPath = "../testdata/sample.hbc"

var sampleAvailable bool

func TestMain(m *testing.M) {
	if _, err := os.Stat(sampleHBCPath); err == nil {
		sampleAvailable = true
	}
	os.Exit(m.Run())
}

func requireSample(t *testing.T) []byte {
	t.Helper()
	if !sampleAvailable {
		t.Skipf("%s not present; skipping fixture test", sampleHBCPath)
	}
	data, err := os.ReadFile(sampleHBCPath)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

func TestDetectVersion(t *testing.T) {
	data := requireSample(t)

	version, err := DetectVersion(data)
	if err != nil {
		t.Fatalf("DetectVersion: %v", err)
	}
	if version != 96 {
		t.Fatalf("fixture version = %d, want 96", version)
	}

	if _, err := DetectVersion(data[:11]); err == nil {
		t.Error("DetectVersion accepted an 11-byte file")
	}
	if _, err := DetectVersion([]byte("not hermes!!")); !errors.Is(err, ErrNotHermes) {
		t.Errorf("DetectVersion(bad magic) = %v, want ErrNotHermes", err)
	}
	// A truncated but magic-correct header must not be accepted by Parse.
	bad := append([]byte(nil), data[:64]...)
	if _, err := Parse(bad); err == nil {
		t.Error("Parse accepted a 64-byte truncated file")
	}
}

func TestParseSampleHeader(t *testing.T) {
	data := requireSample(t)

	m, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	h := m.Header
	if h.Version != 96 {
		t.Errorf("Version = %d, want 96", h.Version)
	}
	if h.FileLength != uint32(len(data)) {
		t.Errorf("FileLength = %d, want %d", h.FileLength, len(data))
	}
	for _, tc := range []struct {
		name string
		got  uint32
		want uint32
	}{
		{"FunctionCount", h.FunctionCount, 41052},
		{"StringCount", h.StringCount, 49147},
		{"StringKindCount", h.StringKindCount, 3},
		{"IdentifierCount", h.IdentifierCount, 21563},
		{"RegExpCount", h.RegExpCount, 541},
		{"FunctionSourceCount", h.FunctionSourceCount, 686},
		{"BigIntCount", h.BigIntCount, 0},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
	if len(m.Functions) != int(h.FunctionCount) {
		t.Errorf("parsed %d functions, want %d", len(m.Functions), h.FunctionCount)
	}
	if len(m.Strings) != int(h.StringCount) {
		t.Errorf("decoded %d strings, want %d", len(m.Strings), h.StringCount)
	}
	if len(m.StringKinds) != int(h.StringCount) {
		t.Errorf("expanded %d string kinds, want %d", len(m.StringKinds), h.StringCount)
	}
}

func TestParseSampleFunctionZero(t *testing.T) {
	data := requireSample(t)

	m, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	f := m.Functions[0]
	if f.Name != "global" {
		t.Errorf("Functions[0].Name = %q, want %q", f.Name, "global")
	}
	if f.Offset != 0x35ab04 {
		t.Errorf("Functions[0].Offset = 0x%x, want 0x35ab04", f.Offset)
	}
	if f.BytecodeSizeInBytes != 118943 {
		t.Errorf("Functions[0].BytecodeSizeInBytes = %d, want 118943", f.BytecodeSizeInBytes)
	}
	if !f.Overflowed {
		t.Error("Functions[0].Overflowed = false, want true (its bytecode size exceeds the small header field)")
	}
	if f.ParamCount != 1 {
		t.Errorf("Functions[0].ParamCount = %d, want 1", f.ParamCount)
	}
	if f.FrameSize != 21 {
		t.Errorf("Functions[0].FrameSize = %d, want 21", f.FrameSize)
	}
	if len(f.Bytecode) != int(f.BytecodeSizeInBytes) {
		t.Errorf("Functions[0].Bytecode length = %d, want %d", len(f.Bytecode), f.BytecodeSizeInBytes)
	}
	if !f.HasExceptionHandler {
		t.Fatal("Functions[0].HasExceptionHandler = false, want true")
	}
	want := []ir.ExceptionHandler{{Start: 0xdb, End: 0x128, Target: 0x12a}}
	if len(f.ExceptionHandlers) != len(want) {
		t.Fatalf("Functions[0] has %d exception handlers, want %d", len(f.ExceptionHandlers), len(want))
	}
	for i := range want {
		if f.ExceptionHandlers[i] != want[i] {
			t.Errorf("Functions[0].ExceptionHandlers[%d] = %+v, want %+v", i, f.ExceptionHandlers[i], want[i])
		}
	}
}

// TestDecodeSample walks every function of the fixture and checks the
// decode is complete and self-consistent. The expected instruction total
// was cross-checked against an independent decoder of the same vendored
// v96 opcode data; a change in either the table or the decoder shows up
// here as an exact-count mismatch rather than a silent misalignment.
func TestDecodeSample(t *testing.T) {
	data := requireSample(t)

	m, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := Decode(m); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	total := 0
	for i := range m.Functions {
		f := &m.Functions[i]
		total += len(f.Instructions)

		// Instructions must tile the function's bytecode exactly: each
		// offset is where the previous instruction ended.
		var off uint32
		for j := range f.Instructions {
			in := &f.Instructions[j]
			if in.Offset != off {
				t.Fatalf("function #%d: instruction %d at offset %d, expected %d", i, j, in.Offset, off)
			}
			if in.Op == nil {
				t.Fatalf("function #%d: unknown opcode 0x%02x at offset %d", i, in.RawOp, in.Offset)
			}
			off = in.NextOffset()
		}
		if int(off) != len(f.Bytecode) {
			t.Fatalf("function #%d: decoded %d bytes, bytecode is %d bytes", i, off, len(f.Bytecode))
		}
	}

	const wantTotal = 1106986
	if total != wantTotal {
		t.Errorf("decoded %d instructions, want %d (was the opcode table regenerated?)", total, wantTotal)
	}
}

func TestParseRejectsGarbageWithoutPanicking(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		bytes.Repeat([]byte{0}, 128),
		bytes.Repeat([]byte{0xFF}, 256),
	}
	// A magic-correct file full of zeroes: header is valid enough to
	// enter the section parsers, which must then reject it cleanly.
	zero := make([]byte, 512)
	irMagic := []byte{0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f}
	copy(zero, irMagic)
	zero[8] = 96 // version 96
	inputs = append(inputs, zero)

	for i, in := range inputs {
		if _, err := Parse(in); err == nil {
			t.Errorf("input %d: Parse succeeded on garbage", i)
		}
	}
}
