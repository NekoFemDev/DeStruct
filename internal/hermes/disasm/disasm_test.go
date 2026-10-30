package disasm

import (
	"os"
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/hermes/ir"
	"github.com/destruct/destruct/internal/hermes/parser"
)

const sampleHBCPath = "../testdata/sample.hbc"

var sampleAvailable bool

func TestMain(m *testing.M) {
	if _, err := os.Stat(sampleHBCPath); err == nil {
		sampleAvailable = true
	}
	os.Exit(m.Run())
}

func requireModule(t *testing.T) *ir.Module {
	t.Helper()
	if !sampleAvailable {
		t.Skipf("%s not present; skipping fixture test", sampleHBCPath)
	}
	data, err := os.ReadFile(sampleHBCPath)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	m, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

// functionTwoGolden is the exact hermes-dec output for function #2 of the
// fixture, byte-for-byte (validated against the reference tool output for
// the whole file). It pins the header line format, operand rendering,
// string comments and section separators.
const functionTwoGolden = `=> [Function #2 "clear" of 37 bytes]: 1 params, frame size=9, strict=1, exc handler=0, debug info=0  @ offset 0x00377cfd

Bytecode listing:

==> 00000000: <GetGlobalObject>: <Reg8: 0>
==> 00000002: <TryGetById>: <Reg8: 0, Reg8: 0, UInt8: 1, string_id: 25>  # String: 'Map' (Identifier)
==> 00000008: <GetByIdShort>: <Reg8: 1, Reg8: 0, UInt8: 2, string_id: 200>  # String: 'prototype' (Identifier)
==> 0000000d: <CreateThis>: <Reg8: 1, Reg8: 1, Reg8: 0>
==> 00000011: <Mov>: <Reg8: 2, Reg8: 1>
==> 00000014: <Construct>: <Reg8: 0, Reg8: 0, UInt8: 1>
==> 00000018: <SelectObject>: <Reg8: 0, Reg8: 1, Reg8: 0>
==> 0000001c: <GetEnvironment>: <Reg8: 1, UInt8: 0>
==> 0000001f: <StoreToEnvironment>: <Reg8: 1, UInt8: 1, Reg8: 0>
==> 00000023: <Ret>: <Reg8: 0>


===============

`

func TestFunctionGolden(t *testing.T) {
	m := requireModule(t)
	text, err := Function(m, 2)
	if err != nil {
		t.Fatalf("Function: %v", err)
	}
	if text != functionTwoGolden {
		t.Fatalf("function #2 disassembly differs from golden output.\n--- got ---\n%s\n--- want ---\n%s", text, functionTwoGolden)
	}
}

// TestEditableCaseLines checks the editable extension: switch jump table
// cases are printed only when requested.
func TestEditableCaseLines(t *testing.T) {
	m := requireModule(t)
	if err := parser.Decode(m); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	switchIdx := -1
	for i := range m.Functions {
		for j := range m.Functions[i].Instructions {
			in := &m.Functions[i].Instructions[j]
			if (in.Name() == "SwitchImm" || in.Name() == "UIntSwitchImm") && len(in.JumpTable) > 0 {
				switchIdx = i
			}
		}
		if switchIdx >= 0 {
			break
		}
	}
	if switchIdx < 0 {
		t.Skip("fixture has no switch with a jump table")
	}

	var plain strings.Builder
	if err := WriteFunction(&plain, m, switchIdx, Options{}); err != nil {
		t.Fatalf("WriteFunction: %v", err)
	}
	if strings.Contains(plain.String(), "    case 0:") {
		t.Fatal("default output must not contain editable case lines")
	}

	var editable strings.Builder
	if err := WriteFunction(&editable, m, switchIdx, Options{Editable: true}); err != nil {
		t.Fatalf("WriteFunction(editable): %v", err)
	}
	if !strings.Contains(editable.String(), "    case 0:") {
		t.Fatal("editable output is missing case lines")
	}
}
