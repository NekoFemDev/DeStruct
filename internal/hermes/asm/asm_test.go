package asm

import (
	"bytes"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/hermes/disasm"
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

func parseSample(t *testing.T, data []byte) *ir.Module {
	t.Helper()
	m, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

// TestRoundTripUnchanged disassembles the whole fixture and assembles the
// untouched text back: no function may be reported changed, and the
// result must be byte-for-byte the input.
func TestRoundTripUnchanged(t *testing.T) {
	data := requireSample(t)
	m := parseSample(t, data)

	text, err := disasm.Disassemble(m)
	if err != nil {
		t.Fatalf("Disassemble: %v", err)
	}

	res, err := Assemble(m, text)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(res.ChangedFunctions) != 0 {
		t.Fatalf("unmodified round trip reported %d changed functions: %v (first few)", len(res.ChangedFunctions), res.ChangedFunctions[:min(10, len(res.ChangedFunctions))])
	}
	if !bytes.Equal(res.Data, data) {
		t.Fatalf("unmodified round trip changed the file bytes (%d -> %d bytes)", len(data), len(res.Data))
	}
}

// TestEditOperandNoSizeChange edits one register operand of a small
// function, assembles, and verifies the patched file decodes with the new
// value while everything else stays intact.
func TestEditOperandNoSizeChange(t *testing.T) {
	data := requireSample(t)
	m := parseSample(t, data)
	if err := parser.Decode(m); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	text, err := disasm.Function(m, 2)
	if err != nil {
		t.Fatalf("Function: %v", err)
	}
	const from = "00000011: <Mov>: <Reg8: 2, Reg8: 1>"
	const to = "00000011: <Mov>: <Reg8: 3, Reg8: 1>"
	edited := strings.Replace(text, from, to, 1)
	if edited == text {
		t.Fatalf("test edit did not apply; disassembly of function #2 no longer contains %q:\n%s", from, text)
	}

	res, err := Assemble(m, edited)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(res.ChangedFunctions) != 1 || res.ChangedFunctions[0] != 2 {
		t.Fatalf("ChangedFunctions = %v, want [2]", res.ChangedFunctions)
	}
	if res.SizeDelta != 0 {
		t.Fatalf("SizeDelta = %d, want 0", res.SizeDelta)
	}

	// The result must be a valid file (Parse verifies the SHA1 footer).
	m2 := parseSample(t, res.Data)
	if err := parser.Decode(m2); err != nil {
		t.Fatalf("Decode(assembled): %v", err)
	}

	var found bool
	for i := range m2.Functions[2].Instructions {
		in := &m2.Functions[2].Instructions[i]
		if in.Offset != 0x11 {
			continue
		}
		found = true
		if in.Name() != "Mov" {
			t.Fatalf("instruction at 0x11 = %s, want Mov", in.Name())
		}
		if got := in.Operand(0); got != 3 {
			t.Fatalf("Mov dst operand = %d, want 3", got)
		}
	}
	if !found {
		t.Fatal("no instruction at offset 0x11 in patched function #2")
	}

	// Other functions must be untouched.
	if !bytes.Equal(m2.Functions[0].Bytecode, m.Functions[0].Bytecode) {
		t.Fatal("function #0 bytecode changed in an unrelated edit")
	}
	if !bytes.Equal(m2.Functions[3].Bytecode, m.Functions[3].Bytecode) {
		t.Fatal("function #3 bytecode changed in an unrelated edit")
	}
}

// TestJumpRelaxation inserts filler instructions between a Jmp and its
// target until the displacement no longer fits a signed byte, and checks
// the assembler promotes the branch to JmpLong while keeping the target
// correct.
func TestJumpRelaxation(t *testing.T) {
	data := requireSample(t)
	m := parseSample(t, data)
	if err := parser.Decode(m); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	// Find a small function with exactly one short forward Jmp, so the
	// only branch in it gets pushed out of range by the filler.
	funcIdx := -1
	var originalDisp int64
	var jmpOffset uint32
	for i := range m.Functions {
		instrs := m.Functions[i].Instructions
		if len(instrs) < 4 || len(instrs) > 150 {
			continue
		}
		hasSwitch := false
		jmpCount := 0
		for j := range instrs {
			switch instrs[j].Name() {
			case "SwitchImm", "UIntSwitchImm", "StringSwitchImm":
				hasSwitch = true
			case "Jmp":
				disp := int64(int32(instrs[j].Operand(0)))
				if disp <= 0 || disp >= 120 {
					hasSwitch = true // disqualify via the no-switch rule
					continue
				}
				jmpCount++
				originalDisp = disp
				jmpOffset = instrs[j].Offset
			}
		}
		if hasSwitch || jmpCount != 1 {
			continue
		}
		funcIdx = i
		break
	}
	if funcIdx < 0 {
		t.Skip("fixture has no suitable single-forward-Jmp function")
	}

	originalTargetName := ""
	for j := range m.Functions[funcIdx].Instructions {
		if m.Functions[funcIdx].Instructions[j].Offset == jmpOffset+uint32(originalDisp) {
			originalTargetName = m.Functions[funcIdx].Instructions[j].Name()
		}
	}
	if originalTargetName == "" {
		t.Fatalf("cannot find original Jmp target at offset 0x%x", jmpOffset+uint32(originalDisp))
	}

	text, err := disasm.Function(m, funcIdx)
	if err != nil {
		t.Fatalf("Function(%d): %v", funcIdx, err)
	}

	// Insert filler lines directly after the Jmp line: the target moves
	// further away by one byte per inserted instruction.
	const fillerCount = 200
	lines := strings.Split(text, "\n")
	var out []string
	inserted := false
	for _, line := range lines {
		out = append(out, line)
		if !inserted && strings.Contains(line, "<Jmp>:") {
			for k := 0; k < fillerCount; k++ {
				out = append(out, "==> 00000000: <Unreachable>: <>")
			}
			inserted = true
		}
	}
	if !inserted {
		t.Fatalf("no Jmp line found in function #%d", funcIdx)
	}
	edited := strings.Join(out, "\n")

	res, err := Assemble(m, edited)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(res.ChangedFunctions) != 1 || res.ChangedFunctions[0] != uint32(funcIdx) {
		t.Fatalf("ChangedFunctions = %v, want [%d]", res.ChangedFunctions, funcIdx)
	}
	// Other short branches in the function may also have been promoted,
	// so the delta is at least the filler size (and 3 bytes for the Jmp
	// itself).
	if res.SizeDelta < fillerCount {
		t.Fatalf("SizeDelta = %d, want at least %d", res.SizeDelta, fillerCount)
	}

	m2 := parseSample(t, res.Data)
	if err := parser.Decode(m2); err != nil {
		t.Fatalf("Decode(assembled): %v", err)
	}
	instrs := m2.Functions[funcIdx].Instructions
	if len(instrs) == 0 {
		t.Fatal("patched function has no instructions")
	}
	// Locate the promoted unconditional branch. Earlier instructions
	// may also have been promoted (which shifts the Jmp's own offset),
	// so find it by name rather than by the original offset.
	var jmpInstr *ir.Instruction
	var jmpIdx = -1
	for j := range instrs {
		if instrs[j].Name() == "JmpLong" {
			if jmpInstr != nil {
				t.Fatalf("more than one JmpLong in patched function (want exactly the edited Jmp)")
			}
			jmpInstr = &instrs[j]
			jmpIdx = j
		}
	}
	if jmpInstr == nil {
		t.Fatalf("no JmpLong found in patched function; instructions: %d", len(instrs))
	}

	targetOffset := jmpInstr.Offset + uint32(int32(jmpInstr.Operand(0)))
	if targetOffset <= jmpInstr.Offset+uint32(fillerCount) {
		t.Fatalf("JmpLong target %08x is not past the inserted filler (jmp at %08x)", targetOffset, jmpInstr.Offset)
	}
	var target *ir.Instruction
	for j := range instrs {
		if instrs[j].Offset == targetOffset {
			target = &instrs[j]
			break
		}
	}
	if target == nil {
		t.Fatalf("JmpLong target %08x is not an instruction boundary", targetOffset)
	}
	if target.Name() != originalTargetName {
		t.Fatalf("JmpLong target instruction = %s, want %s", target.Name(), originalTargetName)
	}

	// The inserted filler instructions must be present right after it.
	for k := jmpIdx + 1; k <= jmpIdx+fillerCount; k++ {
		if instrs[k].Name() != "Unreachable" {
			t.Fatalf("instruction %d = %s, want Unreachable", k, instrs[k].Name())
		}
	}
}

// TestEditAliasedFunction edits one of two functions that share the same
// bytecode bytes; the other must keep working on its own copy.
func TestEditAliasedFunction(t *testing.T) {
	data := requireSample(t)
	m := parseSample(t, data)
	if err := parser.Decode(m); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	// Find a small alias group with exactly two functions.
	target, other := -1, -1
	for i := range m.Functions {
		f := &m.Functions[i]
		if f.BytecodeSizeInBytes == 0 || f.BytecodeSizeInBytes > 40 {
			continue
		}
		count := 0
		peer := -1
		for j := range m.Functions {
			if j != i && m.Functions[j].Offset == f.Offset && m.Functions[j].BytecodeSizeInBytes == f.BytecodeSizeInBytes {
				count++
				peer = j
			}
		}
		if count == 1 {
			target, other = peer, i
			break
		}
	}
	if target < 0 {
		t.Skip("fixture has no two-function alias group small enough")
	}

	otherBefore := append([]byte(nil), m.Functions[other].Bytecode...)
	otherInstrsBefore := append([]ir.Instruction(nil), m.Functions[other].Instructions...)

	text, err := disasm.Function(m, target)
	if err != nil {
		t.Fatalf("Function(%d): %v", target, err)
	}

	// Bump the first Reg8 operand value by one.
	edited := ""
	editDone := false
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if !editDone && strings.HasPrefix(line, "==> ") {
			idx := strings.Index(line, "<Reg8: ")
			if idx >= 0 {
				rest := line[idx+len("<Reg8: "):]
				end := strings.IndexAny(rest, ",>")
				if end > 0 {
					if v, err := strconv.Atoi(rest[:end]); err == nil && v < 250 {
						line = line[:idx] + "<Reg8: " + strconv.Itoa(v+1) + rest[end:]
						editDone = true
					}
				}
			}
		}
		edited += line + "\n"
	}
	if !editDone {
		t.Skip("target function has no editable Reg8 operand")
	}

	res, err := Assemble(m, edited)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(res.ChangedFunctions) != 1 || res.ChangedFunctions[0] != uint32(target) {
		t.Fatalf("ChangedFunctions = %v, want [%d]", res.ChangedFunctions, target)
	}

	m2 := parseSample(t, res.Data)
	if err := parser.Decode(m2); err != nil {
		t.Fatalf("Decode(assembled): %v", err)
	}

	// The untouched alias must decode exactly as before and own distinct
	// bytes now.
	if !bytes.Equal(m2.Functions[other].Bytecode, otherBefore) {
		t.Fatal("aliased function's bytecode changed")
	}
	if m2.Functions[other].Offset == m2.Functions[target].Offset {
		t.Fatal("aliased functions still share an offset after one was edited")
	}
	if len(m2.Functions[other].Instructions) != len(otherInstrsBefore) {
		t.Fatalf("aliased function lost instructions: %d vs %d", len(m2.Functions[other].Instructions), len(otherInstrsBefore))
	}
}

// TestSwitchRetarget retargets one case of a switch jump table through
// the editable "case N:" lines and verifies the patched table.
func TestSwitchRetarget(t *testing.T) {
	data := requireSample(t)
	m := parseSample(t, data)
	if err := parser.Decode(m); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	// Find a function with a switch whose table has at least two cases.
	funcIdx := -1
	for i := range m.Functions {
		for j := range m.Functions[i].Instructions {
			in := &m.Functions[i].Instructions[j]
			switch in.Name() {
			case "SwitchImm", "UIntSwitchImm":
				if len(in.JumpTable) >= 2 {
					funcIdx = i
				}
			}
		}
		if funcIdx >= 0 {
			break
		}
	}
	if funcIdx < 0 {
		t.Skip("fixture has no switch with multiple cases")
	}

	var sb strings.Builder
	if err := disasm.WriteFunction(&sb, m, funcIdx, disasm.Options{Editable: true}); err != nil {
		t.Fatalf("WriteFunction: %v", err)
	}
	text := sb.String()

	// Retarget the second case at the function's first instruction.
	re := regexp.MustCompile(`(?m)^    case 1: ([0-9a-fA-F]{8})$`)
	if !re.MatchString(text) {
		t.Skip("no case 1 line in editable output")
	}
	edited := re.ReplaceAllString(text, "    case 1: 00000000")

	res, err := Assemble(m, edited)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(res.ChangedFunctions) != 1 || res.ChangedFunctions[0] != uint32(funcIdx) {
		t.Fatalf("ChangedFunctions = %v, want [%d]", res.ChangedFunctions, funcIdx)
	}

	m2 := parseSample(t, res.Data)
	if err := parser.Decode(m2); err != nil {
		t.Fatalf("Decode(assembled): %v", err)
	}

	found := false
	for j := range m2.Functions[funcIdx].Instructions {
		in := &m2.Functions[funcIdx].Instructions[j]
		switch in.Name() {
		case "SwitchImm", "UIntSwitchImm":
			if len(in.JumpTable) >= 2 && in.JumpTable[1] == 0 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("retargeted case 1 does not point at offset 0 in the patched file")
	}
}
