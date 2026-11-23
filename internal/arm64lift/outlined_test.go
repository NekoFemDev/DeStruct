package arm64lift

import (
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/native"
)

func TestCallerContextRegs(t *testing.T) {
	insns := []native.DetailedInstruction{
		{Mnemonic: "bti"},
		{Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x19"}},
		}},
	}
	got := CallerContextRegs(insns)
	if len(got) != 1 || got[0] != "x19" {
		t.Fatalf("CallerContextRegs = %v, want [x19]", got)
	}
}

func TestCallerContextRegsIgnoresSpillAndLocalWrite(t *testing.T) {
	insns := []native.DetailedInstruction{
		{Mnemonic: "stp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x19"},
			{Type: native.OperandReg, Reg: "x20"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp"}},
		}},
		{Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x19"},
			{Type: native.OperandReg, Reg: "x0"},
		}},
		{Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x19"}},
		}},
	}
	if got := CallerContextRegs(insns); len(got) != 0 {
		t.Fatalf("CallerContextRegs = %v, want none", got)
	}
}

func TestOutlinedContextSeedAndSave(t *testing.T) {
	insns := disassembleWords(t, 0x1000, []uint32{
		0xf9400260, // ldr x0, [x19]
		0xd65f03c0, // ret
	})
	stmts := LiftFunctionWithOptions(insns, nil, nil, nil, nil, LiftOptions{
		OutlinedContextRegs: []string{"x19"},
	})
	out := renderForTest(stmts)
	if !strings.Contains(out, "x19 = eni_outlined_ctx[0];") {
		t.Fatalf("outlined context was not seeded:\n%s", out)
	}
	if !strings.Contains(out, "*(uint64_t*)((uintptr_t)x19)") {
		t.Fatalf("body did not use the seeded x19:\n%s", out)
	}
}

func TestJumpTableDispatchSavesOutlinedContext(t *testing.T) {
	insns := disassembleWords(t, 0, []uint32{
		0xaa0003f3, // mov x19, x0
		0xd0000009, // adrp x9, 0x2000
		0x91040129, // add x9, x9, #0x100
		0x1000800a, // adr x10, 0x100c
		0x7868792b, // ldrh w11, [x9, x8, lsl #1]
		0x8b0b094a, // add x10, x10, x11, lsl #2
		0xd61f0140, // br x10
	})
	reader := func(addr uint64, size int) ([]byte, bool) {
		if addr != 0x2100 {
			return nil, false
		}
		data := make([]byte, size)
		data[0] = 0x10 // target 0x100c + 0x10*4 = 0x104c
		return data, true
	}
	stmts := LiftFunctionWithOptions(insns, nil, nil, nil, reader, LiftOptions{
		OutlinedContextTargets: map[uint64][]string{0x104c: {"x19"}},
	})
	out := renderForTest(stmts)
	if !strings.Contains(out, "eni_outlined_ctx[0] = x19;") {
		t.Fatalf("jump-table dispatch did not save outlined context:\n%s", out)
	}
}

func TestAnalyzeJumpTableContext(t *testing.T) {
	const (
		tableBase  = 0x2100
		targetBase = 0x1000
		brAddr     = 0x2000
	)
	insns := []native.DetailedInstruction{
		{Mnemonic: "adrp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x9"},
			{Type: native.OperandImm, Imm: 0x2000},
		}},
		{Mnemonic: "add", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x9"},
			{Type: native.OperandReg, Reg: "x9"},
			{Type: native.OperandImm, Imm: 0x100},
		}},
		{Mnemonic: "adr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x10"},
			{Type: native.OperandImm, Imm: targetBase},
		}},
		{Mnemonic: "ldrh", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w11"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x9", Index: "x8", IndexShiftType: 1, IndexShiftValue: 1}},
		}},
		{Mnemonic: "add", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x10"},
			{Type: native.OperandReg, Reg: "x10"},
			{Type: native.OperandReg, Reg: "w11", ShiftType: 1, ShiftValue: 2},
		}},
		{Mnemonic: "br", Address: brAddr, Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x10"},
		}},
	}
	targets := map[uint64][]string{
		targetBase + 0x10*4: {"x19", "x24"},
	}
	reader := func(addr uint64, size int) ([]byte, bool) {
		if addr != tableBase {
			return nil, false
		}
		data := make([]byte, size)
		data[0] = 0x10
		return data, true
	}
	got := analyzeJumpTableContext(insns, targets, reader)
	regs := got[brAddr]
	if len(regs) != 2 || regs[0] != "x19" || regs[1] != "x24" {
		t.Fatalf("analyzeJumpTableContext = %v, want [x19 x24]", got)
	}
}
