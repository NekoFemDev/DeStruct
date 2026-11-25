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
	if !strings.Contains(out, "x19 = ds_outlined_ctx[0];") {
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
		OutlinedContextTargets: map[uint64]OutlinedContext{
			0x104c: {Regs: []string{"x19"}, Stack: true},
		},
	})
	out := renderForTest(stmts)
	for _, want := range []string{
		"ds_outlined_ctx[0] = x19;",
		"DS_OUTLINED_FRAME_RESET(sp);",
		"sp = DS_OUTLINED_FRAME_ALLOC();",
		"ds_outlined_sp = sp;",
		"ds_outlined_fp = x29;",
		"DS_TARGET(",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("jump-table dispatch missing %q:\n%s", want, out)
		}
	}
}

func TestOutlinedStackFrameAdjustments(t *testing.T) {
	insns := disassembleWords(t, 0, []uint32{
		0xd10083ff, // sub sp, sp, #0x20
		0x910003fd, // mov x29, sp
		0xaa0003f3, // mov x19, x0
		0xd0000009, // adrp x9, 0x2000
		0x91040129, // add x9, x9, #0x100
		0x1000800a, // adr x10, 0x1014
		0x7868792b, // ldrh w11, [x9, x8, lsl #1]
		0x8b0b094a, // add x10, x10, x11, lsl #2
		0xd61f0140, // br x10
	})
	reader := func(addr uint64, size int) ([]byte, bool) {
		if addr != 0x2100 {
			return nil, false
		}
		data := make([]byte, size)
		data[0] = 0x10 // 0x1014 + 0x10*4 = 0x1054
		return data, true
	}
	stmts := LiftFunctionWithOptions(insns, nil, nil, nil, reader, LiftOptions{
		OutlinedContextTargets: map[uint64]OutlinedContext{
			0x1054: {Regs: []string{"x19"}, Stack: true},
		},
	})
	out := renderForTest(stmts)
	for _, want := range []string{
		"sp = DS_OUTLINED_FRAME_ALLOC();",
		"sp = sp - 32;",
		"x29 = sp;",
		"ds_outlined_sp = sp;",
		"ds_outlined_fp = x29;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("outlined stack frame missing %q:\n%s", want, out)
		}
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
	targets := map[uint64]OutlinedContext{
		targetBase + 0x10*4: {Regs: []string{"x19", "x24"}, Stack: true},
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
	d := got[brAddr]
	if len(d.regs) != 2 || d.regs[0] != "x19" || d.regs[1] != "x24" || !d.stack {
		t.Fatalf("analyzeJumpTableContext = %+v, want regs [x19 x24] and stack", d)
	}
}

func TestOutlinedStackEntry(t *testing.T) {
	insns := disassembleWords(t, 0x1000, []uint32{
		0x910043e0, // add x0, sp, #0x10
		0xd65f03c0, // ret
	})
	out := renderForTest(LiftFunctionWithOptions(insns, nil, nil, nil, nil, LiftOptions{OutlinedStack: true}))
	for _, want := range []string{"sp = ds_outlined_sp;", "x29 = ds_outlined_fp;"} {
		if !strings.Contains(out, want) {
			t.Fatalf("outlined stack entry missing %q:\n%s", want, out)
		}
	}
}

func TestCallerStackUsed(t *testing.T) {
	if !CallerStackUsed([]native.DetailedInstruction{
		{Mnemonic: "add", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "sp"},
			{Type: native.OperandImm, Imm: 0x10},
		}},
	}) {
		t.Fatal("CallerStackUsed did not detect sp")
	}
	if CallerStackUsed([]native.DetailedInstruction{
		{Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "x1"},
		}},
	}) {
		t.Fatal("CallerStackUsed false positive")
	}
}
