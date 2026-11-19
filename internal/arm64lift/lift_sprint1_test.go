package arm64lift

import (
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/native"
)

// Sprint 1 instruction-coverage tests: movk/movz/movn, byte and halfword
// loads/stores, tst/subs/adds/ands flag snapshots, csel family, and
// register-indexed addressing.

func ret(addr uint64) native.DetailedInstruction {
	return native.DetailedInstruction{Address: addr, Size: 4, Mnemonic: "ret"}
}

func firstReturn(t *testing.T, stmts []ir.Stmt) *ir.ReturnStmt {
	t.Helper()
	for _, s := range stmts {
		if r, ok := s.(*ir.ReturnStmt); ok {
			return r
		}
	}
	t.Fatalf("no ReturnStmt in %v", stmts)
	return nil
}

func firstAssign(t *testing.T, stmts []ir.Stmt) *ir.AssignStmt {
	t.Helper()
	for _, s := range stmts {
		if a, ok := s.(*ir.AssignStmt); ok {
			return a
		}
	}
	t.Fatalf("no AssignStmt in %v", stmts)
	return nil
}

func renderCFunctionToString(stmts []ir.Stmt) string {
	var b strings.Builder
	RenderCFunction(&b, "test_fn", stmts)
	return b.String()
}

func TestLiftFunction_MovkBuildsConstant(t *testing.T) {
	insns := []native.DetailedInstruction{
		// mov x0, #0x1234
		{Address: 0x0, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandImm, Imm: 0x1234},
		}},
		// movk x0, #0xabcd, lsl #16
		{Address: 0x4, Size: 4, Mnemonic: "movk", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandImm, Imm: 0xabcd, ShiftType: 1, ShiftValue: 16},
		}},
		ret(0x8),
	}

	retStmt := firstReturn(t, LiftFunction(insns, nil, nil, nil))
	lit, ok := retStmt.Value.(*ir.IntLit)
	if !ok {
		t.Fatalf("return value = %T, want *ir.IntLit", retStmt.Value)
	}
	if got, want := uint64(lit.Value), uint64(0xabcd1234); got != want {
		t.Fatalf("movk result = 0x%x, want 0x%x", got, want)
	}
}

func TestLiftFunction_MovzAndMovn(t *testing.T) {
	insns := []native.DetailedInstruction{
		// movz x0, #0x1234, lsl #16
		{Address: 0x0, Size: 4, Mnemonic: "movz", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandImm, Imm: 0x1234, ShiftType: 1, ShiftValue: 16},
		}},
		ret(0x4),
	}
	lit, ok := firstReturn(t, LiftFunction(insns, nil, nil, nil)).Value.(*ir.IntLit)
	if !ok || uint64(lit.Value) != 0x12340000 {
		t.Fatalf("movz result = %#v, want 0x12340000", firstReturn(t, LiftFunction(insns, nil, nil, nil)).Value)
	}

	insns[0] = native.DetailedInstruction{
		Address: 0x0, Size: 4, Mnemonic: "movn", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandImm, Imm: 0},
		},
	}
	lit, ok = firstReturn(t, LiftFunction(insns, nil, nil, nil)).Value.(*ir.IntLit)
	if !ok || lit.Value != -1 {
		t.Fatalf("movn result = %#v, want -1", lit)
	}
}

func TestLiftFunction_LdrbWidth(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ldrb w0, [x0, #0x10]
		{Address: 0x0, Size: 4, Mnemonic: "ldrb", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0", Disp: 0x10}},
		}},
		ret(0x4),
	}

	val := firstReturn(t, LiftFunction(insns, []string{"p"}, nil, nil)).Value
	fa, ok := val.(*ir.FieldAccess)
	if !ok {
		t.Fatalf("ldrb value = %T, want *ir.FieldAccess", val)
	}
	if fa.Width != 1 || !fa.HasOffset || fa.Offset != 0x10 {
		t.Fatalf("ldrb access = {width:%d hasOffset:%v offset:0x%x}, want {1 true 0x10}", fa.Width, fa.HasOffset, fa.Offset)
	}
}

func TestLiftFunction_StrbIndexedArray(t *testing.T) {
	insns := []native.DetailedInstruction{
		// strb w1, [x0, x1]
		{Address: 0x0, Size: 4, Mnemonic: "strb", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0", Index: "x1"}},
		}},
		ret(0x4),
	}

	target := firstAssign(t, LiftFunction(insns, []string{"buf", "val"}, nil, nil)).Target
	arr, ok := target.(*ir.ArrayAccess)
	if !ok {
		t.Fatalf("strb target = %T, want *ir.ArrayAccess", target)
	}
	if arr.Width != 1 {
		t.Fatalf("strb array width = %d, want 1", arr.Width)
	}
	out := renderCFunctionToString(LiftFunction(insns, []string{"buf", "val"}, nil, nil))
	if !strings.Contains(out, "uint8_t") || !strings.Contains(out, "[val]") {
		t.Fatalf("strb output does not render a uint8_t array access:\n%s", out)
	}
}

func TestLiftFunction_LdrIndexedScaled(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ldr w0, [x0, x1, lsl #2]
		{Address: 0x0, Size: 4, Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{
				Base: "x0", Index: "x1", IndexShiftType: 1, IndexShiftValue: 2,
			}},
		}},
		ret(0x4),
	}

	val := firstReturn(t, LiftFunction(insns, []string{"arr", "i"}, nil, nil)).Value
	arr, ok := val.(*ir.ArrayAccess)
	if !ok {
		t.Fatalf("ldr value = %T, want *ir.ArrayAccess", val)
	}
	if arr.Width != 4 {
		t.Fatalf("ldr array width = %d, want 4", arr.Width)
	}
	out := renderCFunctionToString(LiftFunction(insns, []string{"arr", "i"}, nil, nil))
	if !strings.Contains(out, "uint32_t") || !strings.Contains(out, "[i]") {
		t.Fatalf("ldr output does not render a uint32_t array access:\n%s", out)
	}
}

func TestLiftFunction_LdrIndexedUnscaledWidth(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ldr w0, [x0, x1] - byte offset, not an implicit *4 scale
		{Address: 0x0, Size: 4, Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0", Index: "x1"}},
		}},
		ret(0x4),
	}

	val := firstReturn(t, LiftFunction(insns, []string{"base", "off"}, nil, nil)).Value
	fa, ok := val.(*ir.FieldAccess)
	if !ok {
		t.Fatalf("ldr value = %T, want *ir.FieldAccess", val)
	}
	if fa.Width != 4 {
		t.Fatalf("ldr access width = %d, want 4", fa.Width)
	}
	out := renderCFunctionToString(LiftFunction(insns, []string{"base", "off"}, nil, nil))
	if !strings.Contains(out, "base + off") {
		t.Fatalf("unscaled indexed ldr did not render as byte-offset arithmetic:\n%s", out)
	}
}

func TestLiftFunction_TstCset(t *testing.T) {
	insns := []native.DetailedInstruction{
		// tst w0, #0xff
		{Address: 0x0, Size: 4, Mnemonic: "tst", WritesFlags: true, Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 0xff},
		}},
		// cset w0, eq
		{Address: 0x4, Size: 4, Mnemonic: "cset", OpStr: "w0, eq", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
		}},
		ret(0x8),
	}

	val := firstReturn(t, LiftFunction(insns, []string{"a"}, nil, nil)).Value
	cmp, ok := val.(*ir.BinaryExpr)
	if !ok || cmp.Op != "==" {
		t.Fatalf("cset value = %#v, want an == comparison", val)
	}
	and, ok := cmp.Left.(*ir.BinaryExpr)
	if !ok || and.Op != "&" {
		t.Fatalf("tst value = %#v, want a bitwise-and on the left", cmp.Left)
	}
}

func TestLiftFunction_SubsCset(t *testing.T) {
	insns := []native.DetailedInstruction{
		// subs w0, w0, #1
		{Address: 0x0, Size: 4, Mnemonic: "subs", WritesFlags: true, Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 1},
		}},
		// cset w0, eq
		{Address: 0x4, Size: 4, Mnemonic: "cset", OpStr: "w0, eq", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
		}},
		ret(0x8),
	}

	val := firstReturn(t, LiftFunction(insns, []string{"a"}, nil, nil)).Value
	cmp, ok := val.(*ir.BinaryExpr)
	if !ok || cmp.Op != "==" {
		t.Fatalf("cset value = %#v, want an == comparison", val)
	}
	lit, ok := cmp.Right.(*ir.IntLit)
	if !ok || lit.Value != 1 {
		t.Fatalf("subs comparison rhs = %#v, want 1", cmp.Right)
	}
}

func TestLiftFunction_CselAndCsinc(t *testing.T) {
	insns := []native.DetailedInstruction{
		// cmp w0, #0
		{Address: 0x0, Size: 4, Mnemonic: "cmp", WritesFlags: true, Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 0},
		}},
		// csel w0, w1, w2, eq
		{Address: 0x4, Size: 4, Mnemonic: "csel", OpStr: "w0, w1, w2, eq", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandReg, Reg: "w2"},
		}},
		ret(0x8),
	}

	val := firstReturn(t, LiftFunction(insns, []string{"a", "b", "c"}, nil, nil)).Value
	tern, ok := val.(*ir.TernaryExpr)
	if !ok {
		t.Fatalf("csel value = %T, want *ir.TernaryExpr", val)
	}
	cmp, ok := tern.Cond.(*ir.BinaryExpr)
	if !ok || cmp.Op != "==" {
		t.Fatalf("csel condition = %#v, want an == comparison", tern.Cond)
	}

	insns[1] = native.DetailedInstruction{
		Address: 0x4, Size: 4, Mnemonic: "csinc", OpStr: "w0, w1, w2, eq", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandReg, Reg: "w2"},
		},
	}
	val = firstReturn(t, LiftFunction(insns, []string{"a", "b", "c"}, nil, nil)).Value
	tern, ok = val.(*ir.TernaryExpr)
	if !ok {
		t.Fatalf("csinc value = %T, want *ir.TernaryExpr", val)
	}
	inc, ok := tern.FalseExpr.(*ir.BinaryExpr)
	if !ok || inc.Op != "+" {
		t.Fatalf("csinc false arm = %#v, want Rm + 1", tern.FalseExpr)
	}
}

func TestLiftFunction_StrWzrUsesRegisterWidth(t *testing.T) {
	insns := []native.DetailedInstruction{
		// str wzr, [x0, x1, lsl #2]
		{Address: 0x0, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "wzr"},
			{Type: native.OperandMem, Mem: native.MemOperand{
				Base: "x0", Index: "x1", IndexShiftType: 1, IndexShiftValue: 2,
			}},
		}},
		ret(0x4),
	}

	target := firstAssign(t, LiftFunction(insns, []string{"arr", "i"}, nil, nil)).Target
	arr, ok := target.(*ir.ArrayAccess)
	if !ok {
		t.Fatalf("str wzr target = %T, want *ir.ArrayAccess", target)
	}
	if arr.Width != 4 {
		t.Fatalf("str wzr array width = %d, want 4", arr.Width)
	}
}

func TestLiftFunction_ShiftedALUOperand(t *testing.T) {
	insns := []native.DetailedInstruction{
		// add w0, w0, w1, lsl #2
		{Address: 0x0, Size: 4, Mnemonic: "add", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w1", ShiftType: 1, ShiftValue: 2},
		}},
		ret(0x4),
	}

	val := firstReturn(t, LiftFunction(insns, []string{"a", "b"}, nil, nil)).Value
	add, ok := val.(*ir.BinaryExpr)
	if !ok || add.Op != "+" {
		t.Fatalf("add value = %#v, want a + expression", val)
	}
	shift, ok := add.Right.(*ir.BinaryExpr)
	if !ok || shift.Op != "<<" {
		t.Fatalf("shifted rhs = %#v, want b << 2", add.Right)
	}
}

func TestLiftFunction_LdurNegativeOffset(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ldur w0, [x0, #-8]
		{Address: 0x0, Size: 4, Mnemonic: "ldur", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0", Disp: -8}},
		}},
		ret(0x4),
	}

	val := firstReturn(t, LiftFunction(insns, []string{"p"}, nil, nil)).Value
	fa, ok := val.(*ir.FieldAccess)
	if !ok {
		t.Fatalf("ldur value = %T, want *ir.FieldAccess", val)
	}
	if fa.Disp != -8 || fa.HasOffset {
		t.Fatalf("ldur access = {disp:%d hasOffset:%v}, want {-8 false}", fa.Disp, fa.HasOffset)
	}
	out := renderCFunctionToString(LiftFunction(insns, []string{"p"}, nil, nil))
	if !strings.Contains(out, "- 0x8") {
		t.Fatalf("negative ldur offset was not rendered:\n%s", out)
	}
}

func TestLiftFunction_LdurStur(t *testing.T) {
	insns := []native.DetailedInstruction{
		// stur w1, [x0, #0xc]
		{Address: 0x0, Size: 4, Mnemonic: "stur", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0", Disp: 0xc}},
		}},
		ret(0x4),
	}

	target := firstAssign(t, LiftFunction(insns, []string{"p", "v"}, nil, nil)).Target
	fa, ok := target.(*ir.FieldAccess)
	if !ok {
		t.Fatalf("stur target = %T, want *ir.FieldAccess", target)
	}
	if fa.Width != 4 || !fa.HasOffset || fa.Offset != 0xc {
		t.Fatalf("stur access = {width:%d hasOffset:%v offset:0x%x}, want {4 true 0xc}", fa.Width, fa.HasOffset, fa.Offset)
	}
}
