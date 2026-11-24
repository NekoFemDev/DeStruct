package arm64lift

import (
	"testing"

	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/native"
)

// Sprint 6 tests: lane-wise vector operations, fmla/fmls, dup and
// multi-register ld1/st1.

func decodeSIMD(t *testing.T, bytes []byte) native.DetailedInstruction {
	t.Helper()
	d, err := native.NewDisassembler(native.ArchARM64, native.ModeARM64|native.ModeLITTLE_ENDIAN)
	if err != nil {
		t.Fatalf("NewDisassembler: %v", err)
	}
	defer d.Close()
	ins, err := d.DisassembleDetailed(bytes, 0x1000)
	if err != nil || len(ins) != 1 {
		t.Fatalf("DisassembleDetailed: %v (%d instructions)", err, len(ins))
	}
	return ins[0]
}

func TestLiftFunction_VectorArithmetic(t *testing.T) {
	// fadd v0.4s, v1.4s, v2.4s
	fadd := decodeSIMD(t, []byte{0x20, 0xd4, 0x22, 0x4e})
	insns := []native.DetailedInstruction{
		fadd,
		{Address: 0x1004, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "q0"},
		}},
		ret(0x1008),
	}
	val := firstReturn(t, LiftFunction(insns, nil, nil, nil)).Value
	call, ok := val.(*ir.StaticMethodCall)
	if !ok || call.Method != "DS_VADD_F32X4" {
		t.Fatalf("vector fadd = %#v, want DS_VADD_F32X4", val)
	}

	// fmla v0.4s, v1.4s, v2.4s
	fmla := decodeSIMD(t, []byte{0x20, 0xcc, 0x22, 0x4e})
	insns[0] = fmla
	val = firstReturn(t, LiftFunction(insns, nil, nil, nil)).Value
	call, ok = val.(*ir.StaticMethodCall)
	if !ok || call.Method != "DS_VFMA_F32X4" {
		t.Fatalf("fmla = %#v, want DS_VFMA_F32X4", val)
	}

	// add v0.4s, v1.4s, v2.4s
	addv := decodeSIMD(t, []byte{0x20, 0x84, 0xa2, 0x4e})
	insns[0] = addv
	val = firstReturn(t, LiftFunction(insns, nil, nil, nil)).Value
	call, ok = val.(*ir.StaticMethodCall)
	if !ok || call.Method != "DS_VADD_U32X4" {
		t.Fatalf("vector add = %#v, want DS_VADD_U32X4", val)
	}
}

func TestLiftFunction_VectorDup(t *testing.T) {
	dup := decodeSIMD(t, []byte{0x20, 0x0c, 0x04, 0x4e})
	insns := []native.DetailedInstruction{
		dup,
		{Address: 0x1004, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "q0"},
		}},
		ret(0x1008),
	}
	val := firstReturn(t, LiftFunction(insns, []string{"p"}, nil, nil)).Value
	call, ok := val.(*ir.StaticMethodCall)
	if !ok || call.Method != "DS_VDUP_U32X4" {
		t.Fatalf("dup = %#v, want DS_VDUP_U32X4", val)
	}
}

func TestLiftFunction_MultiRegisterLD1ST1(t *testing.T) {
	// ld1 {v0.16b, v1.16b}, [x0]
	ld1 := decodeSIMD(t, []byte{0x00, 0xa0, 0x40, 0x4c})
	insns := []native.DetailedInstruction{
		ld1,
		{Address: 0x1004, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "q0"},
		}},
		ret(0x1008),
	}
	val := firstReturn(t, LiftFunction(insns, []string{"p"}, nil, nil)).Value
	fa, ok := val.(*ir.FieldAccess)
	if !ok || fa.Width != 16 {
		t.Fatalf("multi ld1 first register = %#v, want 16-byte field", val)
	}

	// st1 {v0.16b, v1.16b}, [x0]
	st1 := decodeSIMD(t, []byte{0x00, 0xa0, 0x00, 0x4c})
	insns = []native.DetailedInstruction{st1, ret(0x1004)}
	assigns := collectAssigns(LiftFunction(insns, []string{"p"}, nil, nil))
	if len(assigns) != 2 {
		t.Fatalf("multi st1 produced %d assignments, want 2", len(assigns))
	}
	for i, want := range []uint64{0, 16} {
		fa, ok := assigns[i].Target.(*ir.FieldAccess)
		if !ok || !fa.HasOffset || fa.Offset != want || fa.Width != 16 {
			t.Fatalf("st1 target %d = %#v, want 16-byte field at 0x%x", i, assigns[i].Target, want)
		}
	}
}

func TestLiftFunction_LD1PostIndex(t *testing.T) {
	// ld1 {v0.4s, v1.4s}, [x0], #32
	ld1 := decodeSIMD(t, []byte{0x00, 0xa8, 0xdf, 0x4c})
	insns := []native.DetailedInstruction{ld1, ret(0x1004)}
	val := firstReturn(t, LiftFunction(insns, []string{"p"}, nil, nil)).Value
	sum, ok := val.(*ir.BinaryExpr)
	if !ok || sum.Op != "+" {
		t.Fatalf("ld1 post-index return = %#v, want base + 32", val)
	}
	lit, ok := sum.Right.(*ir.IntLit)
	if !ok || lit.Value != 32 {
		t.Fatalf("ld1 post-index offset = %#v, want 32", sum.Right)
	}
}
