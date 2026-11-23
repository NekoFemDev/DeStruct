package arm64lift

import (
	"testing"

	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/native"
)

// Sprint 2 instruction-coverage tests: ldp/stp, pre/post-indexed
// writeback, madd/msub, udiv/sdiv, ubfx/sbfx, sign/zero extension,
// signed loads, acquire/release and exclusive store.

func collectAssigns(stmts []ir.Stmt) []*ir.AssignStmt {
	var out []*ir.AssignStmt
	for _, s := range stmts {
		if a, ok := s.(*ir.AssignStmt); ok {
			out = append(out, a)
		}
	}
	return out
}

func TestLiftFunction_LdpPair(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ldp x0, x1, [x2, #0x10]
		{Address: 0x0, Size: 4, Mnemonic: "ldp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "x1"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x2", Disp: 0x10}},
		}},
		// add x0, x0, x1
		{Address: 0x4, Size: 4, Mnemonic: "add", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "x1"},
		}},
		ret(0x8),
	}

	val := firstReturn(t, LiftFunction(insns, []string{"a", "b", "p"}, nil, nil)).Value
	add, ok := val.(*ir.BinaryExpr)
	if !ok || add.Op != "+" {
		t.Fatalf("ldp result = %#v, want a + expression", val)
	}
	left, ok := add.Left.(*ir.FieldAccess)
	if !ok || !left.HasOffset || left.Offset != 0x10 {
		t.Fatalf("ldp first value = %#v, want field 0x10", add.Left)
	}
	right, ok := add.Right.(*ir.FieldAccess)
	if !ok || !right.HasOffset || right.Offset != 0x18 {
		t.Fatalf("ldp second value = %#v, want field 0x18", add.Right)
	}
}

func TestLiftFunction_StpPair(t *testing.T) {
	insns := []native.DetailedInstruction{
		// stp x0, x1, [x2, #0x10]
		{Address: 0x0, Size: 4, Mnemonic: "stp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "x1"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x2", Disp: 0x10}},
		}},
		ret(0x4),
	}

	assigns := collectAssigns(LiftFunction(insns, []string{"a", "b", "p"}, nil, nil))
	if len(assigns) != 2 {
		t.Fatalf("stp produced %d assignments, want 2: %v", len(assigns), assigns)
	}
	for i, want := range []uint64{0x10, 0x18} {
		fa, ok := assigns[i].Target.(*ir.FieldAccess)
		if !ok || !fa.HasOffset || fa.Offset != want {
			t.Fatalf("stp assignment %d = %#v, want field 0x%x", i, assigns[i].Target, want)
		}
	}
}

func TestLiftFunction_CalleeSavedPairSkipped(t *testing.T) {
	insns := []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "stp", Writeback: true, Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x19"},
			{Type: native.OperandReg, Reg: "x20"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp", Disp: -0x20}},
		}},
		ret(0x4),
	}
	if assigns := collectAssigns(LiftFunction(insns, nil, nil, nil)); len(assigns) != 0 {
		t.Fatalf("callee-saved spill produced assignments: %v", assigns)
	}
}

func TestLiftFunction_PreIndexWriteback(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ldr x0, [x1, #8]!
		{Address: 0x0, Size: 4, Mnemonic: "ldr", Writeback: true, Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x1", Disp: 8}},
		}},
		// mov x0, x1
		{Address: 0x4, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "x1"},
		}},
		ret(0x8),
	}

	val := firstReturn(t, LiftFunction(insns, []string{"p"}, nil, nil)).Value
	sum, ok := val.(*ir.BinaryExpr)
	if !ok || sum.Op != "+" {
		t.Fatalf("pre-index writeback = %#v, want base + 8", val)
	}
	lit, ok := sum.Right.(*ir.IntLit)
	if !ok || lit.Value != 8 {
		t.Fatalf("pre-index writeback offset = %#v, want 8", sum.Right)
	}
}

func TestLiftFunction_PostIndexWriteback(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ldr x0, [x1], #8
		{Address: 0x0, Size: 4, Mnemonic: "ldr", Writeback: true, PostIndex: true, Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x1"}},
			{Type: native.OperandImm, Imm: 8},
		}},
		// mov x0, x1
		{Address: 0x4, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "x1"},
		}},
		ret(0x8),
	}

	val := firstReturn(t, LiftFunction(insns, []string{"p"}, nil, nil)).Value
	sum, ok := val.(*ir.BinaryExpr)
	if !ok || sum.Op != "+" {
		t.Fatalf("post-index writeback = %#v, want base + 8", val)
	}
}

func TestLiftFunction_MaddAndMsub(t *testing.T) {
	insns := []native.DetailedInstruction{
		// madd x0, x1, x2, x3
		{Address: 0x0, Size: 4, Mnemonic: "madd", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "x1"},
			{Type: native.OperandReg, Reg: "x2"},
			{Type: native.OperandReg, Reg: "x3"},
		}},
		ret(0x4),
	}
	val := firstReturn(t, LiftFunction(insns, []string{"a", "b", "c", "d"}, nil, nil)).Value
	sum, ok := val.(*ir.BinaryExpr)
	if !ok || sum.Op != "+" {
		t.Fatalf("madd = %#v, want product + addend", val)
	}
	prod, ok := sum.Left.(*ir.BinaryExpr)
	if !ok || prod.Op != "*" {
		t.Fatalf("madd left = %#v, want product", sum.Left)
	}

	insns[0].Mnemonic = "msub"
	val = firstReturn(t, LiftFunction(insns, []string{"a", "b", "c", "d"}, nil, nil)).Value
	sub, ok := val.(*ir.BinaryExpr)
	if !ok || sub.Op != "-" {
		t.Fatalf("msub = %#v, want product - addend", val)
	}
}

func TestLiftFunction_UDivAndSDiv(t *testing.T) {
	for _, mnemonic := range []string{"udiv", "sdiv"} {
		insns := []native.DetailedInstruction{
			{Address: 0x0, Size: 4, Mnemonic: mnemonic, Operands: []native.Operand{
				{Type: native.OperandReg, Reg: "x0"},
				{Type: native.OperandReg, Reg: "x1"},
				{Type: native.OperandReg, Reg: "x2"},
			}},
			ret(0x4),
		}
		val := firstReturn(t, LiftFunction(insns, []string{"a", "b", "c"}, nil, nil)).Value
		div, ok := val.(*ir.BinaryExpr)
		if !ok || div.Op != "/" {
			t.Fatalf("%s = %#v, want division", mnemonic, val)
		}
	}
}

func TestLiftFunction_Bitfield(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ubfx x0, x1, #4, #8
		{Address: 0x0, Size: 4, Mnemonic: "ubfx", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "x1"},
			{Type: native.OperandImm, Imm: 4},
			{Type: native.OperandImm, Imm: 8},
		}},
		ret(0x4),
	}
	val := firstReturn(t, LiftFunction(insns, []string{"a", "b"}, nil, nil)).Value
	mask, ok := val.(*ir.BinaryExpr)
	if !ok || mask.Op != "&" {
		t.Fatalf("ubfx = %#v, want masked field", val)
	}
	shift, ok := mask.Left.(*ir.BinaryExpr)
	if !ok || shift.Op != ">>" {
		t.Fatalf("ubfx left = %#v, want right shift", mask.Left)
	}

	insns[0].Mnemonic = "sbfx"
	val = firstReturn(t, LiftFunction(insns, []string{"a", "b"}, nil, nil)).Value
	ashr, ok := val.(*ir.BinaryExpr)
	if !ok || ashr.Op != ">>" {
		t.Fatalf("sbfx = %#v, want arithmetic right shift", val)
	}
	if _, ok := ashr.Left.(*ir.CastExpr); !ok {
		t.Fatalf("sbfx left = %T, want signed cast before shift", ashr.Left)
	}
}

func TestLiftFunction_SignExtend(t *testing.T) {
	insns := []native.DetailedInstruction{
		// sxtw x0, w1
		{Address: 0x0, Size: 4, Mnemonic: "sxtw", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "w1"},
		}},
		ret(0x4),
	}
	val := rawFirstReturn(t, LiftFunction(insns, []string{"a", "b"}, nil, nil)).Value
	cast, ok := val.(*ir.CastExpr)
	if !ok {
		t.Fatalf("sxtw = %T, want *ir.CastExpr", val)
	}
	pt, ok := cast.Type.(*ir.PrimitiveType)
	if !ok || pt.Name != "int" {
		t.Fatalf("sxtw cast type = %#v, want int", cast.Type)
	}

	insns[0].Mnemonic = "uxtw"
	val = rawFirstReturn(t, LiftFunction(insns, []string{"a", "b"}, nil, nil)).Value
	cast, ok = val.(*ir.CastExpr)
	if !ok {
		t.Fatalf("uxtw = %T, want *ir.CastExpr", val)
	}
	pt, ok = cast.Type.(*ir.PrimitiveType)
	if !ok || pt.Name != "uint" {
		t.Fatalf("uxtw cast type = %#v, want uint", cast.Type)
	}
}

func TestLiftFunction_SignedLoads(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ldrsb w0, [x0, #4]
		{Address: 0x0, Size: 4, Mnemonic: "ldrsb", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0", Disp: 4}},
		}},
		ret(0x4),
	}
	val := firstReturn(t, LiftFunction(insns, []string{"p"}, nil, nil)).Value
	cast, ok := val.(*ir.CastExpr)
	if !ok {
		t.Fatalf("ldrsb = %T, want *ir.CastExpr", val)
	}
	pt, ok := cast.Type.(*ir.PrimitiveType)
	if !ok || pt.Name != "sbyte" {
		t.Fatalf("ldrsb cast type = %#v, want sbyte", cast.Type)
	}
	fa, ok := cast.Expr.(*ir.FieldAccess)
	if !ok || fa.Width != 1 {
		t.Fatalf("ldrsb inner = %#v, want 1-byte field access", cast.Expr)
	}
}

func TestLiftFunction_LdarStlrAndExclusive(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ldar x0, [x1]
		{Address: 0x0, Size: 4, Mnemonic: "ldar", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x1"}},
		}},
		ret(0x4),
	}
	val := firstReturn(t, LiftFunction(insns, []string{"p"}, nil, nil)).Value
	if _, ok := val.(*ir.FieldAccess); !ok {
		t.Fatalf("ldar = %T, want *ir.FieldAccess", val)
	}

	insns = []native.DetailedInstruction{
		// stlr x0, [x1]
		{Address: 0x0, Size: 4, Mnemonic: "stlr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x1"}},
		}},
		ret(0x4),
	}
	if assigns := collectAssigns(LiftFunction(insns, []string{"v", "p"}, nil, nil)); len(assigns) != 1 {
		t.Fatalf("stlr produced %d assignments, want 1", len(assigns))
	}

	insns = []native.DetailedInstruction{
		// stxr w2, x1, [x0]
		{Address: 0x0, Size: 4, Mnemonic: "stxr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "x1"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0"}},
		}},
		ret(0x4),
	}
	assigns := collectAssigns(LiftFunction(insns, []string{"p", "v"}, nil, nil))
	if len(assigns) != 2 {
		t.Fatalf("stxr produced %d assignments, want 2 (status + store)", len(assigns))
	}
}

func TestLiftFunction_RealSxtwIndexedLoad(t *testing.T) {
	d, err := native.NewDisassembler(native.ArchARM64, native.ModeARM64|native.ModeLITTLE_ENDIAN)
	if err != nil {
		t.Fatalf("NewDisassembler: %v", err)
	}
	defer d.Close()

	// ldr w26, [x6, w23, sxtw #2]
	decoded, err := d.DisassembleDetailed([]byte{0xda, 0xd8, 0x77, 0xb8}, 0x1000)
	if err != nil || len(decoded) != 1 {
		t.Fatalf("DisassembleDetailed: %v (got %d instructions)", err, len(decoded))
	}
	if len(decoded[0].Operands) < 2 || decoded[0].Operands[1].Type != native.OperandMem {
		t.Fatalf("decoded operands = %+v, want a memory operand", decoded[0].Operands)
	}
	mem := decoded[0].Operands[1].Mem
	if mem.Index != "w23" || mem.IndexExtType != 7 || mem.IndexShiftValue != 2 {
		t.Fatalf("mem = %+v, want index w23, sxtw, shift 2", mem)
	}

	insns := append(decoded,
		native.DetailedInstruction{Address: 0x1004, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "x26"},
		}},
		ret(0x1008),
	)
	val := firstReturn(t, LiftFunction(insns, nil, nil, nil)).Value
	arr, ok := val.(*ir.ArrayAccess)
	if !ok {
		t.Fatalf("real sxtw load = %T, want *ir.ArrayAccess", val)
	}
	if arr.Width != 4 {
		t.Fatalf("real sxtw array width = %d, want 4", arr.Width)
	}
	if _, ok := arr.Index.(*ir.CastExpr); !ok {
		t.Fatalf("real sxtw index = %T, want signed cast", arr.Index)
	}
}

func TestLiftFunction_IndexExtend(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ldr w0, [x0, x1, sxtw #2]
		{Address: 0x0, Size: 4, Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{
				Base: "x0", Index: "x1", IndexShiftType: 1, IndexShiftValue: 2, IndexExtType: 7,
			}},
		}},
		ret(0x4),
	}
	val := firstReturn(t, LiftFunction(insns, []string{"arr", "i"}, nil, nil)).Value
	arr, ok := val.(*ir.ArrayAccess)
	if !ok {
		t.Fatalf("indexed sxtw load = %T, want *ir.ArrayAccess", val)
	}
	cast, ok := arr.Index.(*ir.CastExpr)
	if !ok {
		t.Fatalf("index = %T, want signed cast", arr.Index)
	}
	pt, ok := cast.Type.(*ir.PrimitiveType)
	if !ok || pt.Name != "int" {
		t.Fatalf("index cast = %#v, want int", cast.Type)
	}
}
