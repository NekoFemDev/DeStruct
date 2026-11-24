package arm64lift

import (
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/native"
)

// Sprint 3 tests: x29-relative stack slots, remaining integer
// instructions, and the FP/SIMD subset.

type fakeDebugInfo map[int64]struct {
	name string
	typ  string
}

func (f fakeDebugInfo) LocalAt(off int64) (string, string, bool) {
	v, ok := f[off]
	return v.name, v.typ, ok
}

func TestLiftFunction_FPReturnType(t *testing.T) {
	insns := []native.DetailedInstruction{
		// fadd d0, d1, d2
		{Address: 0x0, Size: 4, Mnemonic: "fadd", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "d0"},
			{Type: native.OperandReg, Reg: "d1"},
			{Type: native.OperandReg, Reg: "d2"},
		}},
		ret(0x4),
	}
	val := firstReturn(t, LiftFunctionWithOptions(insns, nil, nil, nil, nil, LiftOptions{ReturnType: "double"})).Value
	if _, ok := val.(*ir.BinaryExpr); !ok {
		t.Fatalf("typed FP return = %#v, want the double expression itself", val)
	}

	var b strings.Builder
	RenderCFunctionWithOptions(&b, "avg", []ir.Stmt{&ir.ReturnStmt{Value: &ir.DoubleLit{Value: 1.0}}}, CRenderOptions{ReturnType: "double"})
	if !strings.Contains(b.String(), "double avg(") {
		t.Fatalf("return-type signature not rendered:\n%s", b.String())
	}
}

func TestRenderCFunction_DWARFSignature(t *testing.T) {
	stmts := []ir.Stmt{&ir.ReturnStmt{Value: &ir.LocalVar{Name: "a"}}}
	var b strings.Builder
	RenderCFunctionWithOptions(&b, "add", stmts, CRenderOptions{
		ParamNames: []string{"a", "b"},
		ParamTypes: []string{"int32_t", "uint64_t"},
	})
	out := b.String()
	if !strings.Contains(out, "int32_t a, uint64_t b") {
		t.Fatalf("DWARF parameter signature not rendered:\n%s", out)
	}
	if strings.Contains(out, "uint64_t x0") {
		t.Fatalf("generic x0 signature was not replaced:\n%s", out)
	}
}

func TestLiftFunction_CasAndSimdAccess(t *testing.T) {
	// cas w0, w1, [x2]
	insns := []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "cas", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x2"}},
		}},
		ret(0x4),
	}
	stmts := LiftFunction(insns, []string{"expected", "desired", "p"}, nil, nil)
	var ifStmt *ir.IfStmt
	for _, s := range stmts {
		if v, ok := s.(*ir.IfStmt); ok {
			ifStmt = v
		}
	}
	if ifStmt == nil {
		t.Fatalf("cas produced no conditional: %v", stmts)
	}
	if cmp, ok := ifStmt.Cond.(*ir.BinaryExpr); !ok || cmp.Op != "==" {
		t.Fatalf("cas condition = %#v, want == comparison", ifStmt.Cond)
	}

	// ld1 {v0.16b}, [x0]
	insns = []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "ld1", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "q0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0"}},
		}},
		{Address: 0x4, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "q0"},
		}},
		ret(0x8),
	}
	val := firstReturn(t, LiftFunction(insns, []string{"p"}, nil, nil)).Value
	fa, ok := val.(*ir.FieldAccess)
	if !ok || fa.Width != 16 {
		t.Fatalf("ld1 = %#v, want a 16-byte field access", val)
	}
}

func TestLiftFunction_StackWidthTypeInference(t *testing.T) {
	opts := LiftOptions{LocalTypes: make(map[string]string)}
	insns := []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandImm, Imm: 7},
		}},
		{Address: 0x4, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp", Disp: 8}},
		}},
		{Address: 0x8, Size: 4, Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp", Disp: 8}},
		}},
		ret(0xc),
	}
	stmts := LiftFunctionWithOptions(insns, nil, nil, nil, nil, opts)
	var b strings.Builder
	RenderCFunctionWithOptions(&b, "test_fn", stmts, CRenderOptions{LocalTypes: opts.LocalTypes})
	out := b.String()
	if !strings.Contains(out, "int32_t local_8 = 0;") {
		t.Fatalf("width-based local type inference did not produce int32_t local_8:\n%s", out)
	}
}

func TestLiftFunction_DWARFLocalNameAndType(t *testing.T) {
	opts := LiftOptions{
		LocalTypes: make(map[string]string),
		Debug: fakeDebugInfo{
			4: {name: "counter", typ: "int32_t"},
		},
	}
	insns := []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x29"},
			{Type: native.OperandReg, Reg: "sp"},
		}},
		{Address: 0x4, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandImm, Imm: 7},
		}},
		{Address: 0x8, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x29", Disp: 4}},
		}},
		{Address: 0xc, Size: 4, Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x29", Disp: 4}},
		}},
		ret(0x10),
	}
	stmts := LiftFunctionWithOptions(insns, []string{"v"}, nil, nil, nil, opts)

	var b strings.Builder
	RenderCFunctionWithOptions(&b, "test_fn", stmts, CRenderOptions{LocalTypes: opts.LocalTypes})
	out := b.String()
	if !strings.Contains(out, "int32_t counter = 0;") {
		t.Fatalf("DWARF local type not used in declarations:\n%s", out)
	}
	if !strings.Contains(out, "counter =") || !strings.Contains(out, "return (uint32_t)counter;") {
		t.Fatalf("DWARF local name not used in the body:\n%s", out)
	}
}

func TestLiftFunction_X29StackSlot(t *testing.T) {
	insns := []native.DetailedInstruction{
		// mov x29, sp
		{Address: 0x0, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x29"},
			{Type: native.OperandReg, Reg: "sp"},
		}},
		// str w0, [x29, #-8]
		{Address: 0x4, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x29", Disp: -8}},
		}},
		// ldr w0, [x29, #-8]
		{Address: 0x8, Size: 4, Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x29", Disp: -8}},
		}},
		ret(0xc),
	}

	stmts := LiftFunction(insns, []string{"v"}, nil, nil)
	val := firstReturn(t, stmts).Value
	if _, ok := val.(*ir.FieldAccess); ok {
		t.Fatalf("x29 slot rendered as a field access: %#v", val)
	}
	out := renderCFunctionToString(stmts)
	if strings.Contains(out, "uintptr_t)x29") {
		t.Fatalf("x29 stack slot still rendered as a raw dereference:\n%s", out)
	}
	if !strings.Contains(out, "return v;") {
		t.Fatalf("x29 stack slot did not resolve back to the parameter name:\n%s", out)
	}
}

func TestLiftFunction_CmnNegBics(t *testing.T) {
	insns := []native.DetailedInstruction{
		// cmn w0, w1
		{Address: 0x0, Size: 4, Mnemonic: "cmn", WritesFlags: true, Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w1"},
		}},
		// cset w0, eq
		{Address: 0x4, Size: 4, Mnemonic: "cset", OpStr: "w0, eq", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
		}},
		ret(0x8),
	}
	val := firstReturn(t, LiftFunction(insns, []string{"a", "b"}, nil, nil)).Value
	cmp, ok := val.(*ir.BinaryExpr)
	if !ok || cmp.Op != "==" {
		t.Fatalf("cmn condition = %#v, want == comparison", val)
	}
	if add, ok := cmp.Left.(*ir.BinaryExpr); !ok || add.Op != "+" {
		t.Fatalf("cmn left = %#v, want a+b", cmp.Left)
	}

	insns = []native.DetailedInstruction{
		// bics w0, w1, w2
		{Address: 0x0, Size: 4, Mnemonic: "bics", WritesFlags: true, Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandReg, Reg: "w2"},
		}},
		ret(0x4),
	}
	val = firstReturn(t, LiftFunction(insns, []string{"a", "b", "c"}, nil, nil)).Value
	and, ok := val.(*ir.BinaryExpr)
	if !ok || and.Op != "&" {
		t.Fatalf("bics = %#v, want bit clear", val)
	}
	if _, ok := and.Right.(*ir.UnaryExpr); !ok {
		t.Fatalf("bics right = %#v, want ~rhs", and.Right)
	}
}

func TestLiftFunction_NegAndNegs(t *testing.T) {
	insns := []native.DetailedInstruction{
		// neg w0, w1
		{Address: 0x0, Size: 4, Mnemonic: "neg", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w1"},
		}},
		ret(0x4),
	}
	val := firstReturn(t, LiftFunction(insns, []string{"a", "b"}, nil, nil)).Value
	sub, ok := val.(*ir.BinaryExpr)
	if !ok || sub.Op != "-" {
		t.Fatalf("neg = %#v, want 0 - b", val)
	}
}

func TestLiftFunction_ExtrUbfizMneg(t *testing.T) {
	// extr x0, x1, x2, #8
	insns := []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "extr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "x1"},
			{Type: native.OperandReg, Reg: "x2"},
			{Type: native.OperandImm, Imm: 8},
		}},
		ret(0x4),
	}
	val := firstReturn(t, LiftFunction(insns, []string{"a", "b", "c"}, nil, nil)).Value
	or, ok := val.(*ir.BinaryExpr)
	if !ok || or.Op != "|" {
		t.Fatalf("extr = %#v, want low | high", val)
	}

	// ubfiz x0, x1, #4, #8
	insns[0] = native.DetailedInstruction{Address: 0x0, Size: 4, Mnemonic: "ubfiz", Operands: []native.Operand{
		{Type: native.OperandReg, Reg: "x0"},
		{Type: native.OperandReg, Reg: "x1"},
		{Type: native.OperandImm, Imm: 4},
		{Type: native.OperandImm, Imm: 8},
	}}
	val = firstReturn(t, LiftFunction(insns, []string{"a", "b"}, nil, nil)).Value
	shl, ok := val.(*ir.BinaryExpr)
	if !ok || shl.Op != "<<" {
		t.Fatalf("ubfiz = %#v, want masked field << 4", val)
	}

	// mneg x0, x1, x2
	insns[0] = native.DetailedInstruction{Address: 0x0, Size: 4, Mnemonic: "mneg", Operands: []native.Operand{
		{Type: native.OperandReg, Reg: "x0"},
		{Type: native.OperandReg, Reg: "x1"},
		{Type: native.OperandReg, Reg: "x2"},
	}}
	val = firstReturn(t, LiftFunction(insns, []string{"a", "b", "c"}, nil, nil)).Value
	neg, ok := val.(*ir.UnaryExpr)
	if !ok || neg.Op != "-" {
		t.Fatalf("mneg = %#v, want -(b*c)", val)
	}
}

func TestLiftFunction_FPArithmetic(t *testing.T) {
	insns := []native.DetailedInstruction{
		// fadd d0, d1, d2
		{Address: 0x0, Size: 4, Mnemonic: "fadd", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "d0"},
			{Type: native.OperandReg, Reg: "d1"},
			{Type: native.OperandReg, Reg: "d2"},
		}},
		// fmov x0, d0
		{Address: 0x4, Size: 4, Mnemonic: "fmov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "d0"},
		}},
		ret(0x8),
	}
	val := firstReturn(t, LiftFunction(insns, nil, nil, nil)).Value
	call, ok := val.(*ir.StaticMethodCall)
	if !ok || call.Method != "DS_BITCAST_U64" {
		t.Fatalf("fmov bitcast = %#v, want DS_BITCAST_U64(...)", val)
	}
	add, ok := call.Args[0].(*ir.BinaryExpr)
	if !ok || add.Op != "+" {
		t.Fatalf("fadd result = %#v, want floating-point addition", call.Args[0])
	}

	insns[0].Mnemonic = "fmul"
	val = firstReturn(t, LiftFunction(insns, nil, nil, nil)).Value
	call = val.(*ir.StaticMethodCall)
	mul, ok := call.Args[0].(*ir.BinaryExpr)
	if !ok || mul.Op != "*" {
		t.Fatalf("fmul result = %#v, want multiplication", call.Args[0])
	}
}

func TestLiftFunction_FPReturn(t *testing.T) {
	insns := []native.DetailedInstruction{
		// fadd d0, d1, d2
		{Address: 0x0, Size: 4, Mnemonic: "fadd", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "d0"},
			{Type: native.OperandReg, Reg: "d1"},
			{Type: native.OperandReg, Reg: "d2"},
		}},
		ret(0x4),
	}
	val := firstReturn(t, LiftFunction(insns, nil, nil, nil)).Value
	call, ok := val.(*ir.StaticMethodCall)
	if !ok || call.Method != "DS_BITCAST_U64" {
		t.Fatalf("FP return = %#v, want DS_BITCAST_U64(d0)", val)
	}
}

func TestLiftFunction_FcmpFcsel(t *testing.T) {
	insns := []native.DetailedInstruction{
		// fcmp d0, d1
		{Address: 0x0, Size: 4, Mnemonic: "fcmp", WritesFlags: true, Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "d0"},
			{Type: native.OperandReg, Reg: "d1"},
		}},
		// fcsel d0, d2, d3, eq
		{Address: 0x4, Size: 4, Mnemonic: "fcsel", OpStr: "d0, d2, d3, eq", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "d0"},
			{Type: native.OperandReg, Reg: "d2"},
			{Type: native.OperandReg, Reg: "d3"},
		}},
		// fmov x0, d0
		{Address: 0x8, Size: 4, Mnemonic: "fmov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "d0"},
		}},
		ret(0xc),
	}
	val := firstReturn(t, LiftFunction(insns, nil, nil, nil)).Value
	call, ok := val.(*ir.StaticMethodCall)
	if !ok {
		t.Fatalf("fcsel result = %T, want bitcast", val)
	}
	tern, ok := call.Args[0].(*ir.TernaryExpr)
	if !ok {
		t.Fatalf("fcsel inner = %T, want ternary", call.Args[0])
	}
	cmp, ok := tern.Cond.(*ir.BinaryExpr)
	if !ok || cmp.Op != "==" {
		t.Fatalf("fcsel condition = %#v, want FP equality", tern.Cond)
	}
}

func TestLiftFunction_FPConvertAndLoad(t *testing.T) {
	insns := []native.DetailedInstruction{
		// scvtf d0, x1
		{Address: 0x0, Size: 4, Mnemonic: "scvtf", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "d0"},
			{Type: native.OperandReg, Reg: "x1"},
		}},
		// fmov x0, d0
		{Address: 0x4, Size: 4, Mnemonic: "fmov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "d0"},
		}},
		ret(0x8),
	}
	val := firstReturn(t, LiftFunction(insns, nil, nil, nil)).Value
	call := val.(*ir.StaticMethodCall)
	if _, ok := call.Args[0].(*ir.CastExpr); !ok {
		t.Fatalf("scvtf = %#v, want cast to double", call.Args[0])
	}

	// ldr d0, [x0, #8]
	insns = []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "d0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0", Disp: 8}},
		}},
		{Address: 0x4, Size: 4, Mnemonic: "fmov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandReg, Reg: "d0"},
		}},
		ret(0x8),
	}
	val = firstReturn(t, LiftFunction(insns, []string{"p"}, nil, nil)).Value
	call = val.(*ir.StaticMethodCall)
	fa, ok := call.Args[0].(*ir.FieldAccess)
	if !ok || fa.CType != "double" {
		t.Fatalf("ldr d0 = %#v, want double field access", call.Args[0])
	}
}

func TestLiftFunction_ByteAtomics(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ldxrb w0, [x1]
		{Address: 0x0, Size: 4, Mnemonic: "ldxrb", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x1"}},
		}},
		ret(0x4),
	}
	val := firstReturn(t, LiftFunction(insns, []string{"p"}, nil, nil)).Value
	if fa, ok := val.(*ir.FieldAccess); !ok || fa.Width != 1 {
		t.Fatalf("ldxrb = %#v, want 1-byte field access", val)
	}

	insns = []native.DetailedInstruction{
		// stxrb w2, w1, [x0]
		{Address: 0x0, Size: 4, Mnemonic: "stxrb", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0"}},
		}},
		ret(0x4),
	}
	assigns := collectAssigns(LiftFunction(insns, []string{"p", "v"}, nil, nil))
	if len(assigns) != 2 {
		t.Fatalf("stxrb produced %d assignments, want 2", len(assigns))
	}
	if fa, ok := assigns[1].Target.(*ir.FieldAccess); !ok || fa.Width != 1 {
		t.Fatalf("stxrb store = %#v, want 1-byte field access", assigns[1].Target)
	}
}
