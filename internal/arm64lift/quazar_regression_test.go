package arm64lift

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/native"
)

// disassembleWords assembles a small hand-encoded instruction sequence.
func disassembleWords(t *testing.T, addr uint64, words []uint32) []native.DetailedInstruction {
	t.Helper()
	d, err := native.NewARM64Disassembler()
	if err != nil {
		t.Skipf("arm64 disassembler unavailable: %v", err)
	}
	defer d.Close()

	code := make([]byte, len(words)*4)
	for i, w := range words {
		binary.LittleEndian.PutUint32(code[i*4:], w)
	}
	insns, err := d.DisassembleDetailed(code, addr)
	if err != nil {
		t.Fatalf("DisassembleDetailed: %v", err)
	}
	return insns
}

func renderForTest(stmts []ir.Stmt) string {
	var buf bytes.Buffer
	RenderCFunction(&buf, "test_fn", stmts)
	return buf.String()
}

// TestTailThunkWithoutUnwindEntry reproduces a real quazar_arm64 thunk:
// bti; add x0, x0, #0x10; b 0x9442bc, where the branch target has no
// .eh_frame entry. The target must still become a call, and untouched
// argument registers must be forwarded rather than zero-padded.
func TestTailThunkWithoutUnwindEntry(t *testing.T) {
	insns := disassembleWords(t, 0x9414b0, []uint32{
		0xd503245f, // bti c
		0x91004000, // add x0, x0, #0x10
		0x14000b81, // b 0x9442bc
	})
	opts := LiftOptions{CodeContains: func(uint64) bool { return true }}
	stmts := LiftFunctionWithOptions(insns, nil, nil, nil, nil, opts)
	if len(stmts) == 0 {
		t.Fatal("tail-call thunk produced no statements")
	}

	ret, ok := stmts[len(stmts)-1].(*ir.ReturnStmt)
	if !ok {
		t.Fatalf("last statement is %T, want *ir.ReturnStmt", stmts[len(stmts)-1])
	}
	call, ok := ret.Value.(*ir.StaticMethodCall)
	if !ok {
		t.Fatalf("tail return value is %T, want *ir.StaticMethodCall", ret.Value)
	}
	if len(call.Args) != 8 {
		t.Fatalf("tail call has %d args, want 8", len(call.Args))
	}
	for i := 1; i < 8; i++ {
		lv, ok := call.Args[i].(*ir.LocalVar)
		want := fmt.Sprintf("x%d", i)
		if !ok || lv.Name != want {
			t.Fatalf("arg %d = %#v, want LocalVar %s", i, call.Args[i], want)
		}
	}

	out := renderForTest(stmts)
	want := "func_9442bc(x0 + 16, x1, x2, x3, x4, x5, x6, x7);"
	if !strings.Contains(out, want) {
		t.Fatalf("expected %q in:\n%s", want, out)
	}
}

// TestRetWithoutExplicitX0 checks that a bare "ret" forwards the incoming
// x0 argument instead of reading an uninitialized w0 placeholder.
// TestCcmnCondition covers the conditional-compare-negative form used by
// optimized bounds checks: "cmp; ccmn; csel" must produce a real combined
// condition, not a cond placeholder.
func TestCcmnCondition(t *testing.T) {
	insns := []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "cmp", OpStr: "w0, w1", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w1"},
		}},
		{Address: 0x4, Size: 4, Mnemonic: "ccmn", OpStr: "w0, #1, #4, lt", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 1},
			{Type: native.OperandImm, Imm: 4},
		}},
		{Address: 0x8, Size: 4, Mnemonic: "csel", OpStr: "w0, w3, w4, ne", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w3"},
			{Type: native.OperandReg, Reg: "w4"},
		}},
		{Address: 0xc, Size: 4, Mnemonic: "ret"},
	}
	stmts := LiftFunction(insns, nil, nil, nil)
	var ternary *ir.TernaryExpr
	var walk func([]ir.Stmt)
	walk = func(list []ir.Stmt) {
		for _, s := range list {
			switch v := s.(type) {
			case *ir.AssignStmt:
				if tv, ok := v.Value.(*ir.TernaryExpr); ok {
					ternary = tv
				}
			case *ir.ReturnStmt:
				if tv, ok := v.Value.(*ir.TernaryExpr); ok {
					ternary = tv
				}
			}
		}
	}
	walk(stmts)
	if ternary == nil {
		t.Fatalf("no ternary select lifted: %v", stmts)
	}
	if lv, ok := ternary.Cond.(*ir.LocalVar); ok && lv.Name == "cond" {
		t.Fatalf("ccmn condition remained unresolved: %s", ternary.Cond)
	}
}

// TestInlineStraightLineOutlinedCall covers a "bl" to a local label inside
// the same function. The target must be inlined with the caller's live
// register state instead of turning into a func_<addr> stub.
func TestInlineStraightLineOutlinedCall(t *testing.T) {
	insns := disassembleWords(t, 0x3000, []uint32{
		0x94000004, // bl 0x3010
		0x91000400, // add x0, x0, #1
		0xd65f03c0, // ret
		0xd503201f, // nop
		0x91001400, // add x0, x0, #5
		0xd65f03c0, // ret
	})
	stmts := LiftFunctionWithOptions(insns, nil, nil, nil, nil, LiftOptions{})
	out := renderForTest(stmts)
	if strings.Contains(out, "func_") {
		t.Fatalf("local outlined call was not inlined:\n%s", out)
	}
	if !strings.Contains(out, "x0 + 5") {
		t.Fatalf("expected the inlined block's add in:\n%s", out)
	}
}

func TestRetWithoutExplicitX0(t *testing.T) {
	insns := disassembleWords(t, 0x2000, []uint32{0xd65f03c0}) // ret
	stmts := LiftFunctionWithOptions(insns, nil, nil, nil, nil, LiftOptions{})
	if len(stmts) != 1 {
		t.Fatalf("got %d statements, want 1: %v", len(stmts), stmts)
	}
	ret, ok := stmts[0].(*ir.ReturnStmt)
	if !ok {
		t.Fatalf("statement is %T, want *ir.ReturnStmt", stmts[0])
	}
	lv, ok := ret.Value.(*ir.LocalVar)
	if !ok || lv.Name != "x0" {
		t.Fatalf("return value is %#v, want LocalVar x0", ret.Value)
	}
}

// TestFPStackSlotAliasing checks that integer and FP views of one stack
// slot share storage. A store of d0 followed by integer and double loads
// must produce one local_16 plus bitcasts, not separate local_16 /
// dlocal_16 variables whose aliasing is lost.
func TestFPStackSlotAliasing(t *testing.T) {
	insns := disassembleWords(t, 0x1000, []uint32{
		0xfd000be0, // str d0, [sp, #16]
		0xf9400be0, // ldr x0, [sp, #16]
		0xfd400be1, // ldr d1, [sp, #16]
		0x9e660020, // fmov x0, d1
		0xd65f03c0, // ret
	})
	stmts := LiftFunctionWithOptions(insns, nil, nil, nil, nil, LiftOptions{})
	out := renderForTest(stmts)

	if strings.Contains(out, "dlocal_16") || strings.Contains(out, "flocal_16") {
		t.Fatalf("FP stack slot was split into a second variable:\n%s", out)
	}
	if !strings.Contains(out, "ENI_BITCAST_U64(d0)") {
		t.Fatalf("missing FP-to-integer bitcast:\n%s", out)
	}
	if !strings.Contains(out, "ENI_BITCAST_F64(local_16)") {
		t.Fatalf("missing integer-to-FP bitcast:\n%s", out)
	}
}
