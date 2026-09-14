package arm64lift

import (
	"testing"

	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/native"
)

// TestAnalyzeCFG_PartialPostdomSeesEarlyReturnMerge locks in the
// partial-post-dominator analysis: standard post-dominance finds no
// merge for a split whose one arm can return early (every path shares
// only the function exit), but the terminating-path-ignoring analysis
// must still identify the continuation both non-terminating paths
// reconverge on.
func TestAnalyzeCFG_PartialPostdomSeesEarlyReturnMerge(t *testing.T) {
	// b -- t -- r_t (return)
	// |    `--- m -- r_m (return)
	// `-- e ----- m
	blocks := []*BasicBlock{
		{StartAddr: 0x0, Succs: []uint64{0x4, 0x10}},
		{StartAddr: 0x4, Succs: []uint64{0x8, 0x14}},
		{StartAddr: 0x8, Succs: nil},
		{StartAddr: 0x10, Succs: []uint64{0x14}},
		{StartAddr: 0x14, Succs: []uint64{0x18}},
		{StartAddr: 0x18, Succs: nil},
	}
	a := analyzeCFG(blocks)
	if got := a.ipdom[0x0]; got != 0 {
		t.Fatalf("standard ipdom[b] = %#x, want none (one arm returns early)", got)
	}
	if got := a.partialIPDom[0x0]; got != 0x14 {
		t.Errorf("partialIPDom[b] = %#x, want 0x14 (the shared continuation)", got)
	}
	if got := a.partialIPDom[0x4]; got != 0x14 {
		t.Errorf("partialIPDom[t] = %#x, want 0x14", got)
	}
	if got := a.partialIPDom[0x10]; got != 0x14 {
		t.Errorf("partialIPDom[e] = %#x, want 0x14", got)
	}
}

// TestLiftFunction_EarlyReturnArmStillSharesMerge lifts a hand-built
// instruction stream equivalent to:
//
//	void f(int a, int b) {
//	    if (a) {          // cbz w0 -> e
//	        if (b) { return; }   // early return arm
//	        goto merge;
//	    }
//	    e: goto merge;
//	    merge: c();
//	    return c();
//	}
//
// The early return on one of the inner arms means standard
// post-dominance cannot see the shared continuation, so before the
// partial analysis was fixed the whole continuation was duplicated into
// both arms. It must be lifted exactly once under a label instead.
func TestLiftFunction_EarlyReturnArmStillSharesMerge(t *testing.T) {
	insns := []native.DetailedInstruction{
		// @0x0: cbz w0, e(0x10) - branch taken = else arm
		{Address: 0x0, Size: 4, Mnemonic: "cbz", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 0x10},
		}},
		// @0x4: cbz w1, r_t(0xc) - branch taken = early-return arm,
		// fallthrough @0x8 continues to the merge
		{Address: 0x4, Size: 4, Mnemonic: "cbz", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandImm, Imm: 0xc},
		}},
		// @0x8: b merge(0x14)
		{Address: 0x8, Size: 4, Mnemonic: "b", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x14},
		}},
		// @0xc: ret  (r_t, terminal - the early return)
		{Address: 0xc, Size: 4, Mnemonic: "ret"},
		// @0x10: b merge(0x14)  (e)
		{Address: 0x10, Size: 4, Mnemonic: "b", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x14},
		}},
		// @0x14: bl c(0x108)  (merge)
		{Address: 0x14, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x108},
		}},
		// @0x18: ret
		{Address: 0x18, Size: 4, Mnemonic: "ret"},
	}

	resolver := func(addr uint64) (string, bool) {
		if addr == 0x108 {
			return "c", true
		}
		return "", false
	}

	stmts := LiftFunction(insns, []string{"a", "b"}, resolver, nil)
	if len(stmts) != 3 {
		t.Fatalf("expected 3 top-level statements (if/else, merge label, shared continuation), got %d: %v", len(stmts), stmts)
	}
	ifStmt, ok := stmts[0].(*ir.IfStmt)
	if !ok {
		t.Fatalf("expected the first statement to be an IfStmt, got %T: %v", stmts[0], stmts[0])
	}
	label, ok := stmts[1].(*ir.LabelStmt)
	if !ok {
		t.Fatalf("expected the second statement to be the merge LabelStmt, got %T: %v", stmts[1], stmts[1])
	}

	// Then (branch-taken, 0x10) is the goto-only arm.
	thenGoto, ok := ifStmt.Then.Statements[0].(*ir.GotoStmt)
	if !ok || thenGoto.Label != label.Name {
		t.Fatalf("expected the then arm to be a single goto %q, got %v", label.Name, ifStmt.Then.Statements)
	}

	// Else (0x4) is the nested split whose else arm reaches the merge.
	inner, ok := ifStmt.Else.Statements[0].(*ir.IfStmt)
	if !ok {
		t.Fatalf("expected the else arm to hold the nested IfStmt, got %v", ifStmt.Else.Statements)
	}
	if _, ok := inner.Then.Statements[0].(*ir.ReturnStmt); !ok {
		t.Errorf("expected the inner then arm to be the early return, got %v", inner.Then.Statements)
	}
	innerGoto, ok := inner.Else.Statements[0].(*ir.GotoStmt)
	if !ok || innerGoto.Label != label.Name {
		t.Errorf("expected the inner else arm to jump to %q, got %v", label.Name, inner.Else.Statements)
	}

	// The shared continuation (c()) is lifted exactly once, after the label.
	ret, ok := stmts[2].(*ir.ReturnStmt)
	if !ok {
		t.Fatalf("expected the continuation to end in the function's ReturnStmt, got %T: %v", stmts[2], stmts[2])
	}
	if call, ok := ret.Value.(*ir.StaticMethodCall); !ok || call.Method != "c" {
		t.Errorf("expected the return value to be the shared c() call, got %#v", ret.Value)
	}
}
