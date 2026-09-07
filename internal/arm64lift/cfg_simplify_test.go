package arm64lift

import (
	"testing"

	"github.com/destruct/destruct/internal/native"
)

// makeBranch is a helper for building branch instructions in tests.
func makeBranch(addr uint64, mnemonic string, target uint64) native.DetailedInstruction {
	return native.DetailedInstruction{
		Address:  addr,
		Size:     4,
		Mnemonic: mnemonic,
		Operands: []native.Operand{
			{Type: native.OperandImm, Imm: int64(target)},
		},
	}
}

func TestSimplifyCFG_UnreachableBlockRemoved(t *testing.T) {
	insns := []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 1},
		}},
		makeBranch(0x4, "b", 0xc),
		// 0x8 is unreachable
		{Address: 0x8, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 2},
		}},
		// 0xc reachable
		{Address: 0xc, Size: 4, Mnemonic: "ret"},
	}

	blocks := simplifyCFG(buildCFG(insns))
	// After removing 0x8, the remaining two blocks form a linear chain and are merged.
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block after removing unreachable + merging, got %d", len(blocks))
	}
	if blocks[0].StartAddr != 0x0 {
		t.Fatalf("expected merged block at 0x0, got 0x%x", blocks[0].StartAddr)
	}
	// The redundant unconditional branch to 0xc should have been dropped.
	if len(blocks[0].Instructions) != 2 {
		t.Fatalf("expected 2 instructions (mov + ret), got %d", len(blocks[0].Instructions))
	}
}

func TestSimplifyCFG_LinearChainMerged(t *testing.T) {
	insns := []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 1},
		}},
		// redundant unconditional branch to the next block
		makeBranch(0x4, "b", 0x8),
		{Address: 0x8, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandImm, Imm: 2},
		}},
		{Address: 0xc, Size: 4, Mnemonic: "ret"},
	}

	blocks := simplifyCFG(buildCFG(insns))
	if len(blocks) != 1 {
		t.Fatalf("expected 1 merged block, got %d", len(blocks))
	}
	if len(blocks[0].Instructions) != 3 {
		t.Fatalf("expected 3 instructions after dropping redundant branch, got %d", len(blocks[0].Instructions))
	}
	if blocks[0].Instructions[0].Address != 0x0 || blocks[0].Instructions[1].Address != 0x8 {
		t.Fatalf("unexpected merged instructions: %v", blocks[0].Instructions)
	}
}

func TestSimplifyCFG_DoesNotDestroyLoop(t *testing.T) {
	// while (a < n) { step(); }
	insns := []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "cmp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w1"},
		}},
		{Address: 0x4, Size: 4, Mnemonic: "b.ge", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x14},
		}},
		{Address: 0x8, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x100},
		}},
		makeBranch(0xc, "b", 0x0),
		{Address: 0x14, Size: 4, Mnemonic: "ret"},
	}

	blocks := simplifyCFG(buildCFG(insns))
	// Head (0x0) and body (0x8) must stay separate; exit (0x14) is the third block.
	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks (head + body + exit), got %d", len(blocks))
	}
	// The loop head must still exist and the body must branch back to it.
	head := blocks[0]
	if head.StartAddr != 0x0 {
		t.Fatalf("expected loop head at 0x0, got 0x%x", head.StartAddr)
	}
	var body *BasicBlock
	for _, b := range blocks {
		if b.StartAddr == 0x8 {
			body = b
			break
		}
	}
	if body == nil {
		t.Fatalf("loop body block at 0x8 disappeared")
	}
	seenBack := false
	for _, s := range body.Succs {
		if s == head.StartAddr {
			seenBack = true
		}
	}
	if !seenBack {
		t.Fatalf("loop body lost its back-edge to head: body.succs=%v", body.Succs)
	}
}
