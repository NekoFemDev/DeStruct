package arm64lift

// simplifyCFG removes unreachable blocks and merges linear chains of
// basic blocks. It is intentionally conservative: it only merges when
// one block is the sole predecessor of another and has exactly one
// successor, preserving all observable control flow.
func simplifyCFG(blocks []*BasicBlock) []*BasicBlock {
	if len(blocks) == 0 {
		return nil
	}
	blocks = removeUnreachableBlocks(blocks)
	blocks = mergeLinearChains(blocks)
	return blocks
}

// backEdgeTargets returns the set of block start addresses that are the
// destination of a backward branch. These are loop heads (and occasional
// other upward jumps); merging into them would destroy the loop shape.
func backEdgeTargets(blocks []*BasicBlock) map[uint64]bool {
	targets := make(map[uint64]bool)
	for _, b := range blocks {
		for _, in := range b.Instructions {
			if target, ok := branchTarget(in); ok {
				if target < in.Address {
					targets[target] = true
				}
			}
		}
	}
	return targets
}

// removeUnreachableBlocks drops every block that cannot be reached from
// the entry block (blocks[0]) by following successor edges.
func removeUnreachableBlocks(blocks []*BasicBlock) []*BasicBlock {
	byAddr := make(map[uint64]*BasicBlock, len(blocks))
	for _, b := range blocks {
		byAddr[b.StartAddr] = b
	}

	reachable := make(map[uint64]bool)
	queue := []uint64{blocks[0].StartAddr}
	for len(queue) > 0 {
		addr := queue[0]
		queue = queue[1:]
		if reachable[addr] {
			continue
		}
		reachable[addr] = true
		b := byAddr[addr]
		if b == nil {
			continue
		}
		for _, s := range b.Succs {
			if !reachable[s] {
				queue = append(queue, s)
			}
		}
	}

	out := make([]*BasicBlock, 0, len(reachable))
	for _, b := range blocks {
		if reachable[b.StartAddr] {
			out = append(out, b)
		}
	}
	return out
}

// computePredCounts returns how many blocks in the current graph have
// each address as a successor.
func computePredCounts(blocks []*BasicBlock) map[uint64]int {
	counts := make(map[uint64]int)
	for _, b := range blocks {
		for _, s := range b.Succs {
			counts[s]++
		}
	}
	return counts
}

// mergeLinearChains folds sequences such as A -> B where A is B's only
// predecessor and A has only B as a successor. Redundant unconditional
// branches at the end of A are dropped as part of the merge. Blocks that
// are the target of a backward branch (loop heads) are never merged into,
// so loop structures stay intact for the structural lifter.
func mergeLinearChains(blocks []*BasicBlock) []*BasicBlock {
	if len(blocks) == 0 {
		return blocks
	}

	byAddr := make(map[uint64]*BasicBlock, len(blocks))
	for _, b := range blocks {
		byAddr[b.StartAddr] = b
	}
	loopHeads := backEdgeTargets(blocks)

	for {
		predCount := computePredCounts(blocks)
		merged := false
		removed := make(map[uint64]bool)
		newBlocks := make([]*BasicBlock, 0, len(blocks))

		for _, b := range blocks {
			if removed[b.StartAddr] {
				continue
			}

			if len(b.Succs) == 1 {
				succAddr := b.Succs[0]
				succ := byAddr[succAddr]
				if succ != nil && succAddr != b.StartAddr && predCount[succAddr] == 1 && !loopHeads[succAddr] {
					// Drop a trailing unconditional "b <succ>" before appending
					// succ's instructions; the fall-through now covers it.
					if len(b.Instructions) > 0 {
						last := &b.Instructions[len(b.Instructions)-1]
						if last.Mnemonic == "b" && len(last.Operands) > 0 {
							if target, ok := branchTarget(*last); ok && target == succAddr {
								b.Instructions = b.Instructions[:len(b.Instructions)-1]
							}
						}
					}
					b.Instructions = append(b.Instructions, succ.Instructions...)
					b.Succs = succ.Succs
					b.LastCond = succ.LastCond
					removed[succAddr] = true
					delete(byAddr, succAddr)
					merged = true
				}
			}

			newBlocks = append(newBlocks, b)
		}

		if !merged {
			break
		}
		blocks = newBlocks
	}

	return blocks
}
