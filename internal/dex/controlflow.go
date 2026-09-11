package dex

import (
	"sort"

	"github.com/destruct/destruct/internal/ir"
)

// basicBlock is a maximal straight-line instruction sequence.
type basicBlock struct {
	index       int
	start       int // first instruction index in d.insns
	end         int // exclusive
	insts       []Instruction
	succ        []int
	pred        []int
	term        *Instruction
	targetBlock int // branch/goto destination block, -1 if none
}

// loopInfo describes a natural loop found via dominator analysis.
type loopInfo struct {
	header  int
	latch   int
	nodes   map[int]bool
	exits   map[int]bool
	invalid bool
}

// structCtx carries loop context while structuring a range: the current
// loop's continue target/back-edge and the blocks whose edges leave it.
type structCtx struct {
	continueTarget int
	latchIndex     int
	ownHeader      int
	exits          map[int]bool
	parent         *structCtx
}

// isBreak reports whether a branch to block t exits the current loop.
func (c *structCtx) isBreak(t int) bool {
	if c == nil {
		return false
	}
	if t == c.continueTarget {
		return false
	}
	if c.exits != nil && c.exits[t] {
		return true
	}
	return t > c.latchIndex
}

func isGoto(inst *Instruction) bool {
	if inst == nil {
		return false
	}
	switch inst.Op {
	case OP_GOTO, OP_GOTO_16, OP_GOTO_32:
		return true
	}
	return false
}

func isCondBranch(inst *Instruction) bool {
	if inst == nil {
		return false
	}
	return inst.Op >= OP_IF_EQ && inst.Op <= OP_IF_LEZ
}

func isTerminatorInst(inst *Instruction) bool {
	if inst == nil {
		return false
	}
	if isGoto(inst) || isCondBranch(inst) {
		return true
	}
	switch inst.Op {
	case OP_RETURN_VOID, OP_RETURN, OP_RETURN_WIDE, OP_RETURN_OBJECT,
		OP_THROW, OP_PACKED_SWITCH, OP_SPARSE_SWITCH:
		return true
	}
	return false
}

func (d *DalvikToIR) buildBlocks() {
	insns := d.insns
	d.offsetToBlock = make(map[int]int, len(insns))
	if len(insns) == 0 {
		return
	}

	offsetToIdx := make(map[int]int, len(insns))
	for i := range insns {
		offsetToIdx[insns[i].Offset] = i
	}

	leaders := make(map[int]bool)
	leaders[0] = true
	for i := range insns {
		inst := &insns[i]
		if !isTerminatorInst(inst) {
			continue
		}
		if i+1 < len(insns) {
			leaders[i+1] = true
		}
		if idx, ok := offsetToIdx[inst.Target]; ok && (isGoto(inst) || isCondBranch(inst)) {
			leaders[idx] = true
		}
		if inst.Switch != nil {
			for _, rel := range inst.Switch.Targets {
				if idx, ok := offsetToIdx[inst.Offset+int(rel)]; ok {
					leaders[idx] = true
				}
			}
		}
	}

	var blocks []*basicBlock
	i := 0
	for i < len(insns) {
		j := i + 1
		for j < len(insns) && !leaders[j] {
			j++
		}
		blk := &basicBlock{
			index:       len(blocks),
			start:       i,
			end:         j,
			insts:       insns[i:j],
			targetBlock: -1,
		}
		if last := &blk.insts[len(blk.insts)-1]; isTerminatorInst(last) {
			blk.term = last
		}
		blocks = append(blocks, blk)
		i = j
	}

	idxToBlock := make(map[int]int, len(blocks))
	for _, b := range blocks {
		idxToBlock[b.start] = b.index
		d.offsetToBlock[insns[b.start].Offset] = b.index
	}
	// Also map every instruction offset to its block for switch targets.
	for _, b := range blocks {
		for k := b.start; k < b.end; k++ {
			d.offsetToBlock[insns[k].Offset] = b.index
		}
	}

	nextBlock := func(blk *basicBlock) int {
		if blk.end >= len(insns) {
			return -1
		}
		if bi, ok := idxToBlock[blk.end]; ok {
			return bi
		}
		return -1
	}
	resolve := func(inst *Instruction) int {
		if idx, ok := offsetToIdx[inst.Target]; ok {
			if bi, ok := idxToBlock[idx]; ok {
				return bi
			}
		}
		return -1
	}

	for _, b := range blocks {
		last := &b.insts[len(b.insts)-1]
		switch {
		case isGoto(last):
			if bi := resolve(last); bi >= 0 {
				b.targetBlock = bi
				b.succ = append(b.succ, bi)
			}
		case isCondBranch(last):
			if bi := resolve(last); bi >= 0 {
				b.targetBlock = bi
				b.succ = append(b.succ, bi)
			}
			if nb := nextBlock(b); nb >= 0 {
				b.succ = append(b.succ, nb)
			}
		case last.Op == OP_PACKED_SWITCH || last.Op == OP_SPARSE_SWITCH:
			if last.Switch != nil {
				for _, rel := range last.Switch.Targets {
					if idx, ok := offsetToIdx[last.Offset+int(rel)]; ok {
						if bi, ok := idxToBlock[idx]; ok {
							b.succ = append(b.succ, bi)
						}
					}
				}
			}
			if nb := nextBlock(b); nb >= 0 {
				b.succ = append(b.succ, nb)
			}
		case last.Op == OP_RETURN_VOID || last.Op == OP_RETURN ||
			last.Op == OP_RETURN_WIDE || last.Op == OP_RETURN_OBJECT || last.Op == OP_THROW:
			// no successors
		default:
			if nb := nextBlock(b); nb >= 0 {
				b.succ = append(b.succ, nb)
			}
		}
	}

	d.blocks = blocks
	for _, b := range blocks {
		for _, s := range b.succ {
			d.blocks[s].pred = append(d.blocks[s].pred, b.index)
		}
	}
}

func (d *DalvikToIR) computeDominators() {
	n := len(d.blocks)
	d.dom = make([][]bool, n)
	for i := range d.dom {
		d.dom[i] = make([]bool, n)
	}
	if n == 0 {
		return
	}

	all := make([]bool, n)
	for i := range all {
		all[i] = true
	}
	d.dom[0][0] = true
	for i := 1; i < n; i++ {
		copy(d.dom[i], all)
	}

	for changed := true; changed; {
		changed = false
		for b := 1; b < n; b++ {
			if len(d.blocks[b].pred) == 0 {
				// Unreachable block: it dominates nothing, otherwise
				// edges out of exception-handler blocks would look
				// like back edges.
				for i := range d.dom[b] {
					d.dom[b][i] = false
				}
				continue
			}
			newDom := make([]bool, n)
			for i := range newDom {
				newDom[i] = true
			}
			for _, p := range d.blocks[b].pred {
				for i := 0; i < n; i++ {
					newDom[i] = newDom[i] && d.dom[p][i]
				}
			}
			newDom[b] = true
			for i := 0; i < n; i++ {
				if newDom[i] != d.dom[b][i] {
					copy(d.dom[b], newDom)
					changed = true
					break
				}
			}
		}
	}
}

func (d *DalvikToIR) findLoops() {
	d.loops = make(map[int]*loopInfo)
	n := len(d.blocks)

	for u := 0; u < n; u++ {
		for _, v := range d.blocks[u].succ {
			if v < 0 || v >= n || !d.dom[u][v] {
				continue
			}
			// Back edge u -> v.
			lp := d.loops[v]
			if lp == nil {
				lp = &loopInfo{
					header: v,
					latch:  v,
					nodes:  map[int]bool{v: true},
					exits:  map[int]bool{},
				}
				d.loops[v] = lp
			}
			if u > lp.latch {
				lp.latch = u
			}
			lp.nodes[u] = true

			stack := []int{u}
			for len(stack) > 0 {
				x := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				for _, p := range d.blocks[x].pred {
					if p == v || lp.nodes[p] {
						continue
					}
					if p < v {
						lp.invalid = true
						continue
					}
					lp.nodes[p] = true
					if p > lp.latch {
						lp.latch = p
					}
					stack = append(stack, p)
				}
			}
		}
	}

	for _, lp := range d.loops {
		for node := range lp.nodes {
			for _, s := range d.blocks[node].succ {
				if !lp.nodes[s] {
					lp.exits[s] = true
				}
			}
		}
		for i := lp.header; i <= lp.latch; i++ {
			if !lp.nodes[i] {
				lp.invalid = true
			}
		}
		if lp.invalid {
			delete(d.loops, lp.header)
		}
	}
}

// structureRange converts blocks [lo, hi) into structured IR.
func (d *DalvikToIR) structureRange(lo, hi int, ctx *structCtx) *ir.Block {
	out := &ir.Block{}
	if lo < 0 {
		lo = 0
	}
	if hi > len(d.blocks) {
		hi = len(d.blocks)
	}

	for i := lo; i < hi; {
		// A switch body that reaches its own switch (malformed or
		// irreducible) must not recurse forever.
		if d.switchStack[i] {
			return out
		}

		// Blocks only reachable from exception handler edges are skipped:
		// try/catch recovery isn't implemented, and emitting their code
		// inline after the normal body would be wrong.
		if d.reachable != nil && !d.reachable[i] {
			i++
			continue
		}

		// Natural loop starting here.
		if lp, ok := d.loops[i]; ok && lp.latch < hi && (ctx == nil || ctx.ownHeader != i) {
			out.Statements = append(out.Statements, d.structureLoop(lp, ctx))
			i = lp.latch + 1
			continue
		}

		blk := d.blocks[i]

		if blk.term != nil && isCondBranch(blk.term) {
			out.Statements = append(out.Statements, d.convertBlock(blk.insts[:len(blk.insts)-1])...)
			cond := d.buildCond(blk.term)
			t := blk.targetBlock
			f := i + 1

			if t < 0 || t == f {
				i++
				continue
			}

			if t > i && t < hi {
				merge := d.findMerge(f, t, hi)
				thenBlk := d.structureRange(f, t, ctx)
				elseBlk := d.structureRange(t, merge, ctx)
				if len(elseBlk.Statements) == 0 {
					elseBlk = nil
				}
				out.Statements = append(out.Statements, &ir.IfStmt{
					Cond: negateExpr(cond),
					Then: thenBlk,
					Else: elseBlk,
				})
				i = merge
				continue
			}

			if ctx != nil && t == ctx.continueTarget {
				out.Statements = append(out.Statements, &ir.IfStmt{
					Cond: cond,
					Then: &ir.Block{Statements: []ir.Stmt{&ir.ContinueStmt{}}},
				})
				i++
				continue
			}
			if ctx != nil && t > i && ctx.isBreak(t) {
				out.Statements = append(out.Statements, &ir.IfStmt{
					Cond: cond,
					Then: &ir.Block{Statements: []ir.Stmt{&ir.BreakStmt{}}},
				})
				i++
				continue
			}
			if t > i {
				// Conditional exit from this region: only the remainder
				// runs when the branch is not taken.
				rest := d.structureRange(f, hi, ctx)
				out.Statements = append(out.Statements, &ir.IfStmt{Cond: negateExpr(cond), Then: rest})
				return out
			}
			// Backward branch not recognized as a loop edge: drop it.
			i++
			continue
		}

		if blk.term != nil && isGoto(blk.term) {
			out.Statements = append(out.Statements, d.convertBlock(blk.insts[:len(blk.insts)-1])...)
			t := blk.targetBlock

			if ctx != nil && ctx.latchIndex == i {
				// Natural loop back edge; the loop statement supplies it.
				return out
			}
			if ctx != nil && t == ctx.continueTarget {
				out.Statements = append(out.Statements, &ir.ContinueStmt{})
				return out
			}
			if ctx != nil && ctx.isBreak(t) {
				out.Statements = append(out.Statements, &ir.BreakStmt{})
				return out
			}
			if t < 0 || t <= i || t >= hi {
				return out
			}
			// Forward goto over an unreachable gap.
			i = t
			continue
		}

		if blk.term != nil && (blk.term.Op == OP_PACKED_SWITCH || blk.term.Op == OP_SPARSE_SWITCH) {
			out.Statements = append(out.Statements, d.convertBlock(blk.insts[:len(blk.insts)-1])...)
			sw, end := d.structureSwitch(blk, ctx, hi)
			if sw != nil {
				out.Statements = append(out.Statements, sw)
			}
			if end <= i {
				end = i + 1
			}
			i = end
			continue
		}

		out.Statements = append(out.Statements, d.convertBlock(blk.insts)...)
		i++
	}

	return out
}

func (d *DalvikToIR) structureLoop(lp *loopInfo, parent *structCtx) ir.Stmt {
	header := lp.header
	latch := lp.latch
	hb := d.blocks[header]
	ctx := &structCtx{
		continueTarget: header,
		latchIndex:     latch,
		ownHeader:      header,
		exits:          lp.exits,
		parent:         parent,
	}

	// do { ... } while (cond): the latch branches back to the header.
	if latch != header {
		lb := d.blocks[latch]
		if lb.term != nil && isCondBranch(lb.term) && lb.targetBlock == header {
			body := d.structureRange(header, latch, ctx)
			body.Statements = append(body.Statements, d.convertBlock(lb.insts[:len(lb.insts)-1])...)
			return &ir.DoWhileStmt{Cond: d.buildCond(lb.term), Body: body}
		}
	}

	// while (cond): the header ends with a conditional branch, with one
	// edge staying in the loop and the other leaving it.
	if hb.term != nil && isCondBranch(hb.term) {
		// Convert the header's own statements first so register types
		// are known when the condition is rendered.
		headerStmts := d.convertBlock(hb.insts[:len(hb.insts)-1])

		t := hb.targetBlock
		f := header + 1
		inBody := func(b int) bool { return lp.nodes[b] }
		var cond ir.Expr
		if inBody(t) && !inBody(f) {
			cond = d.buildCond(hb.term)
		} else if !inBody(t) && inBody(f) {
			cond = negateExpr(d.buildCond(hb.term))
		}

		body := d.structureRange(header+1, latch+1, ctx)
		if len(headerStmts) == 0 && cond != nil {
			return &ir.WhileStmt{Cond: cond, Body: body}
		}
		inner := &ir.Block{}
		inner.Statements = append(inner.Statements, headerStmts...)
		if cond != nil {
			inner.Statements = append(inner.Statements, &ir.IfStmt{
				Cond: negateExpr(cond),
				Then: &ir.Block{Statements: []ir.Stmt{&ir.BreakStmt{}}},
			})
		}
		inner.Statements = append(inner.Statements, body.Statements...)
		return &ir.WhileStmt{Cond: &ir.BoolLit{Value: true}, Body: inner}
	}

	// Infinite loop with explicit breaks/continues.
	body := d.structureRange(header, latch+1, ctx)
	return &ir.WhileStmt{Cond: &ir.BoolLit{Value: true}, Body: body}
}

func (d *DalvikToIR) computeReachable() {
	n := len(d.blocks)
	d.reachable = make([]bool, n)
	if n == 0 {
		return
	}
	stack := []int{0}
	d.reachable[0] = true
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, s := range d.blocks[x].succ {
			if !d.reachable[s] {
				d.reachable[s] = true
				stack = append(stack, s)
			}
		}
	}
}

// findMerge returns the first block in [f, hi) reachable from both branches,
// or hi when they never reconverge.
func (d *DalvikToIR) findMerge(f, t, hi int) int {
	if f >= hi || t >= hi {
		return hi
	}
	reachF := d.forwardReach(f, hi)
	reachT := d.forwardReach(t, hi)
	for m := f; m < hi; m++ {
		if reachF[m] && reachT[m] {
			return m
		}
	}
	return hi
}

func (d *DalvikToIR) forwardReach(start, hi int) map[int]bool {
	seen := make(map[int]bool)
	if start < 0 || start >= hi {
		return seen
	}
	stack := []int{start}
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[x] {
			continue
		}
		seen[x] = true
		for _, s := range d.blocks[x].succ {
			if s >= start && s < hi && !seen[s] {
				stack = append(stack, s)
			}
		}
	}
	return seen
}

func (d *DalvikToIR) structureSwitch(blk *basicBlock, ctx *structCtx, hi int) (*ir.SwitchStmt, int) {
	term := blk.term
	if term == nil || term.Switch == nil {
		return nil, blk.index + 1
	}
	if d.switchStack[blk.index] {
		return nil, blk.index + 1
	}
	d.switchStack[blk.index] = true
	defer delete(d.switchStack, blk.index)

	keysByBlock := make(map[int][]int32)
	seen := make(map[int]bool)
	var targets []int

	for i, rel := range term.Switch.Targets {
		bi, ok := d.offsetToBlock[term.Offset+int(rel)]
		if !ok {
			continue
		}
		bi = d.resolveTrivialGoto(bi, blk.index)
		var key int32
		if term.Switch.Packed {
			key = term.Switch.FirstKey + int32(i)
		} else if i < len(term.Switch.Keys) {
			key = term.Switch.Keys[i]
		}
		keysByBlock[bi] = append(keysByBlock[bi], key)
		if !seen[bi] {
			seen[bi] = true
			targets = append(targets, bi)
		}
	}
	defaultBlk := blk.index + 1
	if defaultBlk < hi && defaultBlk < len(d.blocks) {
		defaultBlk = d.resolveTrivialGoto(defaultBlk, blk.index)
	} else {
		defaultBlk = -1
	}
	if defaultBlk >= 0 && !seen[defaultBlk] {
		seen[defaultBlk] = true
		targets = append(targets, defaultBlk)
	}

	if len(targets) == 0 {
		return nil, blk.index + 1
	}

	sort.Ints(targets)

	// Merge point: first block reachable from every target.
	common := d.forwardReach(targets[0], hi)
	for _, tgt := range targets[1:] {
		r := d.forwardReach(tgt, hi)
		for b := range common {
			if !r[b] {
				delete(common, b)
			}
		}
	}
	merge := hi
	for b := targets[0]; b < hi; b++ {
		if common[b] {
			merge = b
			break
		}
	}

	sw := &ir.SwitchStmt{Target: d.getRegister(term.A)}
	for idx, tgt := range targets {
		end := merge
		if idx+1 < len(targets) {
			end = targets[idx+1]
		}
		if end > merge {
			end = merge
		}
		if tgt >= end {
			end = tgt + 1
			if end > hi {
				end = hi
			}
		}
		body := d.structureRange(tgt, end, ctx)
		if tgt == defaultBlk {
			sw.Default = body
			continue
		}
		vals := keysByBlock[tgt]
		if len(vals) == 0 {
			continue
		}
		exprs := make([]ir.Expr, len(vals))
		for i, v := range vals {
			exprs[i] = &ir.IntLit{Value: int64(v)}
		}
		sw.Cases = append(sw.Cases, &ir.CaseClause{
			Values:      exprs,
			Body:        body,
			Fallthrough: d.rangeFallsThrough(tgt, end),
		})
	}

	return sw, merge
}

// resolveTrivialGoto follows chains of goto-only trampoline blocks so that
// switch partitioning works on real bodies rather than jump stubs. avoid is
// returned unchanged if the chain would loop back to it.
func (d *DalvikToIR) resolveTrivialGoto(b int, avoid int) int {
	for i := 0; i < 16; i++ {
		if b < 0 || b >= len(d.blocks) || b == avoid {
			return b
		}
		blk := d.blocks[b]
		if len(blk.insts) != 1 || !isGoto(blk.term) || blk.targetBlock < 0 {
			return b
		}
		b = blk.targetBlock
	}
	return b
}

// rangeFallsThrough reports whether the last block of [lo, end) continues
// into block end without jumping elsewhere.
func (d *DalvikToIR) rangeFallsThrough(lo, end int) bool {
	if end <= lo || end > len(d.blocks) || lo < 0 {
		return false
	}
	last := d.blocks[end-1]
	if last.term == nil {
		return true
	}
	if isGoto(last.term) && last.targetBlock == end {
		return true
	}
	return false
}
