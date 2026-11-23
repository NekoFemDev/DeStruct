// Package arm64lift lifts disassembled ARM64 instructions
// (native.DetailedInstruction) into this project's existing IR
// (internal/ir), the same target representation the JVM decompiler
// produces - reusing the IR means the same Java-style generator/renderer
// infrastructure could eventually render lifted ARM64 code too (as
// C-like syntax, since the IR itself is expression/statement-oriented
// and not Java-specific at the node level).
//
// Unlike JVM bytecode's stack machine, ARM64 is a register machine: a
// value doesn't get pushed/popped through an implicit stack, it lives in
// a named register (w0, x1, sp, ...) until something overwrites it. The
// lifter's central data structure is therefore a register file mapping
// register name -> the IR expression currently "in" that register,
// updated as each instruction is lifted - not an expression stack like
// the JVM side uses.
package arm64lift

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/native"
)

// LiftFunction lifts a single function's worth of disassembled
// instructions (already isolated by the caller - e.g. by objcopy'ing
// just .text, as in the initial test, or by real function-boundary
// detection later) into IR statements.
//
// paramNames gives the source-level name for each integer/pointer
// argument register in AAPCS64 order (w0/x0 first, w1/x1 second, ...) -
// e.g. []string{"a", "b"} for "int add(int a, int b)". The lifter has no
// way to recover real parameter names on its own (nothing in the binary
// encodes them); callers without better information should just pass
// placeholder names like "a0", "a1".
// BasicBlock is a maximal straight-line run of instructions: control
// enters only at the first instruction and leaves only at the last
// (which is always a branch, conditional branch, or the function's
// final instruction) - the standard definition used throughout the rest
// of this project's JVM-side control-flow reconstruction too, just
// built from ARM64 branch instructions and absolute addresses instead
// of bytecode opcodes and offsets.
type BasicBlock struct {
	StartAddr    uint64
	Instructions []native.DetailedInstruction
	// Succs holds this block's successor addresses in the order a
	// structural matcher (see liftBlockGraph) needs to tell them apart:
	// for a conditional branch, Succs[0] is the "branch taken" target
	// and Succs[1] is the fallthrough (next instruction after the
	// branch) - for an unconditional branch or fallthrough-only block,
	// Succs has exactly one entry.
	Succs []uint64
	// LastCond, if non-nil, is the b.cond (or cbz/cbnz - not yet
	// lifted, see the TODO at the bottom of lift.go) instruction that
	// ends this block, kept alongside Instructions (which also
	// includes it) so callers building an if/else don't need to
	// re-scan for it.
	LastCond *native.DetailedInstruction
}

// buildCFG splits a straight-line instruction stream into basic blocks
// and links them into a graph, using each instruction's own address
// (from Capstone) as the block/edge identifier - unlike the JVM side,
// which works with instruction-slice indices because bytecode offsets
// aren't necessarily instruction-aligned in a convenient way, ARM64
// instructions are always exactly 4 bytes and branch targets are real
// absolute addresses, so addresses double as both.
func buildCFG(instructions []native.DetailedInstruction) []*BasicBlock {
	if len(instructions) == 0 {
		return nil
	}

	// A new block starts at instruction 0, at any branch target, and at
	// the instruction right after any branch (conditional or not) -
	// the standard basic-block leader rules.
	leaders := map[uint64]bool{instructions[0].Address: true}
	for i, inst := range instructions {
		if target, ok := branchTarget(inst); ok {
			leaders[target] = true
		}
		if isAnyBranch(inst) && i+1 < len(instructions) {
			leaders[instructions[i+1].Address] = true
		}
	}

	var blocks []*BasicBlock
	byAddr := make(map[uint64]*BasicBlock)
	var cur *BasicBlock
	for _, inst := range instructions {
		if leaders[inst.Address] {
			cur = &BasicBlock{StartAddr: inst.Address}
			blocks = append(blocks, cur)
			byAddr[inst.Address] = cur
		}
		cur.Instructions = append(cur.Instructions, inst)
	}

	// Wire up successor edges now that every block's start address is
	// known.
	for _, b := range blocks {
		last := b.Instructions[len(b.Instructions)-1]
		if target, ok := branchTarget(last); ok {
			if isConditionalBranch(last) {
				cond := last
				b.LastCond = &cond
				fallthroughAddr := last.Address + uint64(last.Size)
				// Branch-taken target first, fallthrough second - see
				// BasicBlock.Succs' doc comment for why the order
				// matters to callers.
				b.Succs = []uint64{target, fallthroughAddr}
			} else {
				b.Succs = []uint64{target}
			}
		} else if last.Mnemonic != "ret" && last.Mnemonic != "br" {
			// Falls through to the next block in address order (no
			// branch at all ended this block - it just ran out of
			// leaders, meaning the next leader is reached by ordinary
			// sequential execution). "ret" and "br" are both real ends
			// of this path with no statically knowable successor at all
			// (br's target is whatever's in its register, not
			// something branchTarget can ever resolve - see its own doc
			// comment) - Succs stays nil/empty for both, a true leaf,
			// rather than wrongly assuming whatever instruction happens
			// to follow in the byte stream is reachable by falling
			// through.
			fallthroughAddr := last.Address + uint64(last.Size)
			if _, ok := byAddr[fallthroughAddr]; ok {
				b.Succs = []uint64{fallthroughAddr}
			}
		}
	}

	return blocks
}

// branchTarget returns the absolute target address of a branch
// instruction (b, bl, b.cond) and true, or (0, false) for anything
// else. ARM64's branch instructions encode their target as a single
// immediate operand (the absolute address, since Capstone already
// resolves the PC-relative encoding for us).
func branchTarget(inst native.DetailedInstruction) (uint64, bool) {
	if !isAnyBranch(inst) {
		return 0, false
	}
	if len(inst.Operands) == 0 {
		return 0, false
	}
	// The target is always the LAST operand: "b"/"b.cond" have exactly
	// one (the target itself), "cbz"/"cbnz" put it after the tested
	// register ("cbz Rt, #target"), and "tbz"/"tbnz" put it after both
	// the tested register and the bit index ("tbz Rt, #bit, #target").
	last := inst.Operands[len(inst.Operands)-1]
	if last.Type != native.OperandImm {
		return 0, false
	}
	return uint64(last.Imm), true
}

// isAnyBranch reports whether inst is any kind of direct or indirect
// branch this lifter currently recognizes as ending a basic block:
// unconditional "b", indirect "br" (jumps through a register rather
// than an immediate target - see liftBr's own doc comment; by far the
// most common real -O0 shape is a C++ virtual-dispatch thunk: load a
// vtable slot, jump through it), or a conditional one (see
// isConditionalBranch). "bl"/"blr" (calls, direct or indirect)
// deliberately do NOT end a block here - a call returns control to the
// next instruction, so it doesn't change the function's own control
// flow the way a real branch does.
func isAnyBranch(inst native.DetailedInstruction) bool {
	if inst.Mnemonic == "b" || inst.Mnemonic == "br" {
		return true
	}
	return isConditionalBranch(inst)
}

// isConditionalBranch reports whether inst is a conditional branch:
// either "b.cond" (Capstone folds the ARM64 condition code into the
// mnemonic string itself, as "b.eq", "b.le", "b.gt", ... - not a
// separate operand or field), "cbz"/"cbnz" (branch if a register
// is/isn't zero - the single most common -O0 idiom for a null/zero
// check or a simple loop counter test, compiled directly from the
// comparison rather than via a separate "cmp"), or "tbz"/"tbnz"
// (branch if a single bit of a register is/isn't set - the standard
// -O0 idiom for testing one flag bit, e.g. "if (flags & (1 << 3))",
// without needing a separate "and"+"cmp" pair) - see liftCondition's
// own handling of all three.
func isConditionalBranch(inst native.DetailedInstruction) bool {
	switch inst.Mnemonic {
	case "cbz", "cbnz", "tbz", "tbnz":
		return true
	}
	return len(inst.Mnemonic) > 2 && inst.Mnemonic[0] == 'b' && inst.Mnemonic[1] == '.'
}

// SymbolResolver resolves a call target's absolute address to a
// human-readable name (e.g. a demangled or mangled C++ symbol, or an
// imported libc function name via PLT resolution) - see
// internal/native's ELFParser.GetSymbolName and ResolvePLT for the two
// real sources callers combine to build one of these. Returns
// ("", false) for an address with no known name.
type SymbolResolver func(addr uint64) (name string, ok bool)

// StringResolver resolves an absolute data address to the string
// literal stored there, if any - see internal/native's
// ELFParser.ReadCString for the real source callers use to build one
// of these. Returns ("", false) for an address that isn't a
// recognized NUL-terminated printable string (not in a data section,
// unterminated, or not text - most likely because it's some other kind
// of data, e.g. a pointer or vtable, not a string literal). May be
// nil, in which case an adrp/adr-computed address is only ever
// rendered as its raw numeric value.
type StringResolver func(addr uint64) (s string, ok bool)

// LiftFunction lifts a single function's worth of disassembled
// instructions into IR statements. See the type's own doc comment for
// paramNames; resolver may be nil, in which case call targets are
// rendered as bare "func_<address>" placeholders; strResolver may be
// nil, in which case a computed data address is rendered as a raw
// number rather than resolved text.
func LiftFunction(instructions []native.DetailedInstruction, paramNames []string, resolver SymbolResolver, strResolver StringResolver) []ir.Stmt {
	return LiftFunctionWithData(instructions, paramNames, resolver, strResolver, nil, true)
}

// LiftFunctionWithData is LiftFunction with an optional dataReader for
// reading bytes from the original binary by virtual address. When
// non-nil it enables jump-table switch statement detection.
func LiftFunctionWithData(instructions []native.DetailedInstruction, paramNames []string, resolver SymbolResolver, strResolver StringResolver, dataReader func(uint64, int) ([]byte, bool), simplify bool) []ir.Stmt {
	return LiftFunctionWithOptions(instructions, paramNames, resolver, strResolver, dataReader, LiftOptions{Simplify: simplify})
}

// LiftFunctionWithOptions is the full entry point: LiftFunctionWithData
// plus the IL2CPP-aware LiftOptions (see liftopts.go). The zero options
// value is exactly LiftFunctionWithData's behavior, so every existing
// caller keeps its current output.
//
// When Metadata is supplied, the function's entry address (the first
// instruction's address) is looked up as a managed method RVA. A match
// seeds the AAPCS64 parameter registers with the method's real
// parameter names (prepending "this" for instance methods) and records
// the declaring type, which in turn lets a `ldr/str [x0, #off]` on the
// `this` pointer resolve its displacement to the actual IL2CPP field
// name (see newFieldAccess). Nothing changes when the address doesn't
// match - most lifted functions in a real binary aren't managed method
// entries, and that's expected, not an error.
func LiftFunctionWithOptions(instructions []native.DetailedInstruction, paramNames []string, resolver SymbolResolver, strResolver StringResolver, dataReader func(uint64, int) ([]byte, bool), opts LiftOptions) []ir.Stmt {
	budget := blockVisitBudget
	searchBudget := searchVisitBudget
	labelSeq := 0
	regSeq := 0
	simdSeq := 0
	l := &lifter{
		regs:         make(map[string]ir.Expr),
		stack:        make(map[int32]string),
		stackWidth:   make(map[int32]int),
		stackTyped:   make(map[int32]bool),
		resolver:     resolver,
		strings:      strResolver,
		addrRegs:     make(map[string]uint64),
		consumed:     make(map[ir.Expr]bool),
		resultRegs:   make(map[string]bool),
		budget:       &budget,
		searchBudget: &searchBudget,
		dataReader:   dataReader,
		labelSeq:     &labelSeq,
		mergeLabels:  make(map[mergeShareKey]string),
		opts:         opts,
		regNames:     make(map[string]string),
		regSeq:       &regSeq,
		simdSeq:      &simdSeq,
		written:      make(map[string]bool),
		seedRefs:     make(map[string]ir.Expr),
		regWidths:    make(map[string]int),
	}
	if opts.Metadata != nil && len(instructions) > 0 {
		if typeName, params, isStatic, ok := opts.Metadata.MethodAtRVA(instructions[0].Address); ok {
			if paramNames == nil {
				if isStatic {
					paramNames = append([]string(nil), params...)
				} else {
					paramNames = append([]string{"this"}, params...)
				}
			}
			l.thisType = typeName
		}
	}
	l.params = paramNames
	l.seedParams()
	l.functionInsns = instructions
	l.insnIndex = make(map[uint64]int, len(instructions))
	for i, in := range instructions {
		l.insnIndex[in.Address] = i
	}
	if len(instructions) > 0 {
		l.functionStart = instructions[0].Address
		last := instructions[len(instructions)-1]
		l.functionEnd = last.Address + uint64(last.Size)
	}

	blocks := buildCFG(instructions)
	if opts.Simplify {
		blocks = simplifyCFG(blocks)
	}
	l.cfg = analyzeCFG(blocks)
	if len(blocks) <= 1 {
		// No branching at all - the original straight-line path handles
		// this case exactly as before CFG support was added. This is
		// also unconditionally a leaf (nothing follows), so any call
		// this straight-line run produced but never used - most
		// commonly a trailing tail call (see liftTailCall) or a
		// mid-function void call - must be flushed as its own statement
		// now, or it would just vanish.
		var insts []native.DetailedInstruction
		if len(blocks) == 1 {
			insts = blocks[0].Instructions
		}
		stmts := l.run(insts)
		return l.finishFunction(append(stmts, l.flushRemaining()...))
	}

	byAddr := make(map[uint64]*BasicBlock, len(blocks))
	for _, b := range blocks {
		byAddr[b.StartAddr] = b
	}
	return l.finishFunction(l.liftBlockGraph(blocks[0], byAddr, make(map[uint64]bool), nil))
}

// finishFunction makes every lifted C function well-defined: if the last
// top-level statement is not a return, append "return x0" using the ABI
// return register. This covers trailing noreturn calls and paths whose
// ret is only reachable through nested control flow.
func (l *lifter) finishFunction(stmts []ir.Stmt) []ir.Stmt {
	stmts = reconstructTryCatch(stmts)
	if len(stmts) == 0 {
		return stmts
	}
	if _, ok := stmts[len(stmts)-1].(*ir.ReturnStmt); ok {
		return stmts
	}
	return append(stmts, &ir.ReturnStmt{Value: &ir.LocalVar{Name: l.regName("x0")}})
}

// loopCtx identifies the innermost enclosing loop a liftBlockGraph
// call is currently lifting code inside of, if any - headAddr/
// exitAddr are that loop's own head/exit block addresses (see
// tryLiftWhileLoop), which liftBlockGraph intercepts as continue/break
// respectively rather than lifting them as ordinary blocks. nil means
// "not inside any loop" (either at the function's top level, or
// lifting the continuation that runs AFTER a loop, which resumes the
// OUTER loop's own context - see tryLiftWhileLoop's own use of this).
type loopCtx struct {
	headAddr uint64
	exitAddr uint64
	// doWhileTail, when non-nil, means this is a do/for-shaped
	// ("condition last") loop rather than an ordinary while: headAddr is
	// the TAIL block's own address, and - unlike a while-shape loop's
	// head, which is fully lifted up front before the body is ever
	// forked - its instructions haven't been lifted yet when the body
	// starts. See liftDoWhileTail's own doc comment for how reaching
	// headAddr is handled differently in this case.
	doWhileTail *doWhileTailState
	// joinAddr/joinLabel, when set, identify the block every path out of
	// this loop must eventually reach (its immediate post-dominator,
	// from cfgAnalysis.ipdom) and the label emitted in front of its
	// continuation. A walk still in this loop's context that reaches
	// joinAddr is leaving the loop by a route that is NOT the primary
	// exitAddr (a second exit edge, or a split arm whose merge lies past
	// the loop): it must jump to joinLabel - the continuation after the
	// loop - instead of lifting the loop's tail inline or walking on
	// with loop context, either of which duplicated entire downstream
	// regions (see tryLiftIfElseMerge's own note on why a merge outside
	// the loop must not be accepted as an if/else merge point).
	joinAddr  uint64
	joinLabel string
}

// doWhileTailState is shared (via the same *doWhileTailState pointer)
// across every fork spawned while lifting one do-while loop's body, so
// that whichever fork reaches the tail block FIRST (deterministic: Go
// evaluates a composite literal's fields, e.g. IfStmt's Then before
// Else, in the order written) is the one whose lifted condition
// becomes the loop's own displayed Cond - see liftDoWhileTail.
type doWhileTailState struct {
	captured bool
	cond     ir.Expr
}

// liftBlockGraph structurally reconstructs if/else and while loops
// from the CFG, starting at block b, mirroring this project's
// JVM-side control-flow reconstruction: a block ending in a
// conditional branch whose two successors both eventually reach the
// same merge block becomes an if/else (see tryLiftWhileLoop first,
// though, for when one successor instead reaches back to the block
// itself - a loop, not an if/else); anything not matching either shape
// is lifted as a flat, linear sequence (falls through to the next
// block without real structural recovery) - narrower than the JVM
// side's matchers in some respects still (see the TODO at the bottom
// of this file), but not in others: a loop body can freely contain its
// own nested if/else, break/continue, or nested loops, all handled by
// nothing more than this same function recursing into itself with
// (possibly new) loop context - see loop's own doc comment.
//
// visited guards against revisiting a block already lifted along this
// path (defensive - real -O0 code without loops shouldn't need it, but
// prevents infinite recursion on unexpected/malformed input rather than
// hanging).
func (l *lifter) liftBlockGraph(b *BasicBlock, byAddr map[uint64]*BasicBlock, visited map[uint64]bool, loop *loopCtx) []ir.Stmt {
	if b == nil {
		return nil
	}
	// A stop address is this arm's shared continuation, lifted once by
	// the caller after the if/else instead of here: jump to its label.
	// Checked before everything else (including the already-visited
	// check below, which would otherwise silently swallow the jump) so
	// the continuation is never lifted a second time - see
	// tryLiftIfElseMerge's own doc comment.
	if label, ok := l.stops[b.StartAddr]; ok {
		if l.mergeUsed != nil {
			*l.mergeUsed = true
		}
		stmts := l.flushRemaining()
		return append(stmts, &ir.GotoStmt{Label: label})
	}
	// Leaving the current loop through its join block (see
	// loopCtx.joinAddr's own doc comment): jump to the continuation
	// after the loop, exactly like a stop above - and checked before
	// the already-visited case for the same reason stops are.
	if loop != nil && loop.joinAddr != 0 && b.StartAddr == loop.joinAddr {
		stmts := l.flushRemaining()
		return append(stmts, &ir.GotoStmt{Label: loop.joinLabel})
	}
	if visited[b.StartAddr] {
		// Reaching an already-visited block via the plain
		// single-successor path (the only way this can happen at all,
		// since a fork always gets its OWN visited copy - see
		// liftLoopEdge's own reasoning) always means a genuine
		// back-edge/cycle in THIS lineage, recognized as a loop or
		// not (tryLiftWhileLoop can fail to recognize an unusual
		// shape - e.g. a short-circuit "||" compound condition, where
		// EITHER successor of the head can reach back - and still
		// fall back to ordinary if/else). Either way, this path has
		// reached the true end of what it will ever contribute -
		// exactly like a real leaf - so anything it computed and left
		// unconsumed must be flushed now, or it would silently vanish
		// (this is what a plain "return nil" here used to do).
		return l.flushRemaining()
	}
	// See lifter.budget's own doc comment: this bounds the exponential
	// blowup an if/else split with no merge-point sharing is otherwise
	// prone to. Once exhausted, every further call becomes this same
	// O(1) early return, so recursion actually stops quickly rather
	// than merely slowing down.
	if *l.budget <= 0 {
		return nil
	}
	*l.budget--

	// Must be tried before b is marked visited (below) or anything else
	// runs: a do/for-shaped ("condition last") loop's body starts
	// running immediately at b, with no conditional branch of its own
	// to signal "this might be a loop" until control reaches the TAIL
	// block further on - by the time an ordinary straight-line walk got
	// there, b (and any blocks in between) would already be flattened
	// into stmts and marked visited, too late to retroactively wrap in
	// a loop. Trying this before marking b visited also matters for the
	// single-block case (b's own conditional branch loops back to
	// itself): tryLiftDoWhileLoop's own body-lift needs to actually
	// visit b again, which visited[b.StartAddr]=true would otherwise
	// immediately (and incorrectly) block. See tryLiftDoWhileLoop's own
	// doc comment.
	if loopStmts, ok := l.tryLiftDoWhileLoop(b, byAddr, visited, loop); ok {
		return loopStmts
	}
	visited[b.StartAddr] = true
	return l.liftBlockGraphDispatch(b, byAddr, visited, loop)
}

// liftBlockGraphDispatch is liftBlockGraph's own core if/else-vs-
// straight-line dispatch, factored out so tryLiftDoWhileLoop can lift a
// do-while loop's OWN body-start block (b) directly - calling
// liftBlockGraph itself for that specific block would re-run its
// do-while pre-check on the very same b (and, for a single-block
// do-while whose own conditional branch loops back to itself, on the
// very same tail search result), recursing forever. Every other call
// site keeps going through liftBlockGraph as normal (see its own doc
// comment for the visited/budget/do-while bookkeeping this deliberately
// skips - the caller is expected to have already done that once for b).
func (l *lifter) liftBlockGraphDispatch(b *BasicBlock, byAddr map[uint64]*BasicBlock, visited map[uint64]bool, loop *loopCtx) []ir.Stmt {
	if loop != nil && loop.doWhileTail != nil && b.StartAddr == loop.headAddr {
		// The single-block do-while case: b's own conditional branch IS
		// the loop's tail (chain length zero in tryLiftDoWhileLoop's own
		// search - b's back-edge loops directly to itself), so the
		// ordinary if/else-vs-tryLiftWhileLoop dispatch below - which
		// would otherwise treat b's own LastCond+2Succs shape as a brand
		// new nested while-loop rooted at b - must never run for it; see
		// liftDoWhileTail's own doc comment.
		return l.liftDoWhileTail(loop, byAddr)
	}

	var stmts []ir.Stmt

	if b.LastCond != nil && len(b.Succs) == 2 {
		// Lift everything in this block up to (but not including) the
		// conditional branch itself as ordinary straight-line code
		// first (e.g. the "cmp" that sets the flags this branch tests).
		bodyInsns := b.Instructions[:len(b.Instructions)-1]
		stmts = append(stmts, l.run(bodyInsns)...)

		// liftCondition must run BEFORE flushRemaining: a b.cond's
		// operands were already consumed earlier, while running
		// bodyInsns's own "cmp" (so calling it here is a no-op change
		// to consumed either way) - but a cbz/cbnz's tested register is
		// only ever consumed by liftCondition itself (see its own doc
		// comment), and that consumption must land before
		// flushRemaining runs, or a register still holding an
		// unconsumed call result at exactly this point would get
		// flushed as its own spurious statement here and THEN embedded
		// a second time into cond below.
		cond := l.liftCondition(*b.LastCond)

		// Anything else this straight-line prefix produced but left
		// unconsumed (by cond above, or by anything else) can never be
		// reached by name from inside EITHER fork below (each gets its
		// own copy of consumed from this point on - see fork's own doc
		// comment), so it must be flushed here, once, in the parent,
		// before the split - not left for one or both forks to
		// (incorrectly, redundantly) flush independently.
		stmts = append(stmts, l.flushRemaining()...)

		thenAddr, elseAddr := b.Succs[0], b.Succs[1]

		if loopStmts, ok := l.tryLiftWhileLoop(b, cond, thenAddr, elseAddr, byAddr, visited, loop); ok {
			return append(stmts, loopStmts...)
		}

		// liftLoopEdge is what turns a branch straight to the
		// innermost enclosing loop's own head/exit into an explicit
		// continue/break, since this IS one arm of a genuine
		// conditional split (the other arm does something different) -
		// unlike the plain single-successor fallback below, where
		// reaching head this way is simply "the body's done, naturally
		// re-check the condition" and needs no statement at all. See
		// its own doc comment.
		//
		// Before splitting the ordinary way (each arm independently
		// lifting the full continuation), try the merge-point form: if
		// the CFG says both arms must eventually reach one shared
		// block, each arm stops there with a GotoStmt and the
		// continuation is lifted exactly once after the if/else - the
		// difference between linear and exponential output.
		if merged, ok := l.tryLiftIfElseMerge(b, cond, thenAddr, elseAddr, byAddr, visited, loop); ok {
			return append(stmts, merged...)
		}
		stmts = append(stmts, &ir.IfStmt{
			Cond: cond,
			Then: &ir.Block{Statements: l.liftLoopEdge(thenAddr, byAddr, visited, loop, l.stops, l.mergeUsed)},
			Else: &ir.Block{Statements: l.liftLoopEdge(elseAddr, byAddr, visited, loop, l.stops, l.mergeUsed)},
		})
		return stmts
	}

	// No conditional branch ending this block - but check for the
	// AArch64 jump-table switch idiom before falling back to a straight-
	// line lift of the block's instructions.
	if b.Instructions[len(b.Instructions)-1].Mnemonic == "br" {
		if swStmts, ok := l.tryLiftSwitch(b, byAddr, visited, loop); ok {
			return swStmts
		}
	}

	// No conditional branch ending this block - lift it straight-line
	// and continue into whichever single successor it has (if any).
	stmts = append(stmts, l.run(b.Instructions)...)
	if len(b.Succs) == 1 {
		if loop != nil && b.Succs[0] == loop.exitAddr {
			// An unconditional jump straight to the loop's own exit -
			// a "break;" with no enclosing if (unusual, but valid: an
			// unconditional break at the end of some straight-line
			// stretch of the body, e.g. after every other case was
			// already handled by an earlier conditional continue).
			// Unlike reaching headAddr this same way (below), exitAddr
			// is never where a loop body naturally ends up on its own,
			// so this must always be explicit. Flushed first, same
			// reasoning as the headAddr case below: this path doesn't
			// reach liftBlockGraph's own "true leaf" flush either
			// (exitAddr's block does exist in byAddr), so anything
			// left pending here would otherwise vanish right before
			// the break.
			stmts = append(stmts, l.flushRemaining()...)
			return append(stmts, &ir.BreakStmt{})
		}
		if loop != nil && b.Succs[0] == loop.headAddr {
			// A merge stop placed on the do-while tail must win over the
			// ordinary "fall into the tail" handling below: the tail's
			// instructions are lifted exactly once at the label instead,
			// and this path just jumps there.
			if label, ok := l.stops[b.Succs[0]]; ok {
				if l.mergeUsed != nil {
					*l.mergeUsed = true
				}
				stmts = append(stmts, l.flushRemaining()...)
				return append(stmts, &ir.GotoStmt{Label: label})
			}
			if loop.doWhileTail != nil {
				// Unlike a while-shape loop's head (see below), a
				// do-while's tail hasn't been lifted yet at this point -
				// see liftDoWhileTail's own doc comment for why reaching
				// it must actually run its instructions here rather than
				// just flushing and stopping.
				return append(stmts, l.liftDoWhileTail(loop, byAddr)...)
			}
			// The natural end of this path within the loop body - it
			// simply loops back to re-check the condition, needing no
			// explicit statement (unlike exitAddr above: this IS where
			// a body naturally ends up without any special source-level
			// construct at all). head is always already visited by
			// this point (see tryLiftWhileLoop, which lifts it before
			// ever setting up this loop context), so recursing into it
			// like the plain case below would just silently return nil
			// without ever reaching what liftBlockGraph normally treats
			// as a "true leaf" - meaning anything picked up along THIS
			// path (a call whose result nothing here consumed) needs
			// its own explicit flush right here, or it would vanish.
			return append(stmts, l.flushRemaining()...)
		}
		if next, ok := byAddr[b.Succs[0]]; ok {
			return append(stmts, l.liftBlockGraph(next, byAddr, visited, loop)...)
		}
	}
	// A true leaf: either this block has no successor at all, or its
	// one successor address isn't a block we know how to lift (e.g. an
	// external tail-call target already handled by liftTailCall as part
	// of running b.Instructions above). Nothing downstream will ever
	// read whatever this path's straight-line run left sitting unused
	// in a register, so flush it now.
	return append(stmts, l.flushRemaining()...)
}

// tryLiftSwitch detects the standard AArch64 jump-table switch idiom:
//
//	adrp	base, #jump_table_page
//	add	base, base, #jump_table_off
//	ldrsw	off, [base, index, lsl #2]
//	add	target, off, base
//	br	target
//
// When the idiom is found and the table's entries can be read from the
// binary, it emits an ir.SwitchStmt on the original index register with
// one case per valid table entry, lifting each target block as the case
// body. This is intentionally conservative: it only commits when at
// least two case targets resolve to real basic blocks in the CFG.
func (l *lifter) tryLiftSwitch(b *BasicBlock, byAddr map[uint64]*BasicBlock, visited map[uint64]bool, loop *loopCtx) ([]ir.Stmt, bool) {
	if l.dataReader == nil || len(b.Instructions) < 3 {
		return nil, false
	}
	last := b.Instructions[len(b.Instructions)-1]
	if last.Mnemonic != "br" || len(last.Operands) != 1 || last.Operands[0].Type != native.OperandReg {
		return nil, false
	}
	targetReg := last.Operands[0].Reg

	var baseReg, indexReg string
	for i := len(b.Instructions) - 2; i >= 0; i-- {
		inst := b.Instructions[i]
		switch inst.Mnemonic {
		case "add":
			if len(inst.Operands) == 3 &&
				inst.Operands[0].Type == native.OperandReg && inst.Operands[0].Reg == targetReg &&
				inst.Operands[1].Type == native.OperandReg &&
				inst.Operands[2].Type == native.OperandReg && inst.Operands[2].Reg == targetReg {
				baseReg = inst.Operands[1].Reg
			}
		case "ldrsw":
			if len(inst.Operands) == 2 &&
				inst.Operands[0].Type == native.OperandReg && inst.Operands[0].Reg == targetReg &&
				inst.Operands[1].Type == native.OperandMem &&
				inst.Operands[1].Mem.Index != "" &&
				(baseReg == "" || inst.Operands[1].Mem.Base == baseReg) {
				baseReg = inst.Operands[1].Mem.Base
				indexReg = inst.Operands[1].Mem.Index
			}
		}
	}
	if baseReg == "" || indexReg == "" {
		return nil, false
	}
	tableBase, ok := l.addrRegs[baseReg]
	if !ok {
		return nil, false
	}

	const maxCases = 64
	var targets []uint64
	for i := 0; i < maxCases; i++ {
		data, ok := l.dataReader(tableBase+uint64(i*4), 4)
		if !ok || len(data) < 4 {
			break
		}
		off := int32(binary.LittleEndian.Uint32(data))
		target := uint64(int64(tableBase) + int64(off))
		if _, exists := byAddr[target]; !exists {
			break
		}
		targets = append(targets, target)
	}
	if len(targets) < 2 {
		return nil, false
	}

	// Lift the prefix (adrp/add/ldrsw/add) so the index register's
	// expression is available for the switch target.
	stmts := l.run(b.Instructions[:len(b.Instructions)-1])

	sw := &ir.SwitchStmt{Target: l.regValue(indexReg)}
	for i, target := range targets {
		body := l.liftSwitchCase(target, byAddr, visited, loop)
		if body == nil {
			body = []ir.Stmt{}
		}
		sw.Cases = append(sw.Cases, &ir.CaseClause{
			Values: []ir.Expr{&ir.IntLit{Value: int64(i)}},
			Body:   &ir.Block{Statements: body},
		})
	}
	return append(stmts, sw), true
}

// liftSwitchCase lifts one target block of a jump-table switch as a
// case body. It uses a forked lifter and a fresh visited set so the
// case body is independent of the switch block's own state.
func (l *lifter) liftSwitchCase(target uint64, byAddr map[uint64]*BasicBlock, visited map[uint64]bool, loop *loopCtx) []ir.Stmt {
	blk, ok := byAddr[target]
	if !ok {
		return nil
	}
	forked := l.fork()
	return forked.liftBlockGraph(blk, byAddr, cloneVisited(visited), loop)
}

// liftLoopEdge lifts one arm of an if/else split found while lifting
// INSIDE a loop body (the thenAddr/elseAddr case in liftBlockGraph's
// own if/else handling): reaching the innermost enclosing loop's own
// head or exit this way is an explicit continue/break (this arm of
// the branch does that; the other arm does something else - see
// liftBlockGraph's own note on why the plain single-successor case is
// different). Anything else is an ordinary nested block, lifted with
// its own forked lifter and visited copy exactly like an ordinary
// if/else branch (see liftBlockGraph's reasoning for why each side
// needs its own fork: both branches may independently reach a shared
// merge block, and each needs to lift it with its OWN register
// state).
func (l *lifter) liftLoopEdge(addr uint64, byAddr map[uint64]*BasicBlock, visited map[uint64]bool, loop *loopCtx, stops map[uint64]string, mergeUsed *bool) []ir.Stmt {
	if label, ok := stops[addr]; ok {
		if mergeUsed != nil {
			*mergeUsed = true
		}
		return []ir.Stmt{&ir.GotoStmt{Label: label}}
	}
	if loop != nil {
		if addr == loop.joinAddr && loop.joinAddr != 0 {
			// Same leaving-the-loop case liftBlockGraph's own join check
			// handles - see loopCtx.joinAddr's doc comment - just reached
			// directly as one arm of a conditional split.
			return []ir.Stmt{&ir.GotoStmt{Label: loop.joinLabel}}
		}
		if addr == loop.headAddr {
			if loop.doWhileTail != nil {
				// See liftDoWhileTail's own doc comment: this arm's own
				// jump straight to the tail (skipping whatever the OTHER
				// arm still does first) is a genuine "continue" - but
				// the tail's instructions still need to actually run
				// before this path ends, exactly like the plain
				// single-successor case in liftBlockGraph.
				return append(l.liftDoWhileTail(loop, byAddr), &ir.ContinueStmt{})
			}
			return []ir.Stmt{&ir.ContinueStmt{}}
		}
		if addr == loop.exitAddr {
			return []ir.Stmt{&ir.BreakStmt{}}
		}
	}
	block, ok := byAddr[addr]
	if !ok {
		return nil
	}
	forked := l.fork()
	forked.stops = stops
	forked.mergeUsed = mergeUsed
	return forked.liftBlockGraph(block, byAddr, cloneVisited(visited), loop)
}

// tryLiftIfElseMerge lifts a conditional split whose two arms both
// eventually reconverge at a single shared block - the immediate
// post-dominator of the branch block, per the function's cfgAnalysis -
// as:
//
//	if (cond) { ...; goto L; } else { ...; goto L; }
//	L:;
//	<shared continuation, lifted exactly once>
//
// instead of the historical fallback, where each arm's own fork lifted
// the ENTIRE downstream graph itself (correct, but exponential in the
// number of sequential (even non-nested!) conditionals, and the reason
// a 400-line function's output could reach tens of megabytes).
//
// The shared continuation is lifted here in the PARENT lifter, from the
// register state as it was before the split. That loses any
// branch-specific register values the old per-fork duplication used to
// carry into the continuation, but without real phi-node/dataflow
// support there was never a sound way to merge two divergent per-arm
// states anyway; a single deterministic state is the honest
// approximation, and the explicit label/goto preserves the actual
// control flow exactly.
//
// Conservatively falls back (ok=false) whenever the shape isn't a clean
// one: no known ipdom, an ipdom that isn't a genuine multi-predecessor
// merge, an ipdom that is one of the branch's own direct successors or
// an enclosing loop's head/exit (loop/break/continue handling owns
// those), or neither arm actually reaching the merge. Every fallback
// keeps the old behavior, never a wrong guess.
func (l *lifter) tryLiftIfElseMerge(b *BasicBlock, cond ir.Expr, thenAddr, elseAddr uint64, byAddr map[uint64]*BasicBlock, visited map[uint64]bool, loop *loopCtx) ([]ir.Stmt, bool) {
	if l.cfg == nil {
		return nil, false
	}
	merge := l.cfg.ipdom[b.StartAddr]
	if merge == 0 || l.cfg.preds[merge] < 2 {
		// Standard post-dominance found no shared continuation - the
		// classic reason is one arm returning early, which leaves the
		// function exit as the only block all paths share. Fall back to
		// the looser, terminating-path-ignoring merge set before giving
		// up (see cfgAnalysis.partialIPDom's own doc comment).
		if alt := l.cfg.partialIPDom[b.StartAddr]; alt != 0 {
			merge = alt
		}
	}
	// Last resort for a split inside a do-while body whose arms both
	// eventually reach the loop's own tail (the condition check at the
	// end of the body): the tail is the natural shared continuation of
	// an if/else chain of option tests, even when a control-flow cycle
	// makes both post-dominator analyses above give up on it. Both arms
	// having a path to the tail is exactly the shape "each iteration
	// ends at the same condition check" the loop structure already
	// implies; arms that terminate instead simply never reach the
	// label, which is harmless.
	if (merge == 0 || l.cfg.preds[merge] < 2) && loop != nil && loop.doWhileTail != nil {
		if l.reachesAddr(thenAddr, loop.headAddr, byAddr, nil) &&
			l.reachesAddr(elseAddr, loop.headAddr, byAddr, nil) {
			merge = loop.headAddr
		}
	}
	// Real -O0 if/else-if chains - inside a loop OR at the top level -
	// have a case the two post-dominator analyses above cannot express:
	// each arm eventually exits or loops back instead of reconverging,
	// so the only standard post-dominator is some far-away join (or
	// none at all), even though the split's real shared continuation is
	// a plain nearby block (the next test link, an increment tail, ...).
	// findSharedMerge looks for that block directly - see its own doc
	// comment for why any genuinely shared reachable block is a sound
	// merge point. Do-while loops get the same treatment, EXCEPT that
	// their own tail (the condition check at the end of the body) stays
	// the preferred merge whenever it is still available: it is what
	// liftDoWhileTail needs to capture the loop's displayed condition,
	// so it is never overridden for anything else (only rescued when an
	// enclosing stop already owns it, in which case this split needs a
	// different shared block or the ordinary fallback).
	{
		_, stopOwned := l.stops[merge]
		mergeOwned := merge == 0 || l.cfg.preds[merge] < 2 || stopOwned
		if loop != nil && !(loop.doWhileTail != nil && merge == loop.headAddr && !stopOwned) {
			mergeOwned = mergeOwned ||
				merge == loop.headAddr || merge == loop.exitAddr ||
				(loop.joinAddr != 0 && merge == loop.joinAddr)
		}
		if mergeOwned {
			if m := l.findSharedMerge(thenAddr, elseAddr, byAddr, loop); m != 0 {
				merge = m
			}
		}
	}
	if merge == 0 || l.cfg.preds[merge] < 2 {
		return nil, false
	}
	// A merge that IS one of the two successors needs no special case:
	// ipdom/partialIPDom already guarantee that both arms reach it (the
	// arm starting at the merge itself is trivially there), liftLoopEdge
	// turns that arm into a single "goto <label>", and the merge and its
	// continuation are then lifted exactly once after the label. The one
	// visible cost is a redundant "else { goto L; }" when merge ==
	// elseAddr - still linear output, where falling back to the plain
	// if/else path would lift the ENTIRE downstream continuation
	// independently for BOTH arms (the duplication this whole merge
	// mechanism exists to prevent; on real code an early branch whose
	// merge is its fallthrough arm is extremely common, e.g. a function
	// whose prologue tests a flag and the not-taken side is the main
	// body).
	// If the merge is already owned by an ENCLOSING split's own stop
	// (same address), that outer label is where this continuation
	// belongs: nesting a new label+goto pair here would emit
	// "L:; goto L;" - an infinite loop in the generated source. Let the
	// ordinary if/else path run instead, whose arms inherit the outer
	// stop through liftLoopEdge's stops argument.
	if _, owned := l.stops[merge]; owned {
		return nil, false
	}
	// A do-while's "headAddr" IS its tail (the condition check at the
	// END of the body - see loopCtx.doWhileTail): a split inside the
	// body whose shared continuation is that tail is exactly the
	// common case (every arm of a chain of conditions rejoins at the
	// loop's increment/condition). It is a valid merge point here, and
	// the continuation after the label must go through
	// liftDoWhileTail so the loop's own condition still gets captured.
	// For every other enclosing loop address (a while-shape head, or
	// any loop's exit) break/continue handling owns the block instead.
	isTail := loop != nil && loop.doWhileTail != nil && merge == loop.headAddr
	if !isTail && loop != nil && (merge == loop.headAddr || merge == loop.exitAddr) {
		return nil, false
	}
	// The enclosing loop's own join block is not a valid if/else merge
	// point either: accepting it would emit the label (and lift the
	// entire post-loop continuation) INSIDE the loop body, with loop
	// context still active for everything after it - the two arms
	// instead leave via liftLoopEdge/liftBlockGraph's own join checks,
	// each emitting `goto <join label>`. See loopCtx.joinAddr's own doc
	// comment.
	if loop != nil && loop.joinAddr != 0 && merge == loop.joinAddr {
		return nil, false
	}
	mergeBlk, ok := byAddr[merge]
	if !ok {
		return nil, false
	}

	key := mergeShareKey{addr: merge}
	if loop != nil {
		key.loopHead = loop.headAddr
	}
	label, shared := l.mergeLabels[key]
	if !shared {
		label = fmt.Sprintf("L_%x_%d", merge, l.nextLabel())
		l.mergeLabels[key] = label
	}
	used := false
	// Inherit any enclosing stops (see liftBlockGraph's own stop check)
	// and add this split's own merge - an arm that hits an enclosing
	// stop must still jump there rather than walk past it.
	stop := make(map[uint64]string, len(l.stops)+1)
	for addr, lbl := range l.stops {
		stop[addr] = lbl
	}
	stop[merge] = label
	thenStmts := l.liftLoopEdge(thenAddr, byAddr, visited, loop, stop, &used)
	elseStmts := l.liftLoopEdge(elseAddr, byAddr, visited, loop, stop, &used)
	if !used {
		// Neither arm reaches the merge at all (both end in
		// returns/unresolved tail calls): there is no shared
		// continuation to lift, and the ordinary if/else handles the
		// arms identically. The forked arm lifters above are discarded
		// untouched - fork() only copies state, so l itself is
		// unaffected (apart from the shared budget). A claim this call
		// made itself is released again so a later split that does
		// reach the merge can own the label.
		if !shared {
			delete(l.mergeLabels, key)
		}
		return nil, false
	}

	stmts := []ir.Stmt{&ir.IfStmt{
		Cond: cond,
		Then: &ir.Block{Statements: thenStmts},
		Else: &ir.Block{Statements: elseStmts},
	}}
	if shared {
		// An earlier split already claimed this merge: it emitted the
		// label and lifted the shared continuation exactly once, and
		// both arms above simply jump there. Emitting a second label
		// and a second copy of the continuation here is precisely the
		// per-split tail duplication mergeLabels exists to prevent.
		return stmts, true
	}
	stmts = append(stmts, &ir.LabelStmt{Name: label})
	if isTail {
		stmts = append(stmts, l.liftDoWhileTail(loop, byAddr)...)
		return stmts, true
	}
	stmts = append(stmts, l.liftBlockGraph(mergeBlk, byAddr, visited, loop)...)
	return stmts, true
}

// liftDoWhileTail lifts a do-while loop's own tail block (loop.headAddr,
// per doWhileTail's own doc comment) from whichever path just reached
// it - either the plain single-successor "falls straight into it" case
// in liftBlockGraph, or one arm of an if/else in liftLoopEdge (that
// arm's own explicit "continue", which still needs the tail's
// instructions to actually run before the loop re-checks its
// condition). Every reaching path independently runs its own copy of
// the tail's instructions (consistent with how any other merge point
// in this file is handled - see liftBlockGraph's own reasoning on why
// each fork lifts a shared block with its own register state), but
// only the FIRST one (per doWhileTailState's own doc comment) captures
// its lifted condition as the loop's own displayed Cond.
func (l *lifter) liftDoWhileTail(loop *loopCtx, byAddr map[uint64]*BasicBlock) []ir.Stmt {
	tail, ok := byAddr[loop.headAddr]
	if !ok || tail.LastCond == nil || len(tail.Succs) != 2 {
		return nil
	}
	stmts := l.run(tail.Instructions[:len(tail.Instructions)-1])
	cond := l.liftCondition(*tail.LastCond)
	// liftCondition lifts the condition for entering Succs[0] (branch
	// taken) as-is - see its own doc comment. If Succs[0] is instead the
	// loop's EXIT (i.e. the back-edge to the body is on Succs[1], the
	// branch-NOT-taken/fallthrough arm), the real "while (cond)"
	// condition (true means keep looping) is cond's negation.
	if tail.Succs[0] == loop.exitAddr {
		cond = &ir.UnaryExpr{Op: "!", Expr: cond}
	}
	if !loop.doWhileTail.captured {
		loop.doWhileTail.captured = true
		loop.doWhileTail.cond = cond
	}
	return append(stmts, l.flushRemaining()...)
}

// reachesAddr reports whether target is reachable from startAddr by
// following successor edges through byAddr - a plain breadth-first
// search over the CFG, used only to answer "does this path loop back
// to the block we started from" (see tryLiftWhileLoop), not to lift
// anything. The search draws from l.searchBudget (see its own doc
// comment): a function shouldn't get an unbounded amount of extra work
// from every candidate loop shape trying two of these - exhausting the
// search budget here simply answers false (safe: the caller falls back to
// treating the block as an ordinary if/else, never a crash or a hang,
// and never a truncated lift - the lift budget is a separate counter
// precisely so searches cannot starve it).
//
// boundary, when non-nil, is the loop context ALREADY active where
// this search began (tryLiftWhileLoop's own outerLoop) - reaching
// boundary's own head or exit address stops that path from expanding
// any further (though it's still checked against target first, same
// as any other address). Without this, checking whether some inner
// conditional's branch loops back to ITSELF would wrongly see right
// through an ordinary continue/break for the ALREADY-active outer
// loop (which, being an active loop, naturally cycles back through
// its own body eventually) and conclude the inner branch loops back
// to itself too - misreading a plain "if (x) continue;" nested inside
// an outer loop as the head of a brand new (and nonexistent) loop of
// its own.
func (l *lifter) reachesAddr(startAddr, target uint64, byAddr map[uint64]*BasicBlock, boundary *loopCtx) bool {
	seen := map[uint64]bool{}
	queue := []uint64{startAddr}
	for len(queue) > 0 {
		if *l.searchBudget <= 0 {
			return false
		}
		*l.searchBudget--
		addr := queue[0]
		queue = queue[1:]
		if addr == target {
			return true
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		if boundary != nil && (addr == boundary.headAddr || addr == boundary.exitAddr) {
			continue
		}
		if blk, ok := byAddr[addr]; ok {
			queue = append(queue, blk.Succs...)
		}
	}
	return false
}

// bfsShared returns each block address reachable from start without
// crossing out of the current split region, mapped to its BFS depth
// from start (minimum successor-edge count). A region boundary is
// either the enclosing loop's own head/exit/join (see loopCtx.joinAddr)
// or any block an enclosing split already owns as a stop (l.stops):
// paths crossing those have left the region by definition, and the
// boundary block itself is included in the result (a caller can see an
// arm terminates there) but never expanded past. loop may be nil (a
// split outside any loop), in which case only the stop boundaries
// apply. Draws from l.searchBudget like every other speculative search
// in this file; exhaustion simply returns a partial map, always safe
// for the same reason (see reachesAddr's doc comment).
func (l *lifter) bfsShared(start uint64, byAddr map[uint64]*BasicBlock, loop *loopCtx) map[uint64]int {
	depth := map[uint64]int{}
	queue := []uint64{start}
	depth[start] = 0
	for len(queue) > 0 {
		if *l.searchBudget <= 0 {
			return depth
		}
		*l.searchBudget--
		addr := queue[0]
		queue = queue[1:]
		if loop != nil && (addr == loop.headAddr || addr == loop.exitAddr || (loop.joinAddr != 0 && addr == loop.joinAddr)) {
			continue
		}
		if _, owned := l.stops[addr]; owned {
			continue
		}
		blk, ok := byAddr[addr]
		if !ok {
			continue
		}
		for _, s := range blk.Succs {
			if _, seen := depth[s]; !seen {
				depth[s] = depth[addr] + 1
				queue = append(queue, s)
			}
		}
	}
	return depth
}

// findSharedMerge finds the nearest block both arms of a split can
// reach WITHOUT crossing out of the current split region (see
// bfsShared): the common block with the smallest summed BFS depth from
// thenAddr and elseAddr. Unlike standard post-dominance (or
// partial-post-dominance) this deliberately treats reaching the
// enclosing loop's own head/exit/join, or an enclosing split's stop,
// as "left the region, not a coincidence": the two arms of an ordinary
// compiled if/else-if chain very often share only a plain continuation
// block (the increment tail, the next test link) because some arm
// eventually exits or loops back instead, which is exactly the case
// ipdom resolves to a far-away join (or nothing at all) and cannot
// tell apart from a genuine outer merge.
//
// Soundness does not depend on the pick being the *immediate*
// post-dominator: tryLiftIfElseMerge's label/goto form is correct for
// ANY block both arms actually reach - each arm simply stops there, and
// a path that instead hits an enclosing loop's own head/exit/join or an
// enclosing stop is intercepted by that boundary's own handling first.
// The nearest shared block just keeps the emitted continuation as small
// as possible.
func (l *lifter) findSharedMerge(thenAddr, elseAddr uint64, byAddr map[uint64]*BasicBlock, loop *loopCtx) uint64 {
	thenDepth := l.bfsShared(thenAddr, byAddr, loop)
	elseDepth := l.bfsShared(elseAddr, byAddr, loop)
	if len(thenDepth) == 0 || len(elseDepth) == 0 {
		return 0
	}
	best, bestScore := uint64(0), 0
	for addr, dt := range thenDepth {
		de, ok := elseDepth[addr]
		if !ok {
			continue
		}
		if loop != nil && (addr == loop.headAddr || addr == loop.exitAddr || (loop.joinAddr != 0 && addr == loop.joinAddr)) {
			continue
		}
		if _, owned := l.stops[addr]; owned {
			continue
		}
		if _, exists := byAddr[addr]; !exists {
			continue
		}
		if l.cfg != nil && l.cfg.preds[addr] < 2 {
			continue
		}
		score := dt + de
		if best == 0 || score < bestScore || (score == bestScore && addr < best) {
			best, bestScore = addr, score
		}
	}
	return best
}

// isPlainConditionLink reports whether blk has the exact minimal shape
// a real compiler ever emits for one extra link in a short-circuit
// "&&"/"||" chain: nothing but a single condition test, with no other
// work at all - either just the conditional branch itself (cbz/cbnz/
// tbz/tbnz, which test a register directly), or a "cmp" immediately
// followed by the branch (b.cond, which needs the cmp to set the
// flags it tests). Requiring this exact shape (checked by
// tryOrChainLink before it commits to treating a block as a chain
// link at all) is what keeps this from ever misreading real BODY code
// that happens to contain its own if/branch as "more of the
// condition" instead - genuine body code essentially always does
// something (a call, a store, arithmetic) beyond a bare test.
func isPlainConditionLink(blk *BasicBlock) bool {
	switch len(blk.Instructions) {
	case 1:
		return true
	case 2:
		return blk.Instructions[0].Mnemonic == "cmp"
	default:
		return false
	}
}

// tryOrChainLink attempts to extend a short-circuit "a || b (|| c ...)"
// while-condition by treating addr as one more condition test: addr
// must be a fresh isPlainConditionLink block whose own two successors
// split cleanly into "reaches back to headAddr" (continuing the loop -
// either straight into the real body, or into yet another link - see
// below) and "does not" (a candidate real exit) - the exact same
// non-ambiguous shape tryLiftWhileLoop's own first two cases already
// require, just checked against addr instead of head.
//
// A third possibility - BOTH of addr's own successors also reach back
// to headAddr - means addr is itself just another ambiguous link in a
// deeper chain (the exact shape that got tryLiftWhileLoop's caller
// here in the first place), so this recurses into itself on addr's own
// "reaches back" successor rather than giving up, extending the "||"
// one level further - handling any chain depth, not just one extra
// link, through repeated application of this same case. Tries addr's
// own Succs[1] arm first (the far more common compiled orientation -
// see tryLiftWhileLoop's own doc comment on why - then Succs[0]) at
// every level, before concluding the chain doesn't extend cleanly from
// here.
//
// Falls back to ok=false whenever the shape doesn't hold at any level -
// an irregular shape, a genuine body block, or simply nothing left to
// find - so the caller (tryLiftWhileLoop, or this function's own
// recursive caller one level up) falls back to treating the loop as an
// ordinary if/else, always a safe default (never a wrong guess, and
// never lossy: see liftBlockGraph's own flush-on-already-visited
// handling).
//
// Side effects (running a link's own instructions and lifting its
// condition, which can consume registers / touch l.lastCmp) only
// happen once THAT link's shape is confirmed clean, working outward
// from the deepest successful link back to the shallowest - never on a
// path that's about to return ok=false - so a caller trying a second
// candidate address after this one fails is never working with a
// partially-mutated l. No explicit recursion-depth limit: an
// arbitrarily long real "a || b || c || ..." chain is just as valid to
// recognize as a short one, and l.searchBudget (shared with every other
// speculative search in this file - see reachesAddr's own doc comment)
// already bounds the total work regardless of how deep this goes.
func (l *lifter) tryOrChainLink(headAddr, addr uint64, byAddr map[uint64]*BasicBlock, outerLoop *loopCtx) (cond ir.Expr, bodyAddr, exitAddr uint64, ok bool) {
	blk, exists := byAddr[addr]
	if !exists || blk.LastCond == nil || len(blk.Succs) != 2 || !isPlainConditionLink(blk) {
		return nil, 0, 0, false
	}
	t, e := blk.Succs[0], blk.Succs[1]
	tLoops := l.reachesAddr(t, headAddr, byAddr, outerLoop)
	eLoops := l.reachesAddr(e, headAddr, byAddr, outerLoop)
	switch {
	case tLoops && !eLoops:
		l.run(blk.Instructions[:len(blk.Instructions)-1])
		return l.liftCondition(*blk.LastCond), t, e, true
	case eLoops && !tLoops:
		l.run(blk.Instructions[:len(blk.Instructions)-1])
		return &ir.UnaryExpr{Op: "!", Expr: l.liftCondition(*blk.LastCond)}, e, t, true
	case tLoops && eLoops:
		if subCond, subBody, subExit, ok := l.tryOrChainLink(headAddr, e, byAddr, outerLoop); ok {
			l.run(blk.Instructions[:len(blk.Instructions)-1])
			return &ir.BinaryExpr{Op: "||", Left: l.liftCondition(*blk.LastCond), Right: subCond}, subBody, subExit, true
		}
		if subCond, subBody, subExit, ok := l.tryOrChainLink(headAddr, t, byAddr, outerLoop); ok {
			l.run(blk.Instructions[:len(blk.Instructions)-1])
			cond := &ir.UnaryExpr{Op: "!", Expr: l.liftCondition(*blk.LastCond)}
			return &ir.BinaryExpr{Op: "||", Left: cond, Right: subCond}, subBody, subExit, true
		}
		return nil, 0, 0, false
	default:
		return nil, 0, 0, false
	}
}

// tryLiftWhileLoop attempts to recognize head (a block ending in the
// conditional branch already lifted into cond, with thenAddr/elseAddr
// as its two successors - Succs[0]/Succs[1], per BasicBlock.Succs' own
// doc comment) as the standard -O0 "while (cond) { body }" shape:
// exactly one of the two successors can reach back to head itself by
// SOME path (via reachesAddr - the body, which may freely contain its
// own nested control flow, unlike a straight-line-only chain), while
// the other cannot (what runs after the loop exits).
//
// A compiled "a && b (&& ...)" while-condition never reaches this
// ambiguous case at all: only ONE of head's two successors ever
// reaches back (the "keep testing" arm - the OTHER test, then
// eventually the body), while the other is a clean, non-looping exit;
// each further "&&" link is then just an ordinary nested conditional
// found while lifting what looks like "the body" (see
// liftBlockGraph's own if/else case, which tries THIS function again
// for it) - no special handling needed here at all.
//
// "a || b (|| c ...)" is different: head's DIRECT short-circuit entry
// into the body loops back just like the body itself does, so BOTH
// successors satisfy reachesAddr, and tryOrChainLink is what
// disambiguates which one is really "one more condition to fold in
// with ||" versus the real body - recursing into itself for a 3+-deep
// chain (see its own doc comment), so any real chain depth folds into
// a single "||"-chained condition here, not just one extra link. If
// that fails too (an irregular shape this project doesn't otherwise
// have a name for), this returns ok=false so the caller (liftBlockGraph)
// falls back to treating it as an ordinary if/else - always a safe
// default (never a wrong guess, and never lossy: see liftBlockGraph's
// own flush-on-already-visited handling), just not as pretty as a real
// "while" would be.
//
// outerLoop is whatever loop context liftBlockGraph itself was already
// lifting inside of (nil at the top level) - threaded through to the
// exit continuation below (which resumes THAT context, not this loop's
// own), so a break/continue appearing after this loop, but still
// inside an enclosing one, still resolves correctly.
func (l *lifter) tryLiftWhileLoop(head *BasicBlock, cond ir.Expr, thenAddr, elseAddr uint64, byAddr map[uint64]*BasicBlock, visited map[uint64]bool, outerLoop *loopCtx) ([]ir.Stmt, bool) {
	thenLoops := l.reachesAddr(thenAddr, head.StartAddr, byAddr, outerLoop)
	elseLoops := l.reachesAddr(elseAddr, head.StartAddr, byAddr, outerLoop)

	var bodyAddr, exitAddr uint64
	var whileCond ir.Expr
	switch {
	case thenLoops && !elseLoops:
		// Branch-taken enters the body - cond (as lifted, for entering
		// Succs[0] - see liftCondition's own doc comment) IS the
		// while-condition as-is.
		bodyAddr, exitAddr, whileCond = thenAddr, elseAddr, cond
	case elseLoops && !thenLoops:
		// Fallthrough enters the body - the branch-taken path is the
		// EXIT, so entering the body means the branch was NOT taken:
		// the real while-condition is cond's negation.
		bodyAddr, exitAddr, whileCond = elseAddr, thenAddr, &ir.UnaryExpr{Op: "!", Expr: cond}
	case thenLoops && elseLoops:
		// The short-circuit "a || b" shape - see this function's own
		// doc comment. Try elseAddr as the extra link first (the
		// far-more-common compiled orientation: branch-taken enters
		// the body directly, fallthrough continues testing), then
		// thenAddr (the mirror image), before giving up.
		if subCond, subBody, subExit, ok := l.tryOrChainLink(head.StartAddr, elseAddr, byAddr, outerLoop); ok {
			bodyAddr, exitAddr, whileCond = subBody, subExit, &ir.BinaryExpr{Op: "||", Left: cond, Right: subCond}
		} else if subCond, subBody, subExit, ok := l.tryOrChainLink(head.StartAddr, thenAddr, byAddr, outerLoop); ok {
			bodyAddr, exitAddr, whileCond = subBody, subExit, &ir.BinaryExpr{Op: "||", Left: &ir.UnaryExpr{Op: "!", Expr: cond}, Right: subCond}
		} else {
			return nil, false
		}
	default:
		return nil, false
	}

	bodyBlock, ok := byAddr[bodyAddr]
	if !ok {
		return nil, false
	}

	// Identify the loop's post-exit join: the block the CFG says EVERY
	// path from the head must eventually reach (cfgAnalysis.ipdom) -
	// where all of the loop's exits, not just the primary exitAddr,
	// reconverge. A walk still inside the loop that reaches it is
	// leaving the loop by some other route (a second exit edge, or a
	// split arm whose merge lies past the loop); without treating it as
	// a stop, such a walk lifts the whole post-loop continuation inline
	// INSIDE the loop body, and every fork repeats that - the exact
	// duplicated-output blowup loopCtx.joinAddr's own doc comment
	// describes. joinAddr == 0 (no join, e.g. no reconvergence, or an
	// enclosing split already owns that block as its own stop) just
	// disables the mechanism and keeps the historical behavior.
	joinAddr, joinLabel := uint64(0), ""
	if l.cfg != nil {
		if j := l.cfg.ipdom[head.StartAddr]; j != 0 && j != head.StartAddr && j != bodyAddr && j != exitAddr && l.cfg.preds[j] >= 2 {
			if _, owned := l.stops[j]; !owned {
				joinAddr = j
				joinLabel = fmt.Sprintf("L_%x_%d", j, l.nextLabel())
			}
		}
	}

	// The body is lifted with its own forked lifter, exactly like an
	// if/else branch (see liftBlockGraph's own reasoning): its
	// register writes are per-iteration state that must not leak into
	// what runs after the loop, which continues below from head's OWN
	// (pre-loop) state - the simplest sound-enough approximation
	// available without real per-iteration dataflow/fixpoint analysis
	// of what's actually in each register after zero-or-more
	// iterations. Recursing into liftBlockGraph itself (rather than a
	// specialized straight-line-only walk) is what lets the body
	// contain its own nested if/else or loops for free; the new
	// loopCtx is what turns a path back to head, or out to exitAddr,
	// into a continue/break instead of ordinary (or blocked-by-
	// visited) control flow.
	bodyLifter := l.fork()
	bodyStmts := bodyLifter.liftBlockGraph(bodyBlock, byAddr, cloneVisited(visited), &loopCtx{headAddr: head.StartAddr, exitAddr: exitAddr, joinAddr: joinAddr, joinLabel: joinLabel})
	// The body's natural end (reaching head again via the plain
	// single-successor path - see liftBlockGraph's own note on why
	// that's implicit, unlike an explicit continue) is NOT treated as
	// a leaf by liftBlockGraph's own leaf-flush logic (head's block
	// technically exists in byAddr - recursing into it just returns
	// nil because it's already visited, not because there's no
	// successor at all) - so any call the body's own top-level
	// straight-line run left unconsumed still needs flushing here,
	// exactly like LiftFunction/liftBlockGraph do at every OTHER real
	// leaf. Harmless (a no-op) when the body's own internal recursion
	// already flushed everything itself - e.g. a body that's an
	// if/else at its own top level already flushes its own bodyInsns
	// before splitting (see liftBlockGraph's if/else case).
	bodyStmts = append(bodyStmts, bodyLifter.flushRemaining()...)

	stmts := []ir.Stmt{&ir.WhileStmt{Cond: whileCond, Body: &ir.Block{Statements: bodyStmts}}}
	if exitBlock, ok := byAddr[exitAddr]; ok {
		if joinAddr != 0 {
			// Lift the primary exit path with the join active so it
			// itself stops (goto) at the join instead of walking
			// through it; the join block's continuation is then lifted
			// exactly once, after the label, in the OUTER context -
			// never the loop's own (see loopCtx.joinAddr's doc
			// comment). The outer context is preserved because the
			// primary exit path may still resolve to an enclosing
			// loop's continue/break.
			contCtx := &loopCtx{}
			if outerLoop != nil {
				*contCtx = *outerLoop
			}
			contCtx.joinAddr = joinAddr
			contCtx.joinLabel = joinLabel
			stmts = append(stmts, l.liftBlockGraph(exitBlock, byAddr, visited, contCtx)...)
			stmts = append(stmts, &ir.LabelStmt{Name: joinLabel})
			if joinBlk, ok := byAddr[joinAddr]; ok {
				stmts = append(stmts, l.liftBlockGraph(joinBlk, byAddr, visited, outerLoop)...)
			}
		} else {
			stmts = append(stmts, l.liftBlockGraph(exitBlock, byAddr, visited, outerLoop)...)
		}
	}
	return stmts, true
}

// tryLiftDoWhileLoop attempts to recognize b as the entry of a
// do/for-shaped loop: one compiled with the condition check at the END
// of the body (real "do { body } while (cond);" source, and some -O0
// for/while lowerings that reuse this same shape) rather than the
// front, which tryLiftWhileLoop already handles. This must be tried
// BEFORE b's own instructions are lifted at all - unlike a while-shape
// loop, where the head block's conditional branch itself is the signal
// that something might be a loop, a do-while's body starts running
// immediately at b with no branch of its own, and the only sign it was
// a loop all along is a LATER block's back-edge pointing here. By the
// time an ordinary straight-line walk reached that later block, b (and
// anything between) would already be flattened into the caller's own
// stmts and marked visited - too late to retroactively wrap.
//
// findDoWhileTail (a pure structural search, no side effects) locates
// the loop's own tail block - unlike the body itself, which can freely
// contain its own nested if/else, break/continue, or nested loops (see
// below), this search doesn't need to understand any of that: it just
// needs the ONE address a genuine back-edge to b.StartAddr lands on,
// wherever in the reachable subgraph that turns out to be.
//
// Once found, the body (b through the tail, exclusive of the tail's
// own trailing branch) is lifted with a forked lifter using the SAME
// liftBlockGraph/liftLoopEdge machinery a while-shape loop's body
// already uses, via a loopCtx whose headAddr is the TAIL's address
// (not b's) - see loopCtx.doWhileTail's own doc comment for why
// reaching it needs different handling than an ordinary while-shape
// head. This is what lets a do-while body contain its own nested
// if/else, break/continue, or nested loops for free, exactly like a
// while-shape body already does.
//
// Falls back to ok=false - b lifted by the ordinary straight-line/
// if-else path exactly as before this feature existed - whenever no
// such tail is reachable at all, identical to how every other
// loop-shape heuristic in this file falls back when it doesn't
// recognize a shape.
//
// When b itself ends in a conditional branch, this must defer entirely
// to the ordinary if/else dispatch (which tries tryLiftWhileLoop) for
// the standard, UNAMBIGUOUS while-shape - exactly one of b's own two
// arms eventually reaching back to b - rather than attempt its own
// search: reaching a nested "if (x) continue;" further into what's
// really that while-loop's own body would otherwise look identical to
// a genuine do-while tail (both are "some block whose one arm branches
// straight back to b.StartAddr"), and findDoWhileTail's own visited-
// exclusion rule doesn't disambiguate this specific case (b hasn't
// been marked visited yet - this check runs before that happens). The
// one exception is a DIRECT self-edge (one of b's own arms targets
// b.StartAddr itself, not merely some block that eventually reaches
// it) - unambiguously a single-block do-while, since no real
// while-loop's condition check ever branches straight back to its own
// start with zero intervening body instructions. Otherwise, proceed
// only when b's own two arms are BOTH ambiguous in the same way
// tryLiftWhileLoop's own "||" case already is (neither alone
// distinguishes a real exit) - the shape produced when a do-while's
// body starts with its own if/else, both arms eventually reconverging
// at the shared tail.
func (l *lifter) tryLiftDoWhileLoop(b *BasicBlock, byAddr map[uint64]*BasicBlock, visited map[uint64]bool, outerLoop *loopCtx) ([]ir.Stmt, bool) {
	if b.LastCond != nil && len(b.Succs) == 2 && b.Succs[0] != b.StartAddr && b.Succs[1] != b.StartAddr {
		thenLoops := l.reachesAddr(b.Succs[0], b.StartAddr, byAddr, outerLoop)
		elseLoops := l.reachesAddr(b.Succs[1], b.StartAddr, byAddr, outerLoop)
		if thenLoops != elseLoops {
			return nil, false
		}
	}

	tailAddr, exitAddr, ok := l.findDoWhileTail(b.StartAddr, byAddr, visited, outerLoop)
	if !ok {
		return nil, false
	}

	// The body is lifted with its own forked lifter, exactly like a
	// while-shape loop's body (see tryLiftWhileLoop's own reasoning):
	// its register writes are per-iteration state that must not leak
	// into what runs after the loop, which continues below from l's OWN
	// (pre-loop) state.
	bodyLifter := l.fork()
	tailState := &doWhileTailState{}
	loop := &loopCtx{headAddr: tailAddr, exitAddr: exitAddr, doWhileTail: tailState}
	// liftBlockGraphDispatch, not liftBlockGraph, for this specific
	// call: b was already confirmed fresh (not yet visited) by our own
	// caller, and going through liftBlockGraph here would re-run this
	// very function's own do-while pre-check on b - see
	// liftBlockGraphDispatch's own doc comment.
	bodyVisited := cloneVisited(visited)
	bodyVisited[b.StartAddr] = true
	bodyStmts := bodyLifter.liftBlockGraphDispatch(b, byAddr, bodyVisited, loop)
	// Same reasoning as tryLiftWhileLoop's own trailing flush: the
	// body's natural end (reaching the tail via the plain
	// single-successor path) already flushes via liftDoWhileTail, but a
	// body that's itself an if/else at its own top level needs this
	// too, for the same reason tryLiftWhileLoop's own body does.
	bodyStmts = append(bodyStmts, bodyLifter.flushRemaining()...)

	if !tailState.captured {
		// The tail was found structurally reachable but never actually
		// reached while lifting (budget exhaustion mid-traversal, most
		// likely) - without a real Cond to show, fall back rather than
		// emit a loop with a placeholder condition.
		return nil, false
	}

	stmts := []ir.Stmt{&ir.DoWhileStmt{Cond: tailState.cond, Body: &ir.Block{Statements: bodyStmts}}}
	if exitBlock, ok := byAddr[exitAddr]; ok {
		stmts = append(stmts, l.liftBlockGraph(exitBlock, byAddr, visited, outerLoop)...)
	}
	return stmts, true
}

// findDoWhileTail performs a pure (no side effects) breadth-first
// search of the blocks reachable from bodyStart, looking for a block
// whose own conditional branch has exactly one successor equal to
// bodyStart itself (the natural repeat) and one that ISN'T reachable
// back to bodyStart by any path either (a genuine, unambiguous exit) -
// the defining shape of a do-while's tail, wherever in the body's own
// internal control flow it turns out to sit. Ordinary internal
// conditionals (an if/else with neither arm looping back to bodyStart)
// and nested loops (whose own back-edges target some OTHER address,
// not bodyStart) are simply expanded through rather than mistaken for
// the tail - only a clean, unambiguous match ends the search.
//
// The "other arm must not also reach bodyStart" requirement matters
// for a shape this search would otherwise misread: an ordinary nested
// "if (x) continue;" INSIDE an already-while-shaped loop's own body
// has one arm branching straight back to bodyStart too (that's what
// "continue" compiles to) - but unlike a genuine tail, its OTHER arm
// (falling through to the rest of the body) also eventually cycles
// back to bodyStart via the loop's own natural repeat, which a clean
// tail's real exit never does. Rejecting that case here is what leaves
// it for tryLiftWhileLoop/liftLoopEdge to correctly recognize as an
// ordinary nested continue instead.
//
// Draws from l.searchBudget, the counter shared with reachesAddr's own
// BFS and deliberately separate from liftBlockGraph's lift budget (see
// searchBudget's own doc comment): exhausting it here simply answers
// ok=false, safe for the same reason - the caller falls back to lifting
// b as an ordinary block, never a crash, a hang, or a truncated lift.
// outerLoop is passed through to reachesAddr as its own boundary
// parameter, for the same reason tryLiftWhileLoop passes it to its own
// reachesAddr calls (see reachesAddr's own doc comment).
//
// visited matters here in a way the above doesn't quite cover: this
// search is tried at EVERY liftBlockGraph call, including one lifting
// a block that's already inside an enclosing loop's own body-fork
// (e.g. bodyStart being a while-shape loop's own body block, whose
// head - already fully accounted for by that OUTER loop - naturally
// has an edge back into bodyStart, since that's exactly what "loop
// back to re-check the condition" looks like from the body's own
// side). Without excluding already-visited blocks, that would look
// identical to a genuine do-while tail rooted at bodyStart and wrongly
// re-claim the outer loop's own head as if it belonged to a brand new,
// nonexistent do-while - so any address already spoken for by an
// enclosing context is a dead end here, never a candidate tail and
// never expanded past.
func (l *lifter) findDoWhileTail(bodyStart uint64, byAddr map[uint64]*BasicBlock, visited map[uint64]bool, outerLoop *loopCtx) (tailAddr, exitAddr uint64, ok bool) {
	seen := map[uint64]bool{}
	queue := []uint64{bodyStart}
	for len(queue) > 0 {
		if *l.searchBudget <= 0 {
			return 0, 0, false
		}
		*l.searchBudget--
		addr := queue[0]
		queue = queue[1:]
		if seen[addr] {
			continue
		}
		seen[addr] = true
		if addr != bodyStart && visited[addr] {
			continue
		}
		blk, exists := byAddr[addr]
		if !exists {
			continue
		}
		if blk.LastCond != nil && len(blk.Succs) == 2 {
			switch {
			case blk.Succs[0] == bodyStart && blk.Succs[1] != bodyStart && !l.reachesAddr(blk.Succs[1], bodyStart, byAddr, outerLoop):
				return blk.StartAddr, blk.Succs[1], true
			case blk.Succs[1] == bodyStart && blk.Succs[0] != bodyStart && !l.reachesAddr(blk.Succs[0], bodyStart, byAddr, outerLoop):
				return blk.StartAddr, blk.Succs[0], true
			}
		}
		queue = append(queue, blk.Succs...)
	}
	return 0, 0, false
}

// fork returns a new lifter that inherits this lifter's current
// register/stack state as of the branch point, but can diverge from it
// independently - needed because the then/else branches of an if
// statement each continue from the SAME starting state (the condition
// hasn't told either branch anything about what's in which register
// beyond the branch itself) but may each assign registers differently
// from that point on, and those assignments must not leak into the
// other branch or back into the parent.
// cloneVisited returns a shallow copy of a visited-block-address set,
// so a branch's own traversal doesn't share mutations with a sibling
// branch's traversal (see liftBlockGraph's if/else case for why this
// matters).
func cloneVisited(visited map[uint64]bool) map[uint64]bool {
	out := make(map[uint64]bool, len(visited))
	for k, v := range visited {
		out[k] = v
	}
	return out
}

func (l *lifter) fork() *lifter {
	regs := make(map[string]ir.Expr, len(l.regs))
	for k, v := range l.regs {
		regs[k] = v
	}
	stack := make(map[int32]string, len(l.stack))
	for k, v := range l.stack {
		stack[k] = v
	}
	stackWidth := make(map[int32]int, len(l.stackWidth))
	for k, v := range l.stackWidth {
		stackWidth[k] = v
	}
	stackTyped := make(map[int32]bool, len(l.stackTyped))
	for k, v := range l.stackTyped {
		stackTyped[k] = v
	}
	calls := make([]ir.Expr, len(l.calls))
	copy(calls, l.calls)
	consumed := make(map[ir.Expr]bool, len(l.consumed))
	for k, v := range l.consumed {
		consumed[k] = v
	}
	resultRegs := make(map[string]bool, len(l.resultRegs))
	for k, v := range l.resultRegs {
		resultRegs[k] = v
	}
	addrRegs := make(map[string]uint64, len(l.addrRegs))
	for k, v := range l.addrRegs {
		addrRegs[k] = v
	}
	written := make(map[string]bool, len(l.written))
	for k, v := range l.written {
		written[k] = v
	}
	seedRefs := make(map[string]ir.Expr, len(l.seedRefs))
	for k, v := range l.seedRefs {
		seedRefs[k] = v
	}
	regWidths := make(map[string]int, len(l.regWidths))
	for k, v := range l.regWidths {
		regWidths[k] = v
	}
	return &lifter{regs: regs, stack: stack, stackWidth: stackWidth, stackTyped: stackTyped, params: l.params, lastCmp: l.lastCmp, resolver: l.resolver, strings: l.strings, addrRegs: addrRegs, calls: calls, consumed: consumed, resultRegs: resultRegs, budget: l.budget, searchBudget: l.searchBudget, dataReader: l.dataReader, cfg: l.cfg, stops: l.stops, mergeUsed: l.mergeUsed, labelSeq: l.labelSeq, mergeLabels: l.mergeLabels, opts: l.opts, thisType: l.thisType, regNames: l.regNames, regSeq: l.regSeq, simdSeq: l.simdSeq, x29Offset: l.x29Offset, x29Known: l.x29Known, functionInsns: l.functionInsns, insnIndex: l.insnIndex, functionStart: l.functionStart, functionEnd: l.functionEnd, outlinedDepth: l.outlinedDepth, written: written, seedRefs: seedRefs, regWidths: regWidths}
}

// liftCondition lifts a conditional branch instruction (b.cond or
// cbz/cbnz) into the IR condition expression for entering the
// BRANCH-TAKEN path (Succs[0] - see BasicBlock.Succs' doc comment) -
// i.e. the condition as the instruction's own mnemonic states it, not
// inverted. This mirrors how this project's JVM-side buildCondition
// works: the raw branch instruction's condition is what's true when
// the branch is taken: building the caller's if/else around
// Succs[0]-as-then means using that condition directly, with no extra
// negation needed (unlike a few of the JVM-side matchers, which build
// a condition for entering an ordinary if's THEN when the underlying
// bytecode branch jumps AWAY from it - ARM64's conditional branches
// jumping TOWARD the branch-taken block is the more direct case).
func (l *lifter) liftCondition(inst native.DetailedInstruction) ir.Expr {
	switch inst.Mnemonic {
	case "cbz", "cbnz":
		// Unlike b.cond, cbz/cbnz test their OWN register operand
		// directly against zero - there's no preceding "cmp" to read
		// (see cmpOperands' own doc comment for why b.cond needs one
		// and this doesn't).
		if len(inst.Operands) == 0 || inst.Operands[0].Type != native.OperandReg {
			return &ir.LocalVar{Name: "cond"}
		}
		val := l.regValue(inst.Operands[0].Reg)
		l.consume(val)
		// A value that is itself already a boolean expression (a
		// comparison installed by cset/ccmp, a logical combination, a
		// negation) is nonzero exactly when true, so testing it is the
		// expression directly (cbnz) or its negation (cbz). Rewrapping
		// as "<expr> != 0" / "<expr> == 0" is redundant and, for a
		// comparison-valued register, renders as the misleading chained
		// "a == b != 0" this whole case exists to avoid.
		if isBooleanExpr(val) {
			if inst.Mnemonic == "cbnz" {
				return val
			}
			return &ir.UnaryExpr{Op: "!", Expr: val}
		}
		op := "=="
		if inst.Mnemonic == "cbnz" {
			op = "!="
		}
		return &ir.BinaryExpr{Op: op, Left: val, Right: &ir.IntLit{Value: 0}}
	case "tbz", "tbnz":
		// Like cbz/cbnz, tbz/tbnz test their own operand directly -
		// no preceding "cmp" to read - but only a single bit of it
		// ("tbz Rt, #bit, #target": branch when bit #bit of Rt is
		// clear; tbnz when it's set), lifted as the same bit-test
		// expression a real "if (x & (1 << bit))" would use in C.
		if len(inst.Operands) < 2 || inst.Operands[0].Type != native.OperandReg || inst.Operands[1].Type != native.OperandImm {
			return &ir.LocalVar{Name: "cond"}
		}
		val := l.regValue(inst.Operands[0].Reg)
		l.consume(val)
		bit := &ir.IntLit{Value: 1 << uint(inst.Operands[1].Imm)}
		masked := &ir.BinaryExpr{Op: "&", Left: val, Right: bit}
		op := "=="
		if inst.Mnemonic == "tbnz" {
			op = "!="
		}
		return &ir.BinaryExpr{Op: op, Left: masked, Right: &ir.IntLit{Value: 0}}
	}

	// b.cond: the comparison operands come from whatever "cmp"
	// instruction most recently ran before this branch (ARM64's
	// cmp-based conditional branches always test flags set by an
	// earlier instruction, never carry their own operands) -
	// liftCondition relies on l.lastCmp having been populated by run()
	// while lifting that cmp, which is why liftBlockGraph lifts a
	// block's body (including its own trailing cmp) before calling
	// this.
	op := condOpFromMnemonic(inst.Mnemonic)
	if op == "?" {
		return &ir.LocalVar{Name: "cond"}
	}
	return l.flagCondition(op)
}

// isBooleanExpr reports whether e is already a 0/1-valued boolean
// expression - a comparison, a logical AND/OR, or a negation - rather
// than an arbitrary integer value. Such an expression never needs the
// redundant "!= 0" / "== 0" wrapper a cbz/cbnz over a plain register
// gets (see liftCondition).
func isBooleanExpr(e ir.Expr) bool {
	switch v := e.(type) {
	case *ir.BinaryExpr:
		switch v.Op {
		case "==", "!=", "<", "<=", ">", ">=", "&&", "||":
			return true
		}
	case *ir.UnaryExpr:
		return v.Op == "!"
	}
	return false
}

// condOpFromMnemonic maps an ARM64 b.cond mnemonic's condition suffix
// to the Java/C-style comparison operator meaning "the branch is
// taken" - e.g. "b.le" (branch if less-or-equal) maps to "<=", matching
// liftCondition's convention of building the condition for the
// branch-taken path directly (see its doc comment).
func condOpFromMnemonic(mnemonic string) string {
	switch mnemonic {
	case "b.eq":
		return "=="
	case "b.ne":
		return "!="
	case "b.lt":
		return "<"
	case "b.mi":
		// Negative: the unconditional FP-compare form compilers emit
		// for "less than" (b.pl is its "greater or equal" counterpart,
		// modulo NaN, where PL is also set).
		return "<"
	case "b.pl":
		return ">="
	case "b.le":
		return "<="
	case "b.gt":
		return ">"
	case "b.ge":
		return ">="
	case "b.hs":
		// Unsigned "higher or same" (carry set) - the unsigned
		// counterpart of b.ge, from an unsigned "cmp" (e.g. comparing
		// two size_t/pointer values, or after an unsigned-widening
		// load) rather than a signed one. This project's IR has no
		// separate unsigned comparison operator, so ">=" is used as-is
		// - correct for the common case where both operands are
		// already known non-negative (unsigned types), imprecise only
		// if one is a genuinely negative signed value reinterpreted as
		// unsigned, which -O0 code testing size_t/pointer values (by
		// far the common case for b.hs/b.lo/b.hi/b.ls) doesn't do.
		return ">="
	case "b.lo":
		return "<" // unsigned "lower" (carry clear) - see b.hs's own note.
	case "b.hi":
		return ">" // unsigned "higher" - see b.hs's own note.
	case "b.ls":
		return "<=" // unsigned "lower or same" - see b.hs's own note.
	default:
		return "?"
	}
}

// lifter holds the running state while lifting one function.
type lifter struct {
	// regs maps a register name (as Capstone spells it: "w0", "x1",
	// "sp", ...) to the IR expression currently held there. Updated on
	// every instruction that writes a register; read whenever a later
	// instruction uses that register as a source operand.
	regs map[string]ir.Expr

	// stack maps a stack-frame displacement (the #N in "[sp, #N]") to
	// the source-level local variable name that displacement was
	// recognized as representing - populated the first time a
	// parameter-carrying register is spilled to that slot, so a later
	// reload from the same slot resolves back to the same named
	// variable instead of inventing a new one.
	stack map[int32]string
	// stackWidth records the widest access seen for each stack slot and
	// feeds basic local type inference when no DWARF type is known.
	stackWidth map[int32]int
	// stackTyped marks slots whose type came from DWARF and must not be
	// overwritten by the width heuristic.
	stackTyped map[int32]bool

	// x29Offset/x29Known track the frame pointer's displacement from
	// the stack base established by "mov x29, sp" / "add x29, sp, #N".
	// -O0 code addresses locals through x29; mapping those accesses to
	// the same stack map as sp-relative ones turns them into named
	// locals instead of raw `*(uint64_t*)((uintptr_t)x29 - 0xN)`.
	x29Offset int32
	x29Known  bool

	// functionInsns/insnIndex are the complete instruction stream of the
	// function being lifted, used to inline straight-line intra-function
	// calls ("bl" to a local label) with the caller's live register state.
	functionInsns []native.DetailedInstruction
	insnIndex     map[uint64]int
	functionStart uint64
	functionEnd   uint64
	outlinedDepth int
	curAddr       uint64

	// written tracks registers explicitly written since function entry
	// (seeded incoming parameter registers do not count). seedRefs keeps
	// the exact expression each argument register was seeded with.
	written   map[string]bool
	seedRefs  map[string]ir.Expr
	regWidths map[string]int

	// params holds the declared parameter names in AAPCS64 register
	// order, as given to LiftFunction.
	params []string

	// lastCmp holds the operands of the most recently lifted "cmp"
	// instruction, consumed by liftCondition when a following b.cond
	// needs to know what's actually being compared (ARM64 conditional
	// branches always test flags set by an earlier instruction, never
	// carry their own comparison operands).
	lastCmp *cmpOperands

	// resolver resolves a call target address to a human-readable name,
	// as given to LiftFunction. May be nil.
	resolver SymbolResolver

	// strings resolves a data address to the string literal stored
	// there, as given to LiftFunction. May be nil.
	strings StringResolver

	// addrRegs maps a register name to the absolute address it's known
	// to hold as of the most recently lifted instruction - populated by
	// adrp/adr (a fresh page/byte-precise address) and propagated by a
	// following "add Rd, Rn, #imm" (the adrp-page + add-offset idiom
	// AArch64 -O0 code always uses to reach a specific symbol within an
	// adrp's page). This is tracked SEPARATELY from regs (which holds
	// the ordinary IR expression for the register, e.g. a placeholder
	// IntLit of the same address) because the address only becomes
	// interesting - worth trying to resolve to a string literal via
	// strings - at the point a register holding one is actually used
	// (currently: as a call argument, in buildCall) rather than at the
	// point it's computed, since adrp/adr/add are also used for
	// perfectly ordinary integer arithmetic this lifter has no way to
	// distinguish from address computation up front.
	addrRegs map[string]uint64

	// calls holds every call expression this lifter (or an ancestor it
	// was forked from) has produced, in creation order - the ordered
	// half of the "was this call's result ever actually used" tracking
	// that flushRemaining and the inline orphan-detection in setReg/
	// clobberReg rely on to emit a void call as its own statement rather
	// than silently dropping it.
	calls []ir.Expr

	// consumed marks which entries in calls (by expression identity -
	// these are always the same *ir.MethodCall/*ir.StaticMethodCall
	// pointer stored in calls and in regs, never a copy) have been read
	// by something that embeds them into a larger expression (a call's
	// own argument, a cmp/add operand, a return value) or already
	// flushed as their own statement - either way, "already accounted
	// for" and exempt from being flushed again.
	consumed map[ir.Expr]bool

	// resultRegs marks the argument registers currently holding a call
	// result placed there IMPLICITLY by finishCall rather than by an
	// explicit instruction since. AAPCS64 says a callee is free to
	// clobber x0-x7, so a value still sitting there from a previous
	// call was never assigned by this call's own argument setup - it
	// must never be scavenged as this call's argument (see
	// collectCallArgsN). Any explicit write to the register (setReg)
	// or clobber clears the mark, so a genuinely reloaded/moved value
	// is still collected normally; only the untouched leftovers are
	// excluded.
	resultRegs map[string]bool

	// budget bounds the total number of liftBlockGraph calls across
	// THIS lifter and every one it's ever been forked from (a pointer,
	// so fork() shares the same underlying counter rather than copying
	// it - see fork's own doc comment) - a hard cap against the
	// exponential blowup an if/else split with no merge-point sharing
	// is inherently prone to: each nested conditional independently
	// forks and re-traverses everything downstream of it on BOTH
	// branches, so a long chain of N nested ifs (not unusual once
	// cbz/cbnz are recognized as conditional branches too - see
	// isConditionalBranch) does O(2^N) total block visits with no
	// bound otherwise. Once exhausted, liftBlockGraph stops recursing
	// and returns what it has so far for that path - an incomplete but
	// bounded-time result beats hanging indefinitely on a real,
	// large -O0 function.
	budget *int

	// searchBudget bounds the total work the speculative CFG searches
	// (reachesAddr, findDoWhileTail) may do across this whole
	// LiftFunction call, shared by pointer across forks exactly like
	// budget. It is deliberately SEPARATE from budget: those searches
	// run once (or twice) per block and may walk the entire reachable
	// graph each time, O(blocks^2) over a full lift, while the
	// structural lift itself needs only O(blocks) visits - charging the
	// searches to the shared lift budget starved liftBlockGraph on
	// large functions and silently dropped every block after the
	// budget ran out (see searchVisitBudget). Search failure is always
	// safe - loop recognition degrades to the ordinary if/else path,
	// which still lifts every block - so this counter existing only
	// reduces structural prettiness on a pathological input, never
	// completeness.
	searchBudget *int

	// dataReader reads bytes from the original binary by virtual
	// address. Non-nil when switch-statement detection wants to read
	// jump-table entries from rodata.
	dataReader func(uint64, int) ([]byte, bool)

	// cfg holds this function's merge-point facts (predecessor counts
	// and immediate post-dominators) - see cfgAnalysis' own doc comment.
	// nil on the straight-line path, where no branch graph exists.
	cfg *cfgAnalysis

	// stops, when non-nil, maps a block address to the label a path
	// reaching that block must jump to instead of lifting it: set while
	// lifting one arm of a split whose shared continuation is lifted
	// exactly once at the merge point after the if/else - see
	// tryLiftIfElseMerge and liftBlockGraph's own stop check.
	stops map[uint64]string

	// mergeUsed is shared (by pointer) across every fork lifting the
	// arms of the same split; whichever path first reaches one of
	// stops sets it true, which is how the caller knows the merge label
	// is actually referenced and the continuation must be lifted.
	mergeUsed *bool

	// labelSeq numbers merge labels within one function's lift. It is
	// shared by pointer across forks (like budget): the same merge
	// address can legitimately be lifted independently by two different
	// arm forks, and each emission needs its own label name or the
	// rendered C/LLVM would contain duplicate labels inside one
	// function.
	labelSeq *int

	// mergeLabels, shared across every fork (a map is a reference type),
	// records the label already claimed or emitted for a merge block,
	// keyed by the merge address AND the innermost loop head active
	// where the claim happened (a merge reached from a different loop
	// context must not share a label: the continuation was lifted under
	// its own loop's continue/break/join semantics). When a later split
	// resolves to a merge point some earlier split already owned, its
	// arms simply jump to the existing label instead of minting a new
	// one and lifting the whole continuation a second time. Without
	// this, a dispatcher whose condition chain funnels every arm into
	// one shared tail re-lifts that tail once per split - real -O0 code
	// produced 1356 identical copies of the same continuation label in
	// one function, and the whole-binary output stayed in the hundreds
	// of megabytes even with loops correctly recognized.
	mergeLabels map[mergeShareKey]string

	// opts holds the IL2CPP-aware options for this lift - see
	// liftopts.go. The zero value is the original behavior.
	opts LiftOptions

	// thisType is the full dump name of the managed class whose instance
	// method this lift is for, when opts.Metadata identified the entry
	// address as one. Empty otherwise.
	thisType string

	// regNames maps a canonical physical register key ("x8", "v3") to
	// the stable source-level name RegsAsVars assigned it - see
	// regName. Only populated when opts.RegsAsVars is set. Shared
	// across forks (a map is a reference type, and fork deliberately
	// passes the same one) so that whatever branch discovers a register
	// first, every other branch renders it under the same name.
	regNames map[string]string

	// regSeq / simdSeq number var_N / fvar_N names independently, so
	// the SIMD class never interleaves with the integer class. Shared
	// by pointer across forks for the same reason regNames is shared.
	regSeq  *int
	simdSeq *int
}

// mergeShareKey identifies one merge-label sharing scope: the merge
// block itself, plus the innermost enclosing loop head (0 at the top
// level) whose continue/break/join semantics its continuation was
// lifted under.
type mergeShareKey struct {
	addr     uint64
	loopHead uint64
}

// nextLabel returns the next merge-label serial number for this
// function's lift (see lifter.labelSeq).
func (l *lifter) nextLabel() int {
	*l.labelSeq++
	return *l.labelSeq
}

// cmpOperands is the lhs/rhs of a lifted "cmp" instruction, in the
// order the instruction itself specifies (cmp Rn, Rm compares Rn - Rm,
// so lhs=Rn, rhs=Rm) - condOpFromMnemonic's operator meanings assume
// this same left-to-right order.
type cmpOperands struct {
	lhs, rhs ir.Expr
	// combine, when non-nil, rewrites the plain comparison a b.cond
	// would build from lhs/rhs into the full flag condition left behind
	// by a preceding "ccmp" chain: a ccmp compares only
	// CONDITIONALLY (its own comparison applies when the previous flags
	// satisfy its condition; otherwise the flags become its constant
	// NZCV immediate), so the branch's real condition is a conjunction
	// or disjunction of the previous comparison with this one - see
	// liftCcmp's own doc comment.
	combine func(op string, cmp ir.Expr) ir.Expr
}

// blockVisitBudget is the total number of liftBlockGraph calls allowed
// across one entire LiftFunction call (all forks combined) - see the
// lifter.budget field's own doc comment for why this cap exists at
// all. 20000 is generous for any real single function's actual block
// count (typically at most a few hundred) while still keeping even a
// worst-case pathological blowup bounded to a fraction of a second.
const blockVisitBudget = 20000

// searchVisitBudget is the total number of BFS pops reachesAddr and
// findDoWhileTail may spend across one entire LiftFunction call - see
// the lifter.searchBudget field's own doc comment for why the
// speculative searches get their own counter instead of sharing
// blockVisitBudget (sharing it starved the structural lift on large
// functions and silently truncated their output). A few-hundred-block
// real function needs on the order of 10^5 pops to walk fully; 1<<20
// leaves ample headroom while still bounding any input's search work
// to well under a second, and exhaustion only degrades loop
// recognition to plain if/else lifting.
const searchVisitBudget = 1 << 20

// aapcs64IntArgRegs lists the integer/pointer argument registers in
// AAPCS64 (ARM64 procedure call standard) order - the Nth entry is
// where the Nth integer/pointer parameter arrives. 32-bit ("w") and
// 64-bit ("x") names alias the same physical register; a function
// taking `int` parameters (as in our test case) sees them as w0, w1,
// ... - one lifted local per parameter regardless of which width the
// prologue happens to use to spill it.
var aapcs64IntArgRegs = []string{"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"}

// aapcs64IntArgRegs32 is the 32-bit aliasing view of the same registers,
// index-for-index with aapcs64IntArgRegs.
var aapcs64IntArgRegs32 = []string{"w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7"}

// knownArity gives the REAL, ABI-fixed integer/pointer argument count
// for the handful of C/pthread/C++-runtime functions that show up in
// essentially every real-world AArch64 Android/Linux binary - the same
// role Ghidra's own built-in libc signature database plays for it.
// collectCallArgs' general heuristic (grab whatever's currently in
// x0-x7) has no way to know a callee's true arity at all, so for a
// genuinely 0-argument function like __stack_chk_fail it was
// scavenging whatever unrelated, still-unconsumed value happened to be
// sitting in x0 (almost always some earlier call's discarded return
// value) and rendering it as a bogus argument - producing nonsense
// like "__stack_chk_fail(someOtherCall())" instead of two separate
// statements. Deliberately limited to genuinely fixed-arity functions
// (no variadics like fprintf/__android_log_print, whose real arg count
// this lifter has no way to recover either way, so the general
// heuristic remains the least-bad option there).
var knownArity = map[string]int{
	"__stack_chk_fail":          0,
	"abort":                     0,
	"__cxa_pure_virtual":        0,
	"__cxa_deleted_virtual":     0,
	"pthread_self":              0,
	"__cxa_guard_acquire":       1,
	"__cxa_guard_release":       1,
	"__cxa_guard_abort":         1,
	"pthread_mutex_lock":        1,
	"pthread_mutex_unlock":      1,
	"pthread_mutex_trylock":     1,
	"pthread_mutex_destroy":     1,
	"pthread_mutexattr_init":    1,
	"pthread_mutexattr_destroy": 1,
	"pthread_cond_signal":       1,
	"pthread_cond_broadcast":    1,
	"pthread_cond_destroy":      1,
	"strlen":                    1,
	"free":                      1,
	"fflush":                    1,
	"pthread_mutex_init":        2,
	"pthread_mutexattr_settype": 2,
	"pthread_cond_wait":         2,
	"pthread_equal":             2,
	"__cxa_atexit":              3,
	"memcpy":                    3,
	"memset":                    3,
	"memmove":                   3,
}

var knownResultNames = map[string]string{
	"malloc":         "ptr",
	"calloc":         "ptr",
	"realloc":        "ptr",
	"operator new":   "ptr",
	"operator new[]": "ptr",
	"strdup":         "s",
	"strndup":        "s",
	"strlen":         "len",
	"wcslen":         "len",
	"open":           "fd",
	"fopen":          "fp",
	"fdopen":         "fp",
	"socket":         "sock",
	"getenv":         "env",
	"atoi":           "n",
	"atol":           "n",
	"strtol":         "n",
	"strtoul":        "n",
	"read":           "n",
	"write":          "n",
	"recv":           "n",
	"send":           "n",
	"memcpy":         "ptr",
	"memmove":        "ptr",
	"memset":         "ptr",
	"time":           "t",
	"access":         "rc",
	"puts":           "n",
	"printf":         "n",
	"pthread_create": "rc",
	"to_string":      "str",
}

// suggestedVarName returns a readable name hint for a value that comes
// from a well-known libc/C++ runtime function, or "" when no heuristic
// applies. Used to improve local variable names like "local_16" to
// "ptr_16" when the assigned value is a malloc()/operator new/etc.
func suggestedVarName(e ir.Expr) string {
	switch c := e.(type) {
	case *ir.StaticMethodCall:
		base := methodNameOnly(c.Method)
		if n, ok := knownResultNames[base]; ok {
			return n
		}
	case *ir.MethodCall:
		if n, ok := knownResultNames[c.Name]; ok {
			return n
		}
	}
	return ""
}

// localVarOf unwraps integer-width casts to the underlying local.
func localVarOf(e ir.Expr) (*ir.LocalVar, bool) {
	switch v := e.(type) {
	case *ir.LocalVar:
		return v, true
	case *ir.CastExpr:
		return localVarOf(v.Expr)
	}
	return nil, false
}

// paramNameForReg returns the declared parameter name for a register if
// it's one of the AAPCS64 integer argument registers within range of
// the caller-supplied paramNames, and ok=false otherwise (a register
// that isn't a recognized argument register at all, e.g. sp or an
// argument register beyond how many parameters this function actually
// has).
func (l *lifter) paramNameForReg(reg string) (string, bool) {
	for i, r := range aapcs64IntArgRegs {
		if reg == r || reg == aapcs64IntArgRegs32[i] {
			if i < len(l.params) {
				return l.params[i], true
			}
			return "", false
		}
	}
	return "", false
}

// isParam reports whether name is one of this function's own declared
// parameter names - used by liftStr to tell a genuine prologue spill
// (a parameter's own, unmodified value reaching the stack for the
// first time) apart from an ordinary local variable's assignment, by
// the VALUE currently in the source register rather than merely which
// register it happens to be (see liftStr's own doc comment for why
// that distinction matters).
func (l *lifter) isParam(name string) bool {
	for _, p := range l.params {
		if p == name {
			return true
		}
	}
	return false
}

// seedParams initializes each declared parameter's home register(s) to
// an IR reference to that parameter's name - this is what lets a
// prologue's "str w0, [sp, #12]" (spilling the first parameter to the
// stack, the standard -O0 codegen pattern) be recognized as "this stack
// slot IS parameter a", not some anonymous store. Must be called
// exactly ONCE per function (not per basic block - see LiftFunction's
// callers), since calling it again after a branch has already updated a
// register (e.g. w0 holding a computed/loaded value, not the original
// parameter) would silently discard that value and reset the register
// back to the parameter, which is exactly the bug this comment is
// warning against re-introducing.
func (l *lifter) seedParams() {
	for i := 0; i < len(aapcs64IntArgRegs); i++ {
		xReg := aapcs64IntArgRegs[i]
		wReg := aapcs64IntArgRegs32[i]
		name := l.regName(xReg)
		if i < len(l.params) && l.params[i] != "" {
			name = l.params[i]
		}
		xRef := &ir.LocalVar{Name: name}
		// wN is the low 32-bit view of xN, so seed it as an explicit
		// cast rather than a second unrelated variable.
		wRef := ir.Expr(&ir.CastExpr{
			Type: &ir.PrimitiveType{Name: "uint"},
			Expr: xRef,
		})
		l.regs[xReg] = xRef
		l.regs[wReg] = wRef
		l.seedRefs[xReg] = xRef
		l.seedRefs[wReg] = wRef
	}
}

func (l *lifter) run(instructions []native.DetailedInstruction) []ir.Stmt {
	var stmts []ir.Stmt

	for _, inst := range instructions {
		l.curAddr = inst.Address
		switch inst.Mnemonic {
		case "sub":
			if len(inst.Operands) > 0 && isVectorReg(inst.Operands[0]) {
				stmts = append(stmts, l.liftVectorBin(inst)...)
				continue
			}
			// "sub sp, sp, #N" is the standard -O0 prologue reserving
			// stack frame space - not part of the source program's own
			// logic (no C statement corresponds to it), so it's
			// recognized and silently skipped rather than lifted into
			// a meaningless "sp = sp - 16" statement. Any other "sub"
			// shape is ordinary arithmetic - see liftALU.
			if off, ok := framePointerSubOffset(inst); ok {
				l.x29Offset = off
				l.x29Known = true
				continue
			}
			if isSpAdjust(inst) {
				continue
			}
			stmts = append(stmts, l.liftALU(inst)...)
		case "subs":
			stmts = append(stmts, l.liftFlagResult(inst, "-")...)
		case "add":
			if len(inst.Operands) > 0 && isVectorReg(inst.Operands[0]) {
				stmts = append(stmts, l.liftVectorBin(inst)...)
				continue
			}
			if off, ok := framePointerAddOffset(inst); ok {
				l.x29Offset = off
				l.x29Known = true
				continue
			}
			if isSpAdjust(inst) {
				// "add sp, sp, #N" is the matching -O0 epilogue - same
				// reasoning as the sub case above.
				continue
			}
			stmts = append(stmts, l.liftAdd(inst)...)
		case "adds":
			stmts = append(stmts, l.liftFlagResult(inst, "+")...)
		case "and":
			stmts = append(stmts, l.liftALU(inst)...)
		case "ands":
			stmts = append(stmts, l.liftFlagResult(inst, "&")...)
		case "orr", "eor", "mul", "udiv", "sdiv", "lsl", "lsr", "asr":
			stmts = append(stmts, l.liftALU(inst)...)
		case "fadd", "fsub", "fmul", "fdiv":
			if len(inst.Operands) > 0 && isVectorReg(inst.Operands[0]) {
				stmts = append(stmts, l.liftVectorBin(inst)...)
			} else {
				stmts = append(stmts, l.liftALU(inst)...)
			}
		case "fmla":
			stmts = append(stmts, l.liftVectorFma(inst, false)...)
		case "fmls":
			stmts = append(stmts, l.liftVectorFma(inst, true)...)
		case "dup":
			stmts = append(stmts, l.liftVectorDup(inst)...)
		case "movi":
			stmts = append(stmts, l.liftVectorZero(inst)...)
		case "madd":
			stmts = append(stmts, l.liftMadd(inst, false)...)
		case "msub":
			stmts = append(stmts, l.liftMadd(inst, true)...)
		case "mneg":
			stmts = append(stmts, l.liftMadd(inst, true)...)
		case "ubfx":
			stmts = append(stmts, l.liftBitfield(inst, false)...)
		case "sbfx":
			stmts = append(stmts, l.liftBitfield(inst, true)...)
		case "ubfiz":
			stmts = append(stmts, l.liftBfiz(inst, false)...)
		case "sbfiz":
			stmts = append(stmts, l.liftBfiz(inst, true)...)
		case "sxtb":
			stmts = append(stmts, l.liftExtend(inst, &ir.PrimitiveType{Name: "sbyte"})...)
		case "sxth":
			stmts = append(stmts, l.liftExtend(inst, &ir.PrimitiveType{Name: "short"})...)
		case "sxtw":
			stmts = append(stmts, l.liftExtend(inst, &ir.PrimitiveType{Name: "int"})...)
		case "uxtb":
			stmts = append(stmts, l.liftExtend(inst, &ir.PrimitiveType{Name: "byte"})...)
		case "uxth":
			stmts = append(stmts, l.liftExtend(inst, &ir.PrimitiveType{Name: "ushort"})...)
		case "uxtw":
			stmts = append(stmts, l.liftExtend(inst, &ir.PrimitiveType{Name: "uint"})...)
		case "tst":
			l.liftTst(inst)
		case "cmn":
			l.liftCmn(inst)
		case "fcmp", "fcmpe":
			l.liftFcmp(inst)
		case "neg":
			stmts = append(stmts, l.liftNeg(inst, false)...)
		case "negs":
			stmts = append(stmts, l.liftNeg(inst, true)...)
		case "fneg":
			stmts = append(stmts, l.liftFPUnary(inst, false)...)
		case "fabs":
			stmts = append(stmts, l.liftFPUnary(inst, true)...)
		case "bics":
			stmts = append(stmts, l.liftBics(inst)...)
		case "extr":
			stmts = append(stmts, l.liftExtr(inst)...)
		case "scvtf", "ucvtf":
			stmts = append(stmts, l.liftFPConvertToFloat(inst)...)
		case "fcvtzs":
			stmts = append(stmts, l.liftFPConvertToInt(inst, true)...)
		case "fcvtzu":
			stmts = append(stmts, l.liftFPConvertToInt(inst, false)...)
		case "fmov":
			stmts = append(stmts, l.liftFmov(inst)...)
		case "movz", "movk", "movn":
			stmts = append(stmts, l.liftMovWide(inst)...)
		case "adrp", "adr":
			stmts = append(stmts, l.liftAddr(inst)...)
		case "stp":
			// "stp x29, x30, [sp, #-N]!" is the standard -O0
			// frame-pointer prologue (saving the caller's frame
			// pointer and return address before establishing this
			// function's own frame) - not part of the source program's
			// own logic, same reasoning as the sub/sp-adjust prologue
			// case above. Every other pair is a real two-register
			// memory access.
			if isFramePointerSave(inst) {
				continue
			}
			if isCalleeSavedPair(inst) {
				continue
			}
			stmts = append(stmts, l.liftPair(inst, false)...)
		case "ldp":
			// "ldp x29, x30, [sp], #N" is the matching -O0
			// frame-pointer epilogue - same reasoning as stp above.
			if isFramePointerRestore(inst) {
				continue
			}
			if isCalleeSavedPair(inst) {
				continue
			}
			stmts = append(stmts, l.liftPair(inst, true)...)
		case "mov":
			// "mov x29, sp" (establishing the frame pointer, standard
			// -O0 prologue) has no source-level meaning of its own -
			// recognized and skipped. Any other "mov" shape is a
			// genuine register-to-register or register-immediate move;
			// see liftMov.
			if isFramePointerEstablish(inst) {
				l.x29Offset = 0
				l.x29Known = true
				continue
			}
			stmts = append(stmts, l.liftMov(inst)...)
		case "str", "stur", "strb", "strh", "sturb", "sturh", "stlr":
			stmts = append(stmts, l.liftStore(inst, accessWidth(inst))...)
		case "stxr", "stlxr", "stxrb", "stxrh", "stlxrb", "stlxrh":
			width := 8
			if len(inst.Operands) > 1 && inst.Operands[1].Type == native.OperandReg {
				width = regWidth(inst.Operands[1].Reg)
			}
			switch inst.Mnemonic {
			case "stxrb", "stlxrb":
				width = 1
			case "stxrh", "stlxrh":
				width = 2
			}
			stmts = append(stmts, l.liftStoreExclusive(inst, width)...)
		case "cas", "casa", "casl", "casal", "casb", "cash":
			width := 8
			if len(inst.Operands) > 0 && inst.Operands[0].Type == native.OperandReg {
				width = regWidth(inst.Operands[0].Reg)
			}
			switch inst.Mnemonic {
			case "casb":
				width = 1
			case "cash":
				width = 2
			}
			stmts = append(stmts, l.liftCas(inst, width)...)
		case "ld1":
			stmts = append(stmts, l.liftVectorList(inst, true)...)
		case "st1":
			stmts = append(stmts, l.liftVectorList(inst, false)...)
		case "ldr", "ldur", "ldrb", "ldrh", "ldurb", "ldurh", "ldar", "ldaxr", "ldxr", "ldaxrb", "ldaxrh", "ldxrb", "ldxrh":
			stmts = append(stmts, l.liftLoad(inst, accessWidth(inst), nil)...)
		case "ldrsb":
			stmts = append(stmts, l.liftLoad(inst, 1, &ir.PrimitiveType{Name: "sbyte"})...)
		case "ldrsh":
			stmts = append(stmts, l.liftLoad(inst, 2, &ir.PrimitiveType{Name: "short"})...)
		case "ldrsw":
			stmts = append(stmts, l.liftLoad(inst, 4, &ir.PrimitiveType{Name: "int"})...)
		case "cmp", "ccmp", "ccmn", "fccmp", "fccmpe":
			l.liftCmp(inst)
		case "csel", "csinc", "csinv", "csneg", "fcsel":
			stmts = append(stmts, l.liftCsel(inst)...)
		case "bl":
			stmts = append(stmts, l.liftCall(inst)...)
		case "blr":
			stmts = append(stmts, l.liftBlr(inst)...)
		case "cset":
			stmts = append(stmts, l.liftCset(inst)...)
		case "ret":
			stmts = append(stmts, l.liftRet())
		case "b":
			// An unconditional "b" reaching run() at all (rather than
			// ending a block that buildCFG turned into an if/else or a
			// followed successor edge) is this block's own last
			// instruction with nowhere internal left to go - see
			// liftTailCall's own doc comment for why it's only lifted
			// when its target resolves to a known symbol.
			stmts = append(stmts, l.liftTailCall(inst)...)
		case "br":
			// Same reasoning as "b" above, just through a register - see
			// liftBr's own doc comment.
			stmts = append(stmts, l.liftBr(inst)...)
		}

		// A flag-writing instruction this lifter doesn't understand
		// invalidates the comparison snapshot a later b.cond/csel/cset
		// would otherwise read, which could silently turn the branch
		// into a test of an older, unrelated comparison. Clear it so
		// the condition degrades to the explicit "cond" placeholder
		// instead of a wrong expression.
		if inst.WritesFlags && !handlesFlags(inst.Mnemonic) {
			l.lastCmp = nil
		}
	}

	return stmts
}

// handlesFlags reports whether run() has an explicit lift for an
// instruction that writes NZCV. Anything else that writes flags clears
// the lastCmp snapshot (see run) so a later b.cond/csel/cset cannot
// silently test an older comparison.
func handlesFlags(mnemonic string) bool {
	switch mnemonic {
	case "cmp", "ccmp", "ccmn", "fccmp", "fccmpe", "cmn", "tst", "subs", "adds", "ands", "negs", "bics", "fcmp", "fcmpe":
		return true
	}
	return false
}

// isCalleeSavedPair reports whether inst is a stp/ldp of two
// callee-saved integer registers to/from the stack - the standard -O0
// prologue/epilogue spill, which has no source-level equivalent (same
// reasoning as isFramePointerSave/Restore, just for x19-x28).
func isCalleeSavedPair(inst native.DetailedInstruction) bool {
	if len(inst.Operands) < 3 {
		return false
	}
	if inst.Operands[0].Type != native.OperandReg || inst.Operands[1].Type != native.OperandReg {
		return false
	}
	if inst.Operands[2].Type != native.OperandMem || inst.Operands[2].Mem.Base != "sp" {
		return false
	}
	return isCalleeSavedReg(inst.Operands[0].Reg) && isCalleeSavedReg(inst.Operands[1].Reg)
}

func isCalleeSavedReg(reg string) bool {
	if len(reg) < 2 || (reg[0] != 'x' && reg[0] != 'w') {
		return false
	}
	n := 0
	for _, c := range reg[1:] {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 19 && n <= 28
}

// isSpAdjust reports whether inst is "{add,sub} sp, sp, #N" - the
// -O0 prologue/epilogue shape for reserving/releasing stack frame
// space, which carries no source-level meaning of its own.
func isSpAdjust(inst native.DetailedInstruction) bool {
	if len(inst.Operands) != 3 {
		return false
	}
	if inst.Operands[0].Type != native.OperandReg || inst.Operands[0].Reg != "sp" {
		return false
	}
	if inst.Operands[1].Type != native.OperandReg || inst.Operands[1].Reg != "sp" {
		return false
	}
	return inst.Operands[2].Type == native.OperandImm
}

// isFramePointerSave reports whether inst is "stp x29, x30, [sp,
// #-N]!" - the standard -O0 frame-pointer prologue instruction, saving
// the caller's frame pointer (x29) and this call's return address
// (x30, the link register) onto the new stack frame being established.
// The "!" (pre-indexed writeback) means this instruction ALSO performs
// the sp adjustment itself, combining what isSpAdjust's plain "sub sp,
// sp, #N" case handles separately when a function doesn't need a full
// stack frame.
func isFramePointerSave(inst native.DetailedInstruction) bool {
	if len(inst.Operands) != 3 {
		return false
	}
	if inst.Operands[0].Type != native.OperandReg || inst.Operands[0].Reg != "x29" {
		return false
	}
	if inst.Operands[1].Type != native.OperandReg || inst.Operands[1].Reg != "x30" {
		return false
	}
	return inst.Operands[2].Type == native.OperandMem && inst.Operands[2].Mem.Base == "sp"
}

// isFramePointerRestore reports whether inst is "ldp x29, x30, [sp],
// #N" - the matching -O0 frame-pointer epilogue, restoring the
// caller's frame pointer and this call's own return address before
// returning.
func isFramePointerRestore(inst native.DetailedInstruction) bool {
	if len(inst.Operands) != 4 {
		return false
	}
	if inst.Operands[0].Type != native.OperandReg || inst.Operands[0].Reg != "x29" {
		return false
	}
	if inst.Operands[1].Type != native.OperandReg || inst.Operands[1].Reg != "x30" {
		return false
	}
	if inst.Operands[2].Type != native.OperandMem || inst.Operands[2].Mem.Base != "sp" {
		return false
	}
	return inst.Operands[3].Type == native.OperandImm
}

// stackSlotDisp returns the sp-relative stack displacement for an
// access through sp or a known frame pointer (x29). Indexed accesses
// are not stack slots.
func (l *lifter) stackSlotDisp(base string, mem native.MemOperand) (int32, bool) {
	if mem.Index != "" {
		return 0, false
	}
	switch {
	case base == "sp":
		return mem.Disp, true
	case base == "x29" && l.x29Known:
		return l.x29Offset + mem.Disp, true
	default:
		return 0, false
	}
}

// framePointerAddOffset recognizes the -O0 frame-pointer setup
// "add x29, sp, #imm" and returns imm.
func framePointerAddOffset(inst native.DetailedInstruction) (int32, bool) {
	if len(inst.Operands) != 3 {
		return 0, false
	}
	if inst.Operands[0].Type != native.OperandReg || inst.Operands[0].Reg != "x29" {
		return 0, false
	}
	if inst.Operands[1].Type != native.OperandReg || inst.Operands[1].Reg != "sp" {
		return 0, false
	}
	if inst.Operands[2].Type != native.OperandImm {
		return 0, false
	}
	return int32(inst.Operands[2].Imm), true
}

// framePointerSubOffset recognizes "sub x29, sp, #imm" (frame pointer
// below the current stack base) and returns -imm.
func framePointerSubOffset(inst native.DetailedInstruction) (int32, bool) {
	off, ok := framePointerAddOffset(inst)
	if !ok {
		return 0, false
	}
	return -off, true
}

// isFramePointerEstablish reports whether inst is "mov x29, sp" -
// pointing the frame-pointer register at the just-established stack
// frame, immediately after isFramePointerSave's stp. Has no
// source-level meaning of its own.
func isFramePointerEstablish(inst native.DetailedInstruction) bool {
	if len(inst.Operands) != 2 {
		return false
	}
	if inst.Operands[0].Type != native.OperandReg || inst.Operands[0].Reg != "x29" {
		return false
	}
	return inst.Operands[1].Type == native.OperandReg && inst.Operands[1].Reg == "sp"
}

// liftStr lifts "str Rt, [Rn, #disp]" - a store to memory. Two shapes:
//
//   - [sp, #disp] - a stack slot. Two further cases:
//     -- The FIRST store to a fresh slot, where Rt currently holds one
//     of this function's own parameters (checked by the VALUE
//     currently in Rt via regValue/isParam, not merely by which
//     physical register Rt happens to be - unlike an early version of
//     this check, which matched on the register name alone and could
//     therefore mistake a later, genuine reassignment through that
//     same register for another silent spill, silently dropping it -
//     see below): the standard -O0 prologue pattern of copying each
//     incoming argument register to its own stack slot immediately on
//     entry. Pure bookkeeping with no source-level equivalent - lifted
//     silently (no statement); it just teaches the lifter that this
//     slot means this parameter, so a later "ldr" from the same slot
//     resolves back to it (see liftLdr).
//     -- Anything else is a genuine source-level assignment: either
//     the first store to a fresh slot (a new local variable's own
//     initialization - named deterministically from its stack
//     displacement, "local_<disp>", so independent forks that each
//     discover the same slot fresh - see fork's own doc comment on why
//     the stack map isn't shared across forks - agree on the same
//     name without needing to coordinate) or a later store to an
//     already-named slot (reassigning that local, or even a parameter
//     whose value has since changed via that same slot, e.g. "n = n +
//     1;" spilled back to n's own stack home).
//   - [Rn, #disp] for any other base Rn - a write through an arbitrary
//     pointer (a struct field, an array element via a precomputed
//     address, ...). Rendered as a FieldAccess on whatever expression
//     Rn currently holds, named deterministically from disp alone
//     ("field_<disp>") for the same reason stack locals are - there's
//     no debug info to recover the real field name from, and a
//     consistent synthetic one at least reads the same way at every
//     use site. See liftLdr's own doc comment for the matching read
//     side, and its own note on why the POINTER expression (unlike the
//     value being stored here) is deliberately left unconsumed even
//     when the read side embeds it into a value that might never
//     itself be used.
//
// Both shapes always lift to a real AssignStmt (unconditionally part
// of this instruction's own returned statements), which is exactly why
// srcVal - the value actually being written - is always safe to
// consume here: its presence in the output is guaranteed the moment
// this function returns, unlike a register merely holding a value that
// might go unread later.
//
// width is the access width in bytes (1/2/4/8): the plain str/stur
// forms pass the source register's width, while strb/strh override it.
// The non-stack path also accepts register-indexed addressing
// ("[Rn, Rm]" / "[Rn, Rm, lsl #N]").
func (l *lifter) liftStr(inst native.DetailedInstruction, width int) []ir.Stmt {
	if len(inst.Operands) != 2 {
		return nil
	}
	srcOp, dstOp := inst.Operands[0], inst.Operands[1]
	if srcOp.Type != native.OperandReg || dstOp.Type != native.OperandMem {
		return nil
	}
	srcVal := l.regValue(srcOp.Reg)
	ctype := fpCType(srcOp.Reg)

	if disp, ok := l.stackSlotDisp(dstOp.Mem.Base, dstOp.Mem); ok {
		name, exists := l.stack[disp]
		if !exists {
			if lv, ok := localVarOf(srcVal); ok && l.isParam(lv.Name) {
				l.stack[disp] = lv.Name
				return nil
			}
			name = fmt.Sprintf("local_%d", disp)
			if hint := suggestedVarName(srcVal); hint != "" {
				name = fmt.Sprintf("%s_%d", hint, disp)
			}
			l.stack[disp] = name
		}
		if dstOp.Mem.Base == "x29" && l.opts.Debug != nil {
			if dname, dtype, ok := l.opts.Debug.LocalAt(int64(dstOp.Mem.Disp)); ok {
				name = dname
				l.stack[disp] = name
				l.stackTyped[disp] = true
				if dtype != "" && l.opts.LocalTypes != nil {
					l.opts.LocalTypes[name] = dtype
				}
			}
		}
		if ctype != "" && !stackSlotTypedFP(l.opts.LocalTypes, name) {
			// The slot is integer-backed (possibly because it is also
			// read/written as an x/w register); preserve the FP value's
			// bit pattern instead of renaming the slot to a second
			// variable, which would split the storage.
			l.consume(srcVal)
			srcVal = bitcastFPToInt(srcVal, ctype)
		}
		l.noteStackWidth(disp, width)
		l.consume(srcVal)
		return []ir.Stmt{&ir.AssignStmt{Target: &ir.LocalVar{Name: name}, Value: srcVal}}
	}

	if dstOp.Mem.Base == "" {
		return nil
	}
	// The pointer itself IS part of this AssignStmt's own Target
	// (embedded directly, not merely referenced), so - unlike
	// liftLdr's own base handling - it's safe to consume here too: its
	// text is guaranteed to appear in this unconditionally-returned
	// statement. memBaseExpr (see its own doc comment) keeps a
	// constant/zero base from rendering as a literal `.field_N`.
	target := l.memoryAccessTarget(dstOp.Mem.Base, dstOp.Mem, width, true)
	if target == nil {
		return nil
	}
	setAccessCType(target, ctype)
	l.consume(srcVal)
	return []ir.Stmt{&ir.AssignStmt{Target: target, Value: srcVal}}
}

// liftLdr lifts "ldr Rt, [Rn, #disp]" - a load from memory. Three
// shapes are recognized, tried in order:
//
//   - A stack slot previously spilled by liftStr (Rn == sp): if this
//     displacement was recorded as holding a named parameter OR local
//     (see liftStr), the destination register now holds an IR
//     reference to that same name (not a "load" statement - there's
//     nothing to say at the source level; the value simply flows into
//     the register that will use it next).
//   - A GOT/data slot at a known computed address: Rn is a register
//     addrRegs recorded an address for (see its own doc comment,
//     populated by adrp/adr(+add)) - if the resolver knows a name for
//     whatever's stored at that exact address (built from the
//     binary's .rela.dyn relocations - see
//     ELFParser.ResolveGOT's own doc comment for how, e.g., a
//     dynamically-linked std::cout resolves this way), the destination
//     register holds a reference to that name instead of an anonymous
//     loaded value - the common case being a GOT-loaded pointer to a
//     global object that the very next instruction typically uses as
//     an implicit `this`/first argument to some call (an operator<<
//     onto std::cout, say).
//   - Anything else with a real base register: an arbitrary pointer
//     dereference (a struct field, an array element via a
//     precomputed address, ...) - rendered as a FieldAccess on
//     whatever expression Rn currently holds, named deterministically
//     from disp alone ("field_<disp>") the same way a fresh stack
//     local is, since there's equally no debug info here to recover a
//     real field name from.
//
// Rn's own expression (the pointer being dereferenced) is deliberately
// left unconsumed for the third shape, unlike every other place in
// this file that embeds one expression into a larger one: the
// resulting FieldAccess is only installed into Rt's register slot, NOT
// unconditionally emitted as a statement the way liftStr's own
// assignment always is - if Rt goes on to never actually be read, this
// FieldAccess (and everything embedded in it) simply never appears in
// the output at all, same as any other computed-but-discarded value in
// this lifter's model (see liftAdd's own doc comment). Consuming Rn's
// value here regardless would risk a REAL loss for the one case that
// matters more: if Rn's value happens to be an unconsumed call result
// (e.g. "ldr x1, [x0, #8]" right after "x0 = malloc()"), marking it
// consumed here - based purely on being read, with no guarantee this
// FieldAccess itself ever surfaces anywhere - could suppress
// flushRemaining's own fallback flush of that call entirely, silently
// dropping malloc() from the output altogether. Leaving it unconsumed
// costs at most an occasional redundant-looking standalone flush of a
// call whose result ALSO happens to be embedded in some later,
// genuinely-used FieldAccess - a much safer trade than the reverse.
//
// A load that resolves to none of the above - a register that's
// neither a stack slot, a known address, nor has a real base register
// at all - isn't lifted, but the destination register is still
// clobbered (see clobberReg): the real CPU DID overwrite it with
// whatever the load actually produced, so leaving its old IR value in
// place would misrepresent it as still holding that stale value rather
// than an unknown freshly-loaded one.
//
// width is the access width in bytes (1/2/4/8): the plain ldr/ldur
// forms pass the destination register's width, while ldrb/ldrh override
// it. The non-stack path also accepts register-indexed addressing
// ("[Rn, Rm]" / "[Rn, Rm, lsl #N]").
func (l *lifter) liftLdr(inst native.DetailedInstruction, width int, cast ir.Type) []ir.Stmt {
	if len(inst.Operands) != 2 {
		return nil
	}
	dstOp, srcOp := inst.Operands[0], inst.Operands[1]
	if dstOp.Type != native.OperandReg || srcOp.Type != native.OperandMem {
		return nil
	}
	wrap := func(e ir.Expr) ir.Expr {
		if e == nil || cast == nil {
			return e
		}
		return &ir.CastExpr{Type: cast, Expr: e}
	}
	ctype := fpCType(dstOp.Reg)

	if disp, ok := l.stackSlotDisp(srcOp.Mem.Base, srcOp.Mem); ok {
		if srcOp.Mem.Base == "x29" && l.opts.Debug != nil {
			if dname, dtype, ok := l.opts.Debug.LocalAt(int64(srcOp.Mem.Disp)); ok {
				l.stack[disp] = dname
				l.stackTyped[disp] = true
				if dtype != "" && l.opts.LocalTypes != nil {
					l.opts.LocalTypes[dname] = dtype
				}
				l.noteStackWidth(disp, width)
				return l.setReg(dstOp.Reg, wrap(&ir.LocalVar{Name: dname}))
			}
		}
		if name, ok := l.stack[disp]; ok {
			l.noteStackWidth(disp, width)
			val := ir.Expr(&ir.LocalVar{Name: name})
			if ctype != "" && !stackSlotTypedFP(l.opts.LocalTypes, name) {
				val = bitcastIntToFP(val, ctype)
			}
			return l.setReg(dstOp.Reg, wrap(val))
		}
		if ctype != "" {
			name := fmt.Sprintf("local_%d", disp)
			l.stack[disp] = name
			l.noteStackWidth(disp, width)
			return l.setReg(dstOp.Reg, wrap(bitcastIntToFP(&ir.LocalVar{Name: name}, ctype)))
		}
		return l.clobberReg(dstOp.Reg)
	}

	if srcOp.Mem.Index == "" {
		if base, ok := l.addrRegs[srcOp.Mem.Base]; ok && l.resolver != nil {
			addr := base + uint64(srcOp.Mem.Disp)
			if name, ok := l.resolver(addr); ok {
				name = demangle(name)
				// A real symbol name here is the object whose address
				// the GOT/data slot holds. Section labels (".got+0x8")
				// only describe the SLOT itself, so load from the slot's
				// absolute address instead.
				if !isSectionLabel(name) {
					return l.setReg(dstOp.Reg, wrap(&ir.LocalVar{Name: name}))
				}
				target := l.newFieldAccessOn(&ir.AddrLit{Value: addr, Label: name}, 0, width)
				if target != nil {
					setAccessCType(target, ctype)
					return l.setReg(dstOp.Reg, wrap(target))
				}
			}
		}
	}

	if srcOp.Mem.Base != "" {
		val := l.memoryAccessTarget(srcOp.Mem.Base, srcOp.Mem, width, false)
		if val != nil {
			setAccessCType(val, ctype)
			return l.setReg(dstOp.Reg, wrap(val))
		}
		return l.clobberReg(dstOp.Reg)
	}

	return l.clobberReg(dstOp.Reg)
}

// applyWriteback updates a non-stack base register after a pre/post-
// indexed load/store. The stack pointer is deliberately excluded: this
// lifter models sp-relative slots by their raw displacement rather than
// maintaining a running sp value.
func (l *lifter) applyWriteback(inst native.DetailedInstruction, mem native.MemOperand) []ir.Stmt {
	if !inst.Writeback || mem.Base == "" || mem.Base == "sp" || mem.Base == "x29" {
		return nil
	}
	disp := mem.Disp
	if inst.PostIndex {
		disp = 0
		for i := len(inst.Operands) - 1; i >= 0; i-- {
			if inst.Operands[i].Type == native.OperandImm {
				disp = int32(inst.Operands[i].Imm)
				break
			}
		}
	}
	if disp == 0 {
		return nil
	}
	base := l.memBaseExpr(mem.Base)
	val := &ir.BinaryExpr{Op: "+", Left: base, Right: &ir.IntLit{Value: int64(disp)}}
	return l.setReg(mem.Base, val)
}

// liftLoad is liftLdr plus any pre/post-indexed base-register update.
func (l *lifter) liftLoad(inst native.DetailedInstruction, width int, cast ir.Type) []ir.Stmt {
	stmts := l.liftLdr(inst, width, cast)
	if len(inst.Operands) >= 2 && inst.Operands[1].Type == native.OperandMem {
		stmts = append(stmts, l.applyWriteback(inst, inst.Operands[1].Mem)...)
	}
	return stmts
}

// liftStore is liftStr plus any pre/post-indexed base-register update.
func (l *lifter) liftStore(inst native.DetailedInstruction, width int) []ir.Stmt {
	stmts := l.liftStr(inst, width)
	if len(inst.Operands) >= 2 && inst.Operands[1].Type == native.OperandMem {
		stmts = append(stmts, l.applyWriteback(inst, inst.Operands[1].Mem)...)
	}
	return stmts
}

// pairElementInst adapts one half of an ldp/stp into the single-register
// instruction liftLdr/liftStr already know how to lift.
func pairElementInst(mnemonic string, reg native.Operand, mem native.MemOperand) native.DetailedInstruction {
	return native.DetailedInstruction{
		Mnemonic: mnemonic,
		Operands: []native.Operand{
			reg,
			{Type: native.OperandMem, Mem: mem},
		},
	}
}

// liftPair lifts a general "ldp/stp Rt, Rt2, [Rn, #disp]" (including
// register-indexed and writeback forms). The two accesses are widened
// into the existing single-register lifters, so stack slots, field
// accesses, byte/halfword widths and indexed addressing all behave the
// same way they do for ldr/str.
func (l *lifter) liftPair(inst native.DetailedInstruction, load bool) []ir.Stmt {
	if len(inst.Operands) < 3 {
		return nil
	}
	reg1, reg2, memOp := inst.Operands[0], inst.Operands[1], inst.Operands[2]
	if reg1.Type != native.OperandReg || reg2.Type != native.OperandReg || memOp.Type != native.OperandMem {
		return nil
	}

	mem1 := memOp.Mem
	mem2 := memOp.Mem
	mem2.Disp += int32(regWidth(reg1.Reg))

	var stmts []ir.Stmt
	if !load || !isZeroReg(reg1.Reg) {
		if load {
			stmts = append(stmts, l.liftLdr(pairElementInst("ldr", reg1, mem1), regWidth(reg1.Reg), nil)...)
		} else {
			stmts = append(stmts, l.liftStr(pairElementInst("str", reg1, mem1), regWidth(reg1.Reg))...)
		}
	}
	if !load || !isZeroReg(reg2.Reg) {
		if load {
			stmts = append(stmts, l.liftLdr(pairElementInst("ldr", reg2, mem2), regWidth(reg2.Reg), nil)...)
		} else {
			stmts = append(stmts, l.liftStr(pairElementInst("str", reg2, mem2), regWidth(reg2.Reg))...)
		}
	}
	stmts = append(stmts, l.applyWriteback(inst, memOp.Mem)...)
	return stmts
}

// liftStoreExclusive lifts "stxr/stlxr Wstatus, Rt, [Rn]" by emitting a
// zero success status and the actual store. The loop/retry logic around
// it is not reconstructed, but the memory side effect and status are
// preserved.
func (l *lifter) liftStoreExclusive(inst native.DetailedInstruction, width int) []ir.Stmt {
	if len(inst.Operands) < 3 {
		return nil
	}
	status, src, memOp := inst.Operands[0], inst.Operands[1], inst.Operands[2]
	if status.Type != native.OperandReg || src.Type != native.OperandReg || memOp.Type != native.OperandMem {
		return nil
	}

	var stmts []ir.Stmt
	if !isZeroReg(status.Reg) {
		stmts = append(stmts, l.setReg(status.Reg, &ir.IntLit{Value: 0})...)
		stmts = append(stmts, &ir.AssignStmt{
			Target: &ir.LocalVar{Name: l.regName(status.Reg)},
			Value:  &ir.IntLit{Value: 0},
		})
	}
	stmts = append(stmts, l.liftStr(pairElementInst("str", src, memOp.Mem), width)...)
	stmts = append(stmts, l.applyWriteback(inst, memOp.Mem)...)
	return stmts
}

// liftCas lifts the compare-and-swap family:
//
//	if (*mem == expected) *mem = desired;
//	else expected = *mem;
//
// The acquire/release suffix variants (casa/casal/casl) have the same
// source-level shape; ordering semantics remain implicit.
func (l *lifter) liftCas(inst native.DetailedInstruction, width int) []ir.Stmt {
	if len(inst.Operands) < 3 {
		return nil
	}
	expectedOp, desiredOp, memOp := inst.Operands[0], inst.Operands[1], inst.Operands[2]
	if expectedOp.Type != native.OperandReg || desiredOp.Type != native.OperandReg || memOp.Type != native.OperandMem {
		return nil
	}
	expected := l.regValue(expectedOp.Reg)
	desired := l.regValue(desiredOp.Reg)
	l.consume(expected)
	l.consume(desired)

	read := l.memoryAccessTarget(memOp.Mem.Base, memOp.Mem, width, true)
	write := l.memoryAccessTarget(memOp.Mem.Base, memOp.Mem, width, true)
	reload := l.memoryAccessTarget(memOp.Mem.Base, memOp.Mem, width, true)
	if read == nil || write == nil || reload == nil {
		return nil
	}

	then := &ir.Block{Statements: []ir.Stmt{&ir.AssignStmt{Target: write, Value: desired}}}
	var els *ir.Block
	if !isZeroReg(expectedOp.Reg) {
		els = &ir.Block{Statements: []ir.Stmt{&ir.AssignStmt{
			Target: &ir.LocalVar{Name: l.regName(expectedOp.Reg)},
			Value:  reload,
		}}}
	}
	return []ir.Stmt{&ir.IfStmt{
		Cond: &ir.BinaryExpr{Op: "==", Left: read, Right: expected},
		Then: then,
		Else: els,
	}}
}

// explicit so C's usual integer promotions do the sign/zero extension.
func (l *lifter) liftExtend(inst native.DetailedInstruction, cast ir.Type) []ir.Stmt {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg || inst.Operands[1].Type != native.OperandReg {
		return nil
	}
	val := l.regValue(inst.Operands[1].Reg)
	l.consume(val)
	return l.setReg(inst.Operands[0].Reg, &ir.CastExpr{Type: cast, Expr: val})
}

// liftMadd lifts "madd Rd, Rn, Rm, Ra" (Rn*Rm + Ra) and the msub
// variant (Rn*Rm - Ra).
func (l *lifter) liftMadd(inst native.DetailedInstruction, negate bool) []ir.Stmt {
	if inst.Mnemonic == "mneg" {
		if len(inst.Operands) != 3 {
			return nil
		}
		dst, rn, rm := inst.Operands[0], inst.Operands[1], inst.Operands[2]
		if dst.Type != native.OperandReg || rn.Type != native.OperandReg || rm.Type != native.OperandReg {
			return nil
		}
		a := l.regValue(rn.Reg)
		b := l.regValue(rm.Reg)
		l.consume(a)
		l.consume(b)
		return l.setReg(dst.Reg, &ir.UnaryExpr{Op: "-", Expr: &ir.BinaryExpr{Op: "*", Left: a, Right: b}})
	}
	if len(inst.Operands) != 4 {
		return nil
	}
	dst, rn, rm, ra := inst.Operands[0], inst.Operands[1], inst.Operands[2], inst.Operands[3]
	if dst.Type != native.OperandReg || rn.Type != native.OperandReg || rm.Type != native.OperandReg || ra.Type != native.OperandReg {
		return nil
	}
	a := l.regValue(rn.Reg)
	b := l.regValue(rm.Reg)
	c := l.regValue(ra.Reg)
	l.consume(a)
	l.consume(b)
	l.consume(c)
	product := &ir.BinaryExpr{Op: "*", Left: a, Right: b}
	op := "+"
	if negate {
		op = "-"
	}
	return l.setReg(dst.Reg, &ir.BinaryExpr{Op: op, Left: product, Right: c})
}

// isVectorReg reports whether an operand is a SIMD vector register as
// Capstone exposes it (qN).
func isVectorReg(op native.Operand) bool {
	return op.Type == native.OperandReg && len(op.Reg) >= 2 && op.Reg[0] == 'q'
}

// vectorLayout extracts the arrangement suffix (4s, 2d, 16b, ...) from
// an instruction's textual operand list.
func vectorLayout(opstr string) string {
	for _, layout := range []string{"16b", "8h", "4s", "2d", "8b", "4h", "2s", "1d"} {
		if strings.Contains(opstr, "."+layout) {
			return layout
		}
	}
	return ""
}

// liftVectorBin lifts lane-wise vector add/sub/mul/div through the
// eni_v* helper functions emitted in the file preamble.
func (l *lifter) liftVectorBin(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 3 || !isVectorReg(inst.Operands[0]) ||
		!isVectorReg(inst.Operands[1]) || !isVectorReg(inst.Operands[2]) {
		return nil
	}
	layout := vectorLayout(inst.OpStr)
	if layout == "" {
		return nil
	}
	suffix := ""
	isFP := inst.Mnemonic == "fadd" || inst.Mnemonic == "fsub" || inst.Mnemonic == "fmul" || inst.Mnemonic == "fdiv"
	if isFP {
		switch layout {
		case "4s":
			suffix = "F32X4"
		case "2d":
			suffix = "F64X2"
		default:
			return nil
		}
	} else {
		switch layout {
		case "4s":
			suffix = "U32X4"
		case "2d":
			suffix = "U64X2"
		case "16b":
			suffix = "U8X16"
		case "8h":
			suffix = "U16X8"
		default:
			return nil
		}
	}
	prefix := ""
	switch inst.Mnemonic {
	case "fadd", "add":
		prefix = "ENI_VADD_"
	case "fsub", "sub":
		prefix = "ENI_VSUB_"
	case "fmul":
		prefix = "ENI_VMUL_"
	case "fdiv":
		prefix = "ENI_VDIV_"
	default:
		return nil
	}
	if (suffix == "U8X16" || suffix == "U16X8") && (inst.Mnemonic == "fmul" || inst.Mnemonic == "fdiv") {
		return nil
	}
	a := l.regValue(inst.Operands[1].Reg)
	b := l.regValue(inst.Operands[2].Reg)
	l.consume(a)
	l.consume(b)
	return l.setReg(inst.Operands[0].Reg, &ir.StaticMethodCall{
		Method: prefix + suffix,
		Args:   []ir.Expr{a, b},
	})
}

// liftVectorFma lifts fmla/fmls: Rd = Rd ± Rn*Rm, lane-wise.
func (l *lifter) liftVectorFma(inst native.DetailedInstruction, negate bool) []ir.Stmt {
	if len(inst.Operands) != 3 || !isVectorReg(inst.Operands[0]) ||
		!isVectorReg(inst.Operands[1]) || !isVectorReg(inst.Operands[2]) {
		return nil
	}
	layout := vectorLayout(inst.OpStr)
	suffix := ""
	switch layout {
	case "4s":
		suffix = "F32X4"
	case "2d":
		suffix = "F64X2"
	default:
		return nil
	}
	acc := l.regValue(inst.Operands[0].Reg)
	a := l.regValue(inst.Operands[1].Reg)
	b := l.regValue(inst.Operands[2].Reg)
	l.consume(acc)
	l.consume(a)
	l.consume(b)
	name := "ENI_VFMA_" + suffix
	if negate {
		name = "ENI_VFMS_" + suffix
	}
	return l.setReg(inst.Operands[0].Reg, &ir.StaticMethodCall{
		Method: name,
		Args:   []ir.Expr{acc, a, b},
	})
}

// liftVectorZero handles "movi vD.<arr>, #0" and its q/d/s aliases.
// Non-zero vector immediates are left to the existing vector paths.
func (l *lifter) liftVectorZero(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) < 1 || !isVectorReg(inst.Operands[0]) {
		return nil
	}
	zero := len(inst.Operands) >= 2 && inst.Operands[1].Type == native.OperandImm && inst.Operands[1].Imm == 0
	if !zero {
		txt := inst.OpStr
		if i := strings.LastIndex(txt, "#"); i >= 0 {
			v := strings.TrimSpace(txt[i+1:])
			if j := strings.IndexAny(v, ", "); j >= 0 {
				v = v[:j]
			}
			if n, err := strconv.ParseUint(v, 0, 64); err == nil && n == 0 {
				zero = true
			}
		}
	}
	if !zero {
		return nil
	}
	n := vectorRegNumber(inst.Operands[0].Reg)
	if n < 0 {
		return nil
	}
	var stmts []ir.Stmt
	for _, reg := range []string{
		fmt.Sprintf("b%d", n), fmt.Sprintf("h%d", n), fmt.Sprintf("s%d", n),
		fmt.Sprintf("d%d", n), fmt.Sprintf("q%d", n), fmt.Sprintf("v%d", n),
	} {
		stmts = append(stmts, l.setReg(reg, &ir.IntLit{Value: 0})...)
	}
	return stmts
}

func vectorRegNumber(name string) int {
	digits := ""
	for _, r := range name {
		if r >= '0' && r <= '9' {
			digits += string(r)
			continue
		}
		if digits != "" {
			break
		}
	}
	if digits == "" {
		return -1
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n < 0 || n > 31 {
		return -1
	}
	return n
}

// liftVectorDup lifts "dup vD.<arr>, Rn" by broadcasting the scalar
// into every lane.
func (l *lifter) liftVectorDup(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 2 || !isVectorReg(inst.Operands[0]) {
		return nil
	}
	suffix := ""
	switch vectorLayout(inst.OpStr) {
	case "16b":
		suffix = "U8X16"
	case "8h":
		suffix = "U16X8"
	case "4s":
		suffix = "U32X4"
	case "2d":
		suffix = "U64X2"
	default:
		return nil
	}
	var val ir.Expr
	switch inst.Operands[1].Type {
	case native.OperandReg:
		val = l.regValue(inst.Operands[1].Reg)
		l.consume(val)
	case native.OperandImm:
		val = &ir.IntLit{Value: inst.Operands[1].Imm}
	default:
		return nil
	}
	return l.setReg(inst.Operands[0].Reg, &ir.StaticMethodCall{
		Method: "ENI_VDUP_" + suffix,
		Args:   []ir.Expr{val},
	})
}

// liftVectorList lifts ld1/st1 with one or more vector registers. The
// post-index offset is carried in Mem.Disp by Capstone for these forms.
func (l *lifter) liftVectorList(inst native.DetailedInstruction, load bool) []ir.Stmt {
	memIdx := -1
	var mem native.MemOperand
	for i, op := range inst.Operands {
		if op.Type == native.OperandMem {
			memIdx = i
			mem = op.Mem
			break
		}
	}
	if memIdx < 1 {
		return nil
	}
	regs := inst.Operands[:memIdx]
	for _, reg := range regs {
		if reg.Type != native.OperandReg {
			return nil
		}
	}

	accessDisp := mem.Disp
	if inst.PostIndex {
		accessDisp = 0
	}
	var stmts []ir.Stmt
	total := 0
	for _, reg := range regs {
		width := regWidth(reg.Reg)
		m := mem
		m.Disp = accessDisp + int32(total)
		if load {
			stmts = append(stmts, l.liftLdr(pairElementInst("ldr", reg, m), width, nil)...)
		} else {
			stmts = append(stmts, l.liftStr(pairElementInst("str", reg, m), width)...)
		}
		total += width
	}

	if inst.Writeback && mem.Base != "" && mem.Base != "sp" && mem.Base != "x29" {
		disp := mem.Disp
		if disp == 0 && inst.PostIndex {
			disp = int32(total)
		}
		if disp != 0 {
			base := l.memBaseExpr(mem.Base)
			stmts = append(stmts, l.setReg(mem.Base, &ir.BinaryExpr{
				Op:    "+",
				Left:  base,
				Right: &ir.IntLit{Value: int64(disp)},
			})...)
		}
	}
	return stmts
}

// Rn + rhs). A following b.cond tests the sum against zero.
func (l *lifter) liftCmn(inst native.DetailedInstruction) {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg {
		return
	}
	lhs := l.regValue(inst.Operands[0].Reg)
	l.consume(lhs)
	rhs := l.operandValue(inst.Operands[1])
	if rhs == nil {
		l.lastCmp = nil
		return
	}
	l.lastCmp = &cmpOperands{
		lhs: &ir.BinaryExpr{Op: "+", Left: lhs, Right: rhs},
		rhs: &ir.IntLit{Value: 0},
	}
}

// liftFcmp lifts "fcmp/fcmpe Rn, Rm" into the same comparison
// snapshot liftCmp uses; a following b.eq/b.ne/b.lt/... tests it.
func (l *lifter) liftFcmp(inst native.DetailedInstruction) {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg {
		return
	}
	lhs := l.regValue(inst.Operands[0].Reg)
	l.consume(lhs)
	var rhs ir.Expr
	switch inst.Operands[1].Type {
	case native.OperandReg:
		rhs = l.regValue(inst.Operands[1].Reg)
		l.consume(rhs)
	case native.OperandFP:
		rhs = fpLit(inst.Operands[0].Reg, inst.Operands[1].FP)
	default:
		l.lastCmp = nil
		return
	}
	l.lastCmp = &cmpOperands{lhs: lhs, rhs: rhs}
}

// liftFPUnary lifts fneg/fabs on FP registers. fabs has no IR node, so
// it renders as the equivalent "< 0 ? -x : x" ternary.
func (l *lifter) liftFPUnary(inst native.DetailedInstruction, abs bool) []ir.Stmt {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg || inst.Operands[1].Type != native.OperandReg {
		return nil
	}
	dst, src := inst.Operands[0], inst.Operands[1]
	val := l.regValue(src.Reg)
	l.consume(val)
	if !abs {
		return l.setReg(dst.Reg, &ir.UnaryExpr{Op: "-", Expr: val})
	}
	zero := fpLit(dst.Reg, 0)
	return l.setReg(dst.Reg, &ir.TernaryExpr{
		Cond:      &ir.BinaryExpr{Op: "<", Left: val, Right: zero},
		TrueExpr:  &ir.UnaryExpr{Op: "-", Expr: val},
		FalseExpr: val,
	})
}

// liftFPConvertToFloat lifts scvtf/ucvtf from an integer register into
// sN/dN.
func (l *lifter) liftFPConvertToFloat(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg || inst.Operands[1].Type != native.OperandReg {
		return nil
	}
	dst := inst.Operands[0]
	ctype := fpCType(dst.Reg)
	if ctype == "" {
		return nil
	}
	val := l.regValue(inst.Operands[1].Reg)
	l.consume(val)
	return l.setReg(dst.Reg, &ir.CastExpr{Type: &ir.PrimitiveType{Name: ctype}, Expr: val})
}

// liftFPConvertToInt lifts fcvtzs/fcvtzu from sN/dN into an integer
// register.
func (l *lifter) liftFPConvertToInt(inst native.DetailedInstruction, signed bool) []ir.Stmt {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg || inst.Operands[1].Type != native.OperandReg {
		return nil
	}
	dst, src := inst.Operands[0], inst.Operands[1]
	if fpCType(src.Reg) == "" || len(dst.Reg) < 2 {
		return nil
	}
	name := "long"
	switch dst.Reg[0] {
	case 'w':
		name = "int"
	case 'x':
		name = "long"
	default:
		return nil
	}
	if !signed {
		if name == "int" {
			name = "uint"
		} else {
			name = "ulong"
		}
	}
	val := l.regValue(src.Reg)
	l.consume(val)
	return l.setReg(dst.Reg, &ir.CastExpr{Type: &ir.PrimitiveType{Name: name}, Expr: val})
}

// liftFmov lifts register-register and immediate forms, plus the
// integer<->FP bitcast forms through the ENI_BITCAST_* macros.
func (l *lifter) liftFmov(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg {
		return nil
	}
	dst := inst.Operands[0]
	dstCT := fpCType(dst.Reg)
	src := inst.Operands[1]

	switch src.Type {
	case native.OperandFP:
		if dstCT == "" {
			return nil
		}
		return l.setReg(dst.Reg, fpLit(dst.Reg, src.FP))
	case native.OperandReg:
		srcCT := fpCType(src.Reg)
		if srcCT != "" && dstCT != "" && srcCT == dstCT {
			val := l.regValue(src.Reg)
			l.consume(val)
			return l.setReg(dst.Reg, val)
		}
		if dstCT == "" && srcCT == "" {
			return l.liftMov(inst)
		}
		val := l.regValue(src.Reg)
		l.consume(val)
		macro := ""
		switch {
		case dst.Reg[0] == 's' && src.Reg[0] == 'w':
			macro = "ENI_BITCAST_F32"
		case dst.Reg[0] == 'w' && src.Reg[0] == 's':
			macro = "ENI_BITCAST_U32"
		case dst.Reg[0] == 'd' && src.Reg[0] == 'x':
			macro = "ENI_BITCAST_F64"
		case dst.Reg[0] == 'x' && src.Reg[0] == 'd':
			macro = "ENI_BITCAST_U64"
		default:
			return nil
		}
		return l.setReg(dst.Reg, &ir.StaticMethodCall{Method: macro, Args: []ir.Expr{val}})
	default:
		return nil
	}
}

// records the 0-vs-Rm comparison for a later condition consumer.
func (l *lifter) liftNeg(inst native.DetailedInstruction, flags bool) []ir.Stmt {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg || inst.Operands[1].Type != native.OperandReg {
		return nil
	}
	dst, src := inst.Operands[0], inst.Operands[1]
	val := l.regValue(src.Reg)
	l.consume(val)
	if flags {
		l.lastCmp = &cmpOperands{lhs: &ir.IntLit{Value: 0}, rhs: val}
	}
	return l.setReg(dst.Reg, &ir.BinaryExpr{Op: "-", Left: &ir.IntLit{Value: 0}, Right: val})
}

// liftBics lifts "bics Rd, Rn, <Rm|#imm>" (Rn & ~rhs), including the
// flags snapshot for a following condition.
func (l *lifter) liftBics(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 3 || inst.Operands[0].Type != native.OperandReg || inst.Operands[1].Type != native.OperandReg {
		return nil
	}
	dst := inst.Operands[0]
	lhs := l.regValue(inst.Operands[1].Reg)
	l.consume(lhs)
	rhs := l.operandValue(inst.Operands[2])
	if rhs == nil {
		l.lastCmp = nil
		return nil
	}
	result := &ir.BinaryExpr{
		Op:    "&",
		Left:  lhs,
		Right: &ir.UnaryExpr{Op: "~", Expr: rhs},
	}
	l.lastCmp = &cmpOperands{lhs: result, rhs: &ir.IntLit{Value: 0}}
	if isZeroReg(dst.Reg) {
		return nil
	}
	return l.setReg(dst.Reg, result)
}

// liftExtr lifts "extr Rd, Rn, Rm, #lsb": the low (bits-lsb) bits of
// Rn joined with the high lsb bits of Rm.
func (l *lifter) liftExtr(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 4 || inst.Operands[0].Type != native.OperandReg ||
		inst.Operands[1].Type != native.OperandReg || inst.Operands[2].Type != native.OperandReg ||
		inst.Operands[3].Type != native.OperandImm {
		return nil
	}
	dst := inst.Operands[0]
	bits := uint(regWidth(dst.Reg) * 8)
	lsb := uint(inst.Operands[3].Imm)
	if lsb >= bits {
		return nil
	}
	hi := l.regValue(inst.Operands[1].Reg)
	lo := l.regValue(inst.Operands[2].Reg)
	l.consume(hi)
	l.consume(lo)
	var val ir.Expr = lo
	if lsb > 0 {
		val = &ir.BinaryExpr{Op: ">>", Left: lo, Right: &ir.IntLit{Value: int64(lsb)}}
		hi = &ir.BinaryExpr{Op: "<<", Left: hi, Right: &ir.IntLit{Value: int64(bits - lsb)}}
		val = &ir.BinaryExpr{Op: "|", Left: val, Right: hi}
	}
	return l.setReg(dst.Reg, val)
}

// liftBfiz lifts ubfiz/sbfiz: extract the low `width` bits of Rn and
// insert them at #lsb, optionally sign-extending the field first.
func (l *lifter) liftBfiz(inst native.DetailedInstruction, signed bool) []ir.Stmt {
	if len(inst.Operands) != 4 {
		return nil
	}
	dst, src := inst.Operands[0], inst.Operands[1]
	if dst.Type != native.OperandReg || src.Type != native.OperandReg ||
		inst.Operands[2].Type != native.OperandImm || inst.Operands[3].Type != native.OperandImm {
		return nil
	}
	lsb := uint(inst.Operands[2].Imm)
	width := uint(inst.Operands[3].Imm)
	bits := uint(regWidth(dst.Reg) * 8)
	if width == 0 || width > bits || lsb >= bits {
		return nil
	}

	val := l.regValue(src.Reg)
	l.consume(val)
	if signed {
		left := bits - width
		signedType := ir.Type(&ir.PrimitiveType{Name: "long"})
		if bits == 32 {
			signedType = &ir.PrimitiveType{Name: "int"}
		}
		val = &ir.BinaryExpr{Op: ">>", Left: &ir.CastExpr{Type: signedType, Expr: &ir.BinaryExpr{
			Op:    "<<",
			Left:  val,
			Right: &ir.IntLit{Value: int64(left)},
		}}, Right: &ir.IntLit{Value: int64(left)}}
	} else if width < 64 {
		mask := (uint64(1) << width) - 1
		val = &ir.BinaryExpr{Op: "&", Left: val, Right: &ir.IntLit{Value: int64(mask)}}
	}
	if lsb > 0 {
		val = &ir.BinaryExpr{Op: "<<", Left: val, Right: &ir.IntLit{Value: int64(lsb)}}
	}
	return l.setReg(dst.Reg, val)
}

// liftBitfield lifts ubfx/sbfx (Rd, Rn, #lsb, #width). The signed form
// shifts the field to the top and performs an arithmetic right shift
// through a signed cast, so C's implementation-defined-but-universal
// signed shift supplies the extension.
func (l *lifter) liftBitfield(inst native.DetailedInstruction, signed bool) []ir.Stmt {
	if len(inst.Operands) != 4 {
		return nil
	}
	dst, src := inst.Operands[0], inst.Operands[1]
	if dst.Type != native.OperandReg || src.Type != native.OperandReg ||
		inst.Operands[2].Type != native.OperandImm || inst.Operands[3].Type != native.OperandImm {
		return nil
	}
	lsb := uint(inst.Operands[2].Imm)
	width := uint(inst.Operands[3].Imm)
	bits := uint(regWidth(dst.Reg) * 8)
	if width == 0 || lsb+width > bits {
		return nil
	}

	val := l.regValue(src.Reg)
	l.consume(val)

	if signed {
		left := bits - (lsb + width)
		right := bits - width
		signedType := ir.Type(&ir.PrimitiveType{Name: "long"})
		if bits == 32 {
			signedType = &ir.PrimitiveType{Name: "int"}
		}
		shifted := &ir.CastExpr{Type: signedType, Expr: &ir.BinaryExpr{
			Op:    "<<",
			Left:  val,
			Right: &ir.IntLit{Value: int64(left)},
		}}
		return l.setReg(dst.Reg, &ir.BinaryExpr{
			Op:    ">>",
			Left:  shifted,
			Right: &ir.IntLit{Value: int64(right)},
		})
	}

	if lsb > 0 {
		val = &ir.BinaryExpr{Op: ">>", Left: val, Right: &ir.IntLit{Value: int64(lsb)}}
	}
	if width < 64 {
		mask := (uint64(1) << width) - 1
		val = &ir.BinaryExpr{Op: "&", Left: val, Right: &ir.IntLit{Value: int64(mask)}}
	}
	return l.setReg(dst.Reg, val)
}

// fpCType returns the C scalar type for an FP/SIMD view register
// (sN -> float, dN -> double), or "" for integer/vector registers.
func fpCType(reg string) string {
	if len(reg) < 2 {
		return ""
	}
	switch reg[0] {
	case 's':
		return "float"
	case 'd':
		return "double"
	}
	return ""
}

// setAccessCType tags a memory access with an explicit scalar type so
// the renderer emits float*/double* instead of uint32_t*/uint64_t*.
func setAccessCType(e ir.Expr, ctype string) {
	if ctype == "" {
		return
	}
	switch v := e.(type) {
	case *ir.FieldAccess:
		v.CType = ctype
	case *ir.ArrayAccess:
		v.CType = ctype
	}
}

// stackSlotTypedFP reports whether a stack slot has a real float/double
// declaration from DWARF. Such slots can store the value directly; every
// other slot is integer-backed and FP accesses go through bitcasts so
// integer and FP views of the same bytes keep aliasing one variable.
func stackSlotTypedFP(types map[string]string, name string) bool {
	t := types[name]
	return t == "float" || t == "double"
}

func bitcastFPToInt(e ir.Expr, ctype string) ir.Expr {
	if e == nil {
		return nil
	}
	macro := "ENI_BITCAST_U64"
	if ctype == "float" {
		macro = "ENI_BITCAST_U32"
	}
	return &ir.StaticMethodCall{Method: macro, Args: []ir.Expr{e}}
}

func bitcastIntToFP(e ir.Expr, ctype string) ir.Expr {
	if e == nil {
		return nil
	}
	macro := "ENI_BITCAST_F64"
	if ctype == "float" {
		macro = "ENI_BITCAST_F32"
	}
	return &ir.StaticMethodCall{Method: macro, Args: []ir.Expr{e}}
}

// fpViewBitcast converts a d/s register operand to its raw integer bits
// (or the result back into the register's C view) for integer ALU ops on
// vector registers, e.g. NEON "orr d0, d1, d2". Non-FP-view registers
// pass through unchanged.
func fpViewBitcast(reg string, e ir.Expr, toBits bool) ir.Expr {
	if e == nil || len(reg) < 2 {
		return e
	}
	var macro string
	switch reg[0] {
	case 'd':
		if toBits {
			macro = "ENI_BITCAST_U64"
		} else {
			macro = "ENI_BITCAST_F64"
		}
	case 's':
		if toBits {
			macro = "ENI_BITCAST_U32"
		} else {
			macro = "ENI_BITCAST_F32"
		}
	default:
		return e
	}
	return &ir.StaticMethodCall{Method: macro, Args: []ir.Expr{e}}
}

func signedTypeForWidth(width int) string {
	switch width {
	case 1:
		return "int8_t"
	case 2:
		return "int16_t"
	case 4:
		return "int32_t"
	default:
		return "int64_t"
	}
}

// noteStackWidth records an access width for a stack slot and, when no
// DWARF/FP type already owns that slot, infers a signed C type for the
// local from the widest access seen.
func (l *lifter) noteStackWidth(disp int32, width int) {
	if width <= 0 {
		return
	}
	if width > l.stackWidth[disp] {
		l.stackWidth[disp] = width
	}
	if l.stackTyped[disp] || l.opts.LocalTypes == nil {
		return
	}
	name, ok := l.stack[disp]
	if !ok || name == "" || strings.HasPrefix(name, "flocal_") || strings.HasPrefix(name, "dlocal_") {
		return
	}
	l.opts.LocalTypes[name] = signedTypeForWidth(l.stackWidth[disp])
}

// accessWidth returns the byte width of a load/store mnemonic. The
// byte/halfword forms override the register's natural width (a w8
// destination for ldrb is still a 1-byte access), while plain ldr/str
// and the unscaled ldur/stur family use the register width.
func accessWidth(inst native.DetailedInstruction) int {
	switch inst.Mnemonic {
	case "ldrb", "strb", "ldurb", "sturb", "ldxrb", "ldaxrb", "stxrb", "stlxrb":
		return 1
	case "ldrh", "strh", "ldurh", "sturh", "ldxrh", "ldaxrh", "stxrh", "stlxrh":
		return 2
	}
	if len(inst.Operands) > 0 && inst.Operands[0].Type == native.OperandReg {
		return regWidth(inst.Operands[0].Reg)
	}
	return 8
}

// regWidth returns the access width in bytes implied by the register an
// ldr/str names: x/w are the 8/4-byte integer accesses and the SIMD
// views map to their natural sizes (q=16, d=8, s=4, h=2, b=1). The
// width feeds the IL2CPP rewrite's cast type; unknown spellings
// default to 8, matching the plain "ldr" the lifter understands best.
func regWidth(reg string) int {
	switch reg {
	case "xzr":
		return 8
	case "wzr":
		return 4
	}
	if len(reg) < 2 {
		return 8
	}
	for _, c := range reg[1:] {
		if c < '0' || c > '9' {
			return 8
		}
	}
	switch reg[0] {
	case 'x':
		return 8
	case 'w':
		return 4
	case 'q':
		return 16
	case 'd':
		return 8
	case 's':
		return 4
	case 'h':
		return 2
	case 'b':
		return 1
	}
	return 8
}

// newFieldAccessOn builds the IR node for a memory access at disp
// through base. Name keeps the historical displacement-derived
// "field_<disp>" (decimal) spelling so every existing consumer and test
// is unchanged; Offset/HasOffset/Width are the IL2CPP-facing metadata
// (see ir.FieldAccess's own doc comment) and - when opts.Metadata has
// bound this function to a managed method and base is the `this`
// pointer - FieldName/TypeName carry the resolved field, which
// FieldAccess.String prefers over the synthetic name.
func (l *lifter) newFieldAccessOn(base ir.Expr, disp int32, width int) *ir.FieldAccess {
	fa := &ir.FieldAccess{
		Object: base,
		Name:   fmt.Sprintf("field_%d", disp),
		Disp:   disp,
		Width:  width,
	}
	if disp >= 0 {
		fa.HasOffset = true
		fa.Offset = uint64(disp)
	}
	if fa.HasOffset && l.thisType != "" && l.opts.Metadata != nil && l.isThisExpr(base) {
		if name, _, ok := l.opts.Metadata.FieldAtOffset(l.thisType, fa.Offset); ok {
			fa.FieldName = name
			fa.TypeName = l.thisType
		}
	}
	return fa
}

// memoryAccessTarget builds the IR lvalue/rvalue for a memory operand
// with an optional index register. It supports the immediate-LSL form
// ARM64 uses for arrays ([xN, xM, lsl #2]) and falls back to explicit
// byte-offset arithmetic when the shift does not match the access
// width. Unsupported shift forms return nil rather than emitting a
// wrong address.
//
// consume controls whether embedded expressions are marked consumed:
// a store target is always emitted as an AssignStmt (safe to consume),
// while a load may never surface (so its base/index stay unconsumed,
// mirroring liftLdr's existing policy).
func (l *lifter) memoryAccessTarget(base string, mem native.MemOperand, width int, consume bool) ir.Expr {
	if base == "" || base == "sp" {
		return nil
	}

	baseExpr := l.memBaseExpr(base)
	if consume {
		l.consume(baseExpr)
	}
	if mem.Index == "" {
		return l.newFieldAccessOn(baseExpr, mem.Disp, width)
	}

	shift := 0
	switch mem.IndexShiftType {
	case 0: // no shift
	case 1: // AARCH64_SFT_LSL
		shift = mem.IndexShiftValue
	default:
		// Register-controlled shifts and extenders cannot be
		// represented faithfully here yet.
		return nil
	}
	if shift < 0 || shift > 30 {
		return nil
	}

	idx := l.regValue(mem.Index)
	idx = applyIndexExtend(mem.IndexExtType, idx)
	if consume {
		l.consume(idx)
	}

	if mem.Disp != 0 {
		baseExpr = &ir.BinaryExpr{Op: "+", Left: baseExpr, Right: &ir.IntLit{Value: int64(mem.Disp)}}
	}

	if width > 0 && shift <= 4 && (1<<uint(shift)) == width {
		return &ir.ArrayAccess{Array: baseExpr, Index: idx, Width: width}
	}

	offset := idx
	if shift > 0 {
		offset = &ir.BinaryExpr{Op: "<<", Left: idx, Right: &ir.IntLit{Value: int64(shift)}}
	}
	return l.newFieldAccessOn(&ir.BinaryExpr{Op: "+", Left: baseExpr, Right: offset}, 0, width)
}

// applyIndexExtend wraps a memory index in its AArch64 extender
// (sxtw/uxtw/sxtb/...). The C renderer's casts preserve the signedness
// the address calculation needs; an extend of "none" is a no-op.
func applyIndexExtend(extType int, e ir.Expr) ir.Expr {
	if e == nil {
		return nil
	}
	var name string
	switch extType {
	case 1:
		name = "byte" // UXTB
	case 2:
		name = "ushort" // UXTH
	case 3:
		name = "uint" // UXTW
	case 5:
		name = "sbyte" // SXTB
	case 6:
		name = "short" // SXTH
	case 7:
		name = "int" // SXTW
	default:
		return e
	}
	return &ir.CastExpr{Type: &ir.PrimitiveType{Name: name}, Expr: e}
}

// isThisExpr reports whether e is the `this` pointer this lift seeded
// for an instance method - a LocalVar named "this" (the name
// LiftFunctionWithOptions gives parameter register x0 when Metadata
// identified the entry as an instance method).
func (l *lifter) isThisExpr(e ir.Expr) bool {
	lv, ok := e.(*ir.LocalVar)
	return ok && lv.Name == "this"
}

// isSectionLabel reports whether a resolver-provided name is a
// section-relative address label (".data+0x0", ".rodata+0x1fa0")
// rather than a real symbol. Section labels have no C declaration, so
// the C renderer needs their numeric address; ordinary symbols keep
// their name-based LocalVar rendering.
func isSectionLabel(name string) bool {
	return strings.HasPrefix(name, ".") && strings.Contains(name, "+0x")
}

// resolveAddrExpr turns a register's fully computed constant address
// into the most readable expression available: the string literal it
// points at (the common .rodata case), a symbol or ".section+0xoffset"
// label from the resolver, or - when neither resolves it - an AddrLit,
// which renders in hex rather than the unreadable decimal form the
// adrp/add pair's two raw constants used to produce. fallback is
// returned only for address 0, where no meaningful rendering exists.
func (l *lifter) resolveAddrExpr(addr uint64, fallback ir.Expr) ir.Expr {
	if addr == 0 {
		return fallback
	}
	if l.strings != nil {
		if s, ok := l.strings(addr); ok {
			return &ir.StringLit{Value: s}
		}
	}
	if l.resolver != nil {
		if n, ok := l.resolver(addr); ok {
			n = demangle(n)
			if isSectionLabel(n) {
				return &ir.AddrLit{Value: addr, Label: n}
			}
			return &ir.LocalVar{Name: n}
		}
	}
	return &ir.AddrLit{Value: addr}
}

// liftAdd lifts "add Rd, Rn, Rm" (register-register add) and
// "add Rd, Rn, #imm" (register-immediate) into an IR BinaryExpr,
// recorded as Rd's new value in the register file - not emitted as a
// statement yet, since a bare arithmetic result with nothing done with
// it isn't source-level meaningful on its own; it becomes a statement
// once something (a return, a store, ...) actually consumes it.
func (l *lifter) liftAdd(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 3 {
		return nil
	}
	dstOp, lhsOp, rhsOp := inst.Operands[0], inst.Operands[1], inst.Operands[2]
	if dstOp.Type != native.OperandReg || lhsOp.Type != native.OperandReg {
		return nil
	}

	switch rhsOp.Type {
	case native.OperandReg:
		lhs := l.regValue(lhsOp.Reg)
		rhs := applyOperandShift(rhsOp, l.regValue(rhsOp.Reg))
		l.consume(lhs)
		l.consume(rhs)
		return l.setReg(dstOp.Reg, &ir.BinaryExpr{Op: "+", Left: lhs, Right: rhs})
	case native.OperandImm:
		// "add Rd, Rn, #imm" - the standard -O0 second half of the
		// adrp+add idiom for reaching an exact symbol within an adrp's
		// page (see liftAddr), but also just ordinary immediate
		// arithmetic when Rn isn't a known address - propagate addrRegs
		// in the former case, alongside lifting the arithmetic either
		// way (nothing here can tell which this is until/unless the
		// result later gets used as a call argument - see buildCall).
		lhs := l.regValue(lhsOp.Reg)
		l.consume(lhs)
		rhs := applyOperandShift(rhsOp, &ir.IntLit{Value: rhsOp.Imm})
		base, isAddr := l.addrRegs[lhsOp.Reg]
		var val ir.Expr = &ir.BinaryExpr{Op: "+", Left: lhs, Right: rhs}
		if isAddr {
			immVal := uint64(rhsOp.Imm)
			if rhsOp.ShiftType == 1 { // AARCH64_SFT_LSL
				immVal <<= uint(rhsOp.ShiftValue)
			}
			newBase := base + immVal
			// The page+offset sum is now a complete address: resolve it
			// to a string literal / symbol / section label (or, failing
			// all three, keep it as a hex AddrLit) instead of leaving
			// the two raw decimal constants in the output.
			val = l.resolveAddrExpr(newBase, val)
			stmts := l.setReg(dstOp.Reg, val)
			l.addrRegs[dstOp.Reg] = newBase
			return stmts
		}
		return l.setReg(dstOp.Reg, val)
	default:
		return nil
	}
}

// aluOps maps an ALU/shift mnemonic (other than "add", which liftAdd
// handles separately - see its own doc comment for why) to its IR
// BinaryExpr operator and whether ARM64 actually encodes an
// immediate-operand form for it at all - paired with liftALU below.
var aluOps = map[string]struct {
	irOp     string
	allowImm bool
}{
	"sub": {"-", true},
	"and": {"&", true},
	"orr": {"|", true},
	"eor": {"^", true},
	"lsl": {"<<", true},
	"lsr": {">>", true},
	// asr (arithmetic shift right): ">>" is used as-is, correct for an
	// already non-negative operand - this project's IR has no
	// separate unsigned/signed-arithmetic shift operator, the same
	// accepted approximation as the b.hs/b.lo/b.hi/b.ls unsigned
	// condition codes already documented in condOpFromMnemonic.
	"asr": {">>", true},
	// mul has no immediate-operand encoding at all in AArch64 (always
	// register*register) - allowImm=false rejects an immediate rhs as
	// an ISA-level fact, not an arbitrary lifter restriction.
	"mul":  {"*", false},
	"udiv": {"/", false},
	"sdiv": {"/", false},
	"fadd": {"+", false},
	"fsub": {"-", false},
	"fmul": {"*", false},
	"fdiv": {"/", false},
}

// liftALU lifts the common "Rd, Rn, Rm" (register-register) or
// "Rd, Rn, #imm" (register-immediate) ALU/shift instruction shape -
// every mnemonic in aluOps - into an ir.BinaryExpr, recorded as Rd's
// new value in the register file. Not emitted as a statement of its
// own: same reasoning as liftAdd (its closest sibling, kept separate
// since it also propagates addrRegs for the adrp+add idiom, which
// none of these other ops ever participate in) - a bare arithmetic
// result only becomes source-level meaningful once something (a
// return, a call argument, ...) actually consumes it.
func (l *lifter) liftALU(inst native.DetailedInstruction) []ir.Stmt {
	op, ok := aluOps[inst.Mnemonic]
	if !ok {
		return nil
	}
	// Capstone reports immediate shifts ("asr x8, x8, #3") as two
	// structured operands with the amount only in OpStr, unlike add/sub
	// which expose a third immediate operand.
	if len(inst.Operands) == 2 && (inst.Mnemonic == "lsl" || inst.Mnemonic == "lsr" || inst.Mnemonic == "asr") {
		dstOp, srcOp := inst.Operands[0], inst.Operands[1]
		if dstOp.Type != native.OperandReg || srcOp.Type != native.OperandReg {
			return nil
		}
		shift, ok := trailingImmediate(inst.OpStr)
		if !ok {
			return nil
		}
		lhs := l.regValue(srcOp.Reg)
		l.consume(lhs)
		if !strings.HasPrefix(inst.Mnemonic, "f") {
			lhs = fpViewBitcast(srcOp.Reg, lhs, true)
		}
		return l.setReg(dstOp.Reg, &ir.BinaryExpr{Op: op.irOp, Left: lhs, Right: &ir.IntLit{Value: shift}})
	}
	if len(inst.Operands) != 3 {
		return nil
	}
	dstOp, lhsOp, rhsOp := inst.Operands[0], inst.Operands[1], inst.Operands[2]
	if dstOp.Type != native.OperandReg || lhsOp.Type != native.OperandReg {
		return nil
	}
	lhs := l.regValue(lhsOp.Reg)
	l.consume(lhs)
	// fadd/fsub/fmul/fdiv operate on real FP values; every other op in
	// aluOps is an integer/bitwise operation, so d/s register operands
	// must be viewed as their raw bits (NEON orr/and/eor, vector shifts).
	integerOp := !strings.HasPrefix(inst.Mnemonic, "f")
	if integerOp {
		lhs = fpViewBitcast(lhsOp.Reg, lhs, true)
	}

	switch rhsOp.Type {
	case native.OperandReg:
		rhsVal := l.regValue(rhsOp.Reg)
		l.consume(rhsVal)
		if integerOp {
			rhsVal = fpViewBitcast(rhsOp.Reg, rhsVal, true)
		}
		rhs := applyOperandShift(rhsOp, rhsVal)
		val := ir.Expr(&ir.BinaryExpr{Op: op.irOp, Left: lhs, Right: rhs})
		if integerOp {
			val = fpViewBitcast(dstOp.Reg, val, false)
		}
		return l.setReg(dstOp.Reg, val)
	case native.OperandImm:
		if !op.allowImm {
			return nil
		}
		rhs := applyOperandShift(rhsOp, &ir.IntLit{Value: rhsOp.Imm})
		val := ir.Expr(&ir.BinaryExpr{Op: op.irOp, Left: lhs, Right: rhs})
		if integerOp {
			val = fpViewBitcast(dstOp.Reg, val, false)
		}
		return l.setReg(dstOp.Reg, val)
	case native.OperandFP:
		return l.setReg(dstOp.Reg, &ir.BinaryExpr{Op: op.irOp, Left: lhs, Right: fpLit(dstOp.Reg, rhsOp.FP)})
	default:
		return nil
	}
}

// fpLit builds a float/double literal matching the destination
// register's view width.
func fpLit(reg string, v float64) ir.Expr {
	if strings.HasPrefix(reg, "s") {
		return &ir.FloatLit{Value: float32(v)}
	}
	return &ir.DoubleLit{Value: v}
}

// trailingImmediate parses the last "#N" from an operand string such as
// "x8, x8, #3".
func trailingImmediate(opStr string) (int64, bool) {
	idx := strings.LastIndex(opStr, "#")
	if idx < 0 {
		return 0, false
	}
	txt := strings.TrimSpace(opStr[idx+1:])
	if j := strings.IndexAny(txt, ", "); j >= 0 {
		txt = txt[:j]
	}
	n, err := strconv.ParseInt(txt, 0, 64)
	return n, err == nil
}

// applyOperandShift wraps e in the shift named by an operand's own
// detail shift field (the ", lsl #3" in "add x0, x1, x2, lsl #3" or
// "tst x0, x1, lsr #2"). Only immediate LSL/LSR/ASR are modelled;
// register-controlled shifts and extenders are left as-is rather than
// guessed (their register id is not an immediate amount).
func applyOperandShift(op native.Operand, e ir.Expr) ir.Expr {
	if e == nil {
		return nil
	}
	switch op.ShiftType {
	case 0: // AARCH64_SFT_INVALID: no shift
		return e
	case 1: // AARCH64_SFT_LSL
		if op.ShiftValue > 0 {
			return &ir.BinaryExpr{Op: "<<", Left: e, Right: &ir.IntLit{Value: int64(op.ShiftValue)}}
		}
		return e
	case 3, 4: // AARCH64_SFT_LSR / AARCH64_SFT_ASR
		if op.ShiftValue > 0 {
			return &ir.BinaryExpr{Op: ">>", Left: e, Right: &ir.IntLit{Value: int64(op.ShiftValue)}}
		}
		return e
	default:
		// Register-controlled shifts and ROR/MSL have no direct C
		// equivalent in this IR; leave the value unshifted rather than
		// inventing a wrong expression.
		return e
	}
}

// liftAddr lifts "adrp Xd, #page" and "adr Xd, #addr" - both compute a
// PC-relative absolute address into Xd (Capstone resolves the
// encoded, page- or byte-relative immediate to the final absolute
// address already, the same way it does for branch targets - see
// branchTarget's own note); adrp's is page-aligned and typically needs
// a following "add Xd, Xd, #imm" to reach an exact symbol (see
// liftAdd's immediate case), while adr's is already byte-precise on
// its own. Recorded in addrRegs (see its own doc comment) for later
// resolution to a string literal when the register is actually used;
// also given an ordinary IntLit placeholder in regs so a use this
// lifter doesn't (yet) resolve to a string still degrades to a
// plausible numeric address rather than an unrelated stale value.
func (l *lifter) liftAddr(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg || inst.Operands[1].Type != native.OperandImm {
		return nil
	}
	dst, imm := inst.Operands[0], inst.Operands[1]
	stmts := l.setReg(dst.Reg, &ir.AddrLit{Value: uint64(imm.Imm)})
	l.addrRegs[dst.Reg] = uint64(imm.Imm)
	return stmts
}

// liftMovWide lifts the 16-bit immediate materialisation family:
//
//	movz Rd, #imm, lsl #shift   Rd = imm << shift
//	movk Rd, #imm, lsl #shift   Rd = (Rd & ~(0xffff<<shift)) | (imm<<shift)
//	movn Rd, #imm, lsl #shift   Rd = ~(imm << shift)
//
// Capstone often aliases movz/movn to plain "mov", which liftMov already
// handles; movk is the one that really needs this path, since -O0 code
// builds every larger constant as mov/movz followed by one or more
// movk. Constant operands are folded; only the uncommon non-constant
// movk target stays as explicit mask/shift arithmetic.
func (l *lifter) liftMovWide(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 2 {
		return nil
	}
	dstOp, srcOp := inst.Operands[0], inst.Operands[1]
	if dstOp.Type != native.OperandReg || srcOp.Type != native.OperandImm {
		return nil
	}
	shift := 0
	if srcOp.ShiftType == 1 { // AARCH64_SFT_LSL
		shift = srcOp.ShiftValue
	}
	if shift < 0 || shift > 48 {
		return nil
	}
	bits := uint(regWidth(dstOp.Reg) * 8)
	if bits == 0 || bits > 64 {
		bits = 64
	}
	imm := uint64(srcOp.Imm) & 0xffff
	shifted := imm << uint(shift)

	switch inst.Mnemonic {
	case "movz":
		return l.setReg(dstOp.Reg, &ir.IntLit{Value: int64(truncateToBits(shifted, bits))})
	case "movn":
		return l.setReg(dstOp.Reg, &ir.IntLit{Value: int64(truncateToBits(^shifted, bits))})
	case "movk":
		old := l.regValue(dstOp.Reg)
		mask := uint64(0xffff) << uint(shift)
		if c, ok := constantOf(old); ok {
			v := truncateToBits((c & ^mask)|shifted, bits)
			return l.setReg(dstOp.Reg, &ir.IntLit{Value: int64(v)})
		}
		l.consume(old)
		val := &ir.BinaryExpr{
			Op: "|",
			Left: &ir.BinaryExpr{
				Op:    "&",
				Left:  old,
				Right: &ir.IntLit{Value: int64(^mask)},
			},
			Right: &ir.IntLit{Value: int64(shifted)},
		}
		return l.setReg(dstOp.Reg, val)
	default:
		return nil
	}
}

// liftMov lifts "mov Rd, Rn" (register-to-register) and "mov Rd, #imm"
// (register-immediate) - the two shapes real -O0 code uses constantly
// to shuttle values into the callee-saved registers (x19-x28) that
// survive across calls, since AAPCS64 lets a callee clobber x0-x18
// freely. A register-to-register move does NOT count as consuming its
// source: it's a rename, not a use, so the value must remain just as
// flushable/embeddable under its new name as it was under the old one
// (see isOrphanCandidate's own reachable-under-another-name check).
func (l *lifter) liftMov(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg {
		return nil
	}
	dst, src := inst.Operands[0], inst.Operands[1]
	switch src.Type {
	case native.OperandReg:
		// A register-to-register move of a known address must carry the
		// addrRegs entry along with the value: the standard -O0 idiom
		// for reaching a string literal is "adrp xN, #page; add xN,
		// xN, #off" followed by moving xN into an argument register
		// right before the call ("mov x1, x28; bl strcmp"), and
		// without this the string resolution in collectCallArgsN would
		// see only the raw computed address arithmetic
		// ("12288 + 3349") instead of the "--pid" it points at.
		// setReg deletes any stale addrRegs entry first (its clobber
		// step), so the entry is re-installed after it returns.
		if addr, ok := l.addrRegs[src.Reg]; ok {
			stmts := l.setReg(dst.Reg, l.regValue(src.Reg))
			l.addrRegs[dst.Reg] = addr
			return stmts
		}
		return l.setReg(dst.Reg, l.regValue(src.Reg))
	case native.OperandImm:
		return l.setReg(dst.Reg, &ir.IntLit{Value: src.Imm})
	default:
		return nil
	}
}

// collectCallArgs gathers a call's own arguments from x0-x7 (AAPCS64's
// integer/pointer argument registers) as they stand right now, before
// the call overwrites any of them with its own return value - shared
// by buildCall (a direct call, resolved by address) and
// buildIndirectCall (a call through whatever a register currently
// holds - "blr"/"br"), since collecting the arguments themselves
// doesn't depend on how the callee is identified. Stops at the first
// register this lifter never actually assigned a value to (see
// regValue's own placeholder-on-miss behavior; checked directly
// against l.regs here rather than through regValue, since regValue
// itself can't distinguish "genuinely holds this register's raw value
// because nothing overwrote it" from "known assigned value"). This is
// a heuristic, not a real signature lookup (nothing in the binary
// reliably encodes how many arguments a given call actually passes) -
// it works for the common case where a function's own argument-passing
// code runs immediately before the call and doesn't happen to also
// touch unrelated argument registers for other reasons, but can
// overcount or undercount on more unusual codegen. See the TODO at the
// bottom of this file.
func (l *lifter) collectCallArgs() []ir.Expr {
	return l.collectCallArgsN(len(aapcs64IntArgRegs))
}

// collectCallArgsN is collectCallArgs capped at at most n registers -
// used when the callee's real arity is actually known (see
// knownArity), so a genuinely zero/fixed-argument well-known ABI
// function (__stack_chk_fail, pthread_mutex_lock, ...) can never
// scavenge an unrelated leftover value out of x0-x7 the way the
// general heuristic otherwise would. n == len(aapcs64IntArgRegs) (via
// collectCallArgs) reproduces the original unlimited heuristic
// exactly.
func (l *lifter) collectCallArgsN(n int) []ir.Expr {
	var args []ir.Expr
	for i, reg := range aapcs64IntArgRegs {
		if i >= n {
			break
		}
		v, ok := l.regs[reg]
		if !ok {
			break
		}
		// A value still sitting in an argument register implicitly from
		// a PREVIOUS call's own return (see resultRegs' doc comment) was
		// never explicitly assigned as part of THIS call's argument
		// setup - AAPCS64 lets any callee clobber x0-x7, and real -O0
		// code always writes every argument register it actually passes
		// before the call. Carrying such a stale result over as if it
		// were an argument is exactly the bug this guard exists to
		// prevent (e.g. "bl a; bl b" rendering as "b(a())" when the
		// source was two independent zero-argument calls).
		if l.resultRegs[reg] {
			break
		}
		// Seeded incoming arguments that this function never wrote were
		// not explicitly set up for this call; stop here rather than
		// spraying xN placeholders into every unresolved call.
		if l.isSeedReg(reg) {
			break
		}
		// If this register currently holds a known address (from
		// adrp/adr, possibly via a following add - see addrRegs' own
		// doc comment) and it resolves to an actual string literal,
		// render the literal itself rather than the raw computed
		// address - this is the whole point of tracking addrRegs in
		// the first place. Falls back to the placeholder numeric value
		// already in v when the address doesn't resolve (most likely:
		// it's some other kind of data - a pointer, a vtable - not a
		// plain C string).
		if addr, isAddr := l.addrRegs[reg]; isAddr && l.strings != nil {
			if s, ok := l.strings(addr); ok {
				v = &ir.StringLit{Value: s}
			}
		}
		v = l.zeroExtend(reg, v)
		l.consume(v)
		args = append(args, v)
	}
	return args
}

// zeroExtend wraps a 32-bit register write's value when read through its
// 64-bit alias, matching AArch64's W->X zero-extension.
func (l *lifter) zeroExtend(reg string, v ir.Expr) ir.Expr {
	if v == nil || l.regWidths[reg] != 32 {
		return v
	}
	switch v.(type) {
	case *ir.StringLit, *ir.AddrLit:
		return v
	}
	return &ir.CastExpr{Type: &ir.PrimitiveType{Name: "uint"}, Expr: v}
}

// isSeedReg reports whether reg still holds exactly the value it was
// seeded with at function entry.
func (l *lifter) isSeedReg(reg string) bool {
	if l.written[reg] {
		return false
	}
	seed, ok := l.seedRefs[reg]
	if !ok {
		return false
	}
	cur, ok := l.regs[reg]
	return ok && seed == cur
}

// collectTailCallArgs is the tail-call counterpart of collectCallArgs:
// every ABI argument register is forwarded. Registers the callee
// explicitly set use their current value; untouched ones fall back to
// their incoming register (x0..x7 in the generated signature), which is
// exactly what the hardware jump would pass through.
func (l *lifter) collectTailCallArgs() []ir.Expr {
	args := make([]ir.Expr, 0, len(aapcs64IntArgRegs))
	for _, reg := range aapcs64IntArgRegs {
		v, ok := l.regs[reg]
		if !ok {
			args = append(args, &ir.LocalVar{Name: l.regName(reg)})
			continue
		}
		if addr, isAddr := l.addrRegs[reg]; isAddr && l.strings != nil {
			if s, ok := l.strings(addr); ok {
				v = &ir.StringLit{Value: s}
			}
		}
		v = l.zeroExtend(reg, v)
		l.consume(v)
		args = append(args, v)
	}
	return args
}

// buildCall resolves target to a readable name via l.resolver (falling
// back to a "func_<address>" placeholder if resolution fails or there
// is no resolver) and builds the call expression from whatever's
// currently sitting in x0-x7, shared by both liftCall ("bl", an
// ordinary call resolution is optional - an unresolved target still
// gets a placeholder name) and liftTailCall ("b" used as a tail call,
// where requireResolved must be true: an unresolved "b" target is far
// more likely an intra-function loop back-edge this lifter doesn't yet
// understand than a real call, and misreading one as a call to a
// nonsense "func_<addr>" placeholder would be actively worse than the
// current silent skip - see isAnyBranch's own note on "b" ending a
// block). Returns ok=false when requireResolved is true and resolution
// failed - the only failure case, since an ordinary unresolved call
// still produces a usable (if uninformative) placeholder call.
func (l *lifter) buildCall(target uint64, requireResolved bool, tail bool) (ir.Expr, bool) {
	rawName := fmt.Sprintf("func_%x", target)
	resolved := false
	if l.resolver != nil {
		if n, ok := l.resolver(target); ok {
			rawName = n
			resolved = true
		}
	}
	if requireResolved && !resolved {
		return nil, false
	}
	name := demangle(rawName)

	var args []ir.Expr
	if n, known := knownArity[rawName]; known {
		args = l.collectCallArgsN(n)
	} else if tail {
		// A tail call transfers whatever is still live in the ABI
		// argument registers, not just the prefix explicitly written.
		// The generated signature always declares x0..x7, so filling
		// the untouched ones with their incoming register value keeps
		// the jump faithful (a plain forward of the caller's args).
		args = l.collectTailCallArgs()
	} else {
		args = l.collectCallArgs()
	}

	// A mangled Itanium C++ instance method name (recognized by the
	// standard "_ZN...E" nested-name pattern, as opposed to a free
	// function's "_Z<len><name>") always receives the implicit `this`
	// pointer as its first argument - render it as the call's receiver
	// rather than an ordinary first argument, for readability. Not
	// reliable for a STATIC member function (mangled the same way, but
	// with no real `this`) - there's no way to tell the two apart from
	// the mangled name alone without a real demangler that understands
	// the full grammar; see the TODO at the bottom of this file.
	//
	// Also excluded: args[0] itself being a call result (*MethodCall,
	// *StaticMethodCall, or *IndirectCall) - without real stack-slot
	// tracking, this lifter can't tell "x0 holds a genuinely-reloaded
	// object pointer" from "x0 still holds the PREVIOUS call's leftover
	// return value" in general, but it CAN identify this one case,
	// which is never a valid `this` (a real `this` is a variable/
	// pointer value, not literally the return value of some unrelated
	// call) - excluding it avoids the worst symptom (a nonsensical
	// call1().call2().call3() dot-chain from independent sequential
	// calls) even though the underlying ambiguity for other cases
	// remains unresolved. See the TODO at the bottom of this file.
	isCallResult := false
	if len(args) > 0 {
		switch args[0].(type) {
		case *ir.MethodCall, *ir.StaticMethodCall, *ir.IndirectCall:
			isCallResult = true
		}
	}

	var call ir.Expr
	if resolved && looksLikeInstanceMethod(rawName) && len(args) > 0 && !isCallResult {
		call = &ir.MethodCall{Object: args[0], Name: methodNameOnly(name), Args: args[1:]}
	} else {
		call = &ir.StaticMethodCall{Method: name, Args: args}
	}
	return call, true
}

// finishCall applies a just-built call's effect on the register file:
// x0-x7 (and their w-register aliases) are caller-saved per AAPCS64 -
// the called function is free to clobber any of them, so whatever was
// sitting in them before this call is no longer trustworthy afterward
// (each clobber flushes it first if it was itself an unconsumed call
// result - see clobberReg). w0/x0 then become the new call's own
// result. call is also recorded in l.calls so flushRemaining can still
// emit it later if nothing ever ends up reading w0/x0.
func (l *lifter) finishCall(call ir.Expr) []ir.Stmt {
	var stmts []ir.Stmt
	for i := range aapcs64IntArgRegs {
		stmts = append(stmts, l.clobberReg(aapcs64IntArgRegs[i])...)
		stmts = append(stmts, l.clobberReg(aapcs64IntArgRegs32[i])...)
	}
	l.calls = append(l.calls, call)
	stmts = append(stmts, l.setReg("w0", call)...)
	stmts = append(stmts, l.setReg("x0", call)...)
	// Mark the return-value registers as implicitly holding this call's
	// result, so the NEXT call's argument collection never mistakes them
	// for its own explicitly-set arguments - see resultRegs' own doc
	// comment.
	l.resultRegs["w0"] = true
	l.resultRegs["x0"] = true
	return stmts
}

// liftCall lifts "bl <addr>" - a direct function call - into a call
// expression recorded as the new value of w0/x0 (AAPCS64's
// return-value register). Not emitted as a statement immediately:
// mirroring liftAdd's reasoning, the call only becomes its own visible
// statement once it's clear nothing will ever consume its result as a
// value - see clobberReg (superseded before anything reads it) and
// flushRemaining (never read at all before this path ends).
func (l *lifter) liftCall(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 1 || inst.Operands[0].Type != native.OperandImm {
		return nil
	}
	target := uint64(inst.Operands[0].Imm)
	if stmts, ok := l.inlineOutlinedCall(target); ok {
		return stmts
	}
	call, ok := l.buildCall(target, false, false)
	if !ok {
		return nil
	}
	return l.finishCall(call)
}

// inlineOutlinedCall inlines a straight-line "bl" target located inside the
// current function (a compiler-outlined local subroutine, common in
// obfuscated binaries). The caller's live register/stack state is used
// directly, so no ABI wrapper or context struct is needed. Branched or
// recursive blocks fall back to the ordinary unresolved call path.
func (l *lifter) inlineOutlinedCall(target uint64) ([]ir.Stmt, bool) {
	if l.insnIndex == nil || l.outlinedDepth >= 4 {
		return nil, false
	}
	if target <= l.functionStart || target >= l.functionEnd {
		return nil, false
	}
	if l.opts.KnownFunction != nil && l.opts.KnownFunction(target) {
		return nil, false
	}
	idx, ok := l.insnIndex[target]
	if !ok {
		return nil, false
	}
	end := idx
	for end < len(l.functionInsns) {
		in := l.functionInsns[end]
		if in.Mnemonic == "ret" {
			break
		}
		if in.Mnemonic == "br" || (isAnyBranch(in) && in.Mnemonic != "bl") {
			return nil, false
		}
		if end-idx >= 200 {
			return nil, false
		}
		end++
	}
	if end >= len(l.functionInsns) || l.functionInsns[end].Mnemonic != "ret" {
		return nil, false
	}
	l.outlinedDepth++
	stmts := l.run(l.functionInsns[idx:end])
	l.outlinedDepth--
	return stmts, true
}

// liftTailCall lifts a plain "b <addr>" as a tail call when its target
// resolves to a known symbol - the standard -O0 codegen for a
// function's last action being a call whose result (if any) becomes
// this function's own return value, via AAPCS64 tail-call convention
// rather than an explicit "bl"+"ret" pair. Requires a resolved target
// (see buildCall's own doc comment) so an ordinary intra-function
// branch (a loop back-edge, say - not yet understood by this lifter)
// is never misread as a call to a bogus "func_<addr>" placeholder.
//
// Unlike liftCall, the resulting call is emitted as this function's
// ReturnStmt immediately: the callee's result is forwarded to our own
// caller (or is discarded if the callee never returns, e.g. abort).
func (l *lifter) liftTailCall(inst native.DetailedInstruction) []ir.Stmt {
	target, ok := branchTarget(inst)
	if !ok {
		return nil
	}
	// A "b" whose target is a basic block of THIS function is an ordinary
	// intra-function branch, not a tail call. run() lifts the block's
	// instructions unconditionally, so without this check the synthetic
	// unresolved-tail-target fallback would emit a bogus func_<addr>() and
	// truncate the rest of the function.
	if l.cfg != nil && l.cfg.blocks[target] {
		return nil
	}
	call, ok := l.buildCall(target, true, true)
	if !ok && l.opts.CodeContains != nil && l.opts.CodeContains(target) {
		// Targets without unwind/symbol metadata (e.g. context-restore
		// trampolines reached only by tail branches) still represent a
		// real cross-function call. Keep the placeholder name rather
		// than emitting nothing and producing an empty function body.
		call, ok = l.buildCall(target, false, true)
	}
	if !ok {
		return nil
	}
	stmts := l.finishCall(call)
	l.consume(call)
	// A tail call's result IS this function's result: after the callee
	// returns, its x0 is forwarded to our caller.
	return append(stmts, &ir.ReturnStmt{Value: call})
}

// buildIndirectCall builds a call expression whose callee is an
// arbitrary EXPRESSION - whatever calleeReg currently holds - rather
// than a name resolved from a statically known address, for "blr Rn"
// (an ordinary call through a register) and "br Rn" (the same, but in
// tail position - see liftBr's own doc comment). There's no symbol to
// resolve here at all, so unlike buildCall this never fails: the
// callee is rendered as whatever expression is available, even if
// that's just a raw register-name placeholder (see regValue's own doc
// comment) when this lifter never learned anything more specific about
// it - most often, in real -O0 C++ code, a vtable slot loaded through a
// chain of FieldAccess dereferences (see liftLdr's own doc comment).
func (l *lifter) buildIndirectCall(calleeReg string, tail bool) ir.Expr {
	callee := l.regValue(calleeReg)
	l.consume(callee)
	args := l.collectCallArgs()
	if tail {
		args = l.collectTailCallArgs()
	}
	return &ir.IndirectCall{Callee: callee, Args: args}
}

// liftBlr lifts "blr Rn" - an ordinary call through a register - into
// a call expression recorded as w0/x0's new value, exactly like
// liftCall does for "bl", just with buildIndirectCall's
// resolved-from-a-register callee instead of buildCall's
// resolved-from-an-address one.
func (l *lifter) liftBlr(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 1 || inst.Operands[0].Type != native.OperandReg {
		return nil
	}
	call := l.buildIndirectCall(inst.Operands[0].Reg, false)
	return l.finishCall(call)
}

// liftBr lifts "br Rn" - an unconditional, indirect JUMP through a
// register (ending this block's own control flow - see isAnyBranch's
// own doc comment on why this counts as a branch for CFG purposes,
// unlike "blr") - as an indirect tail call: the standard -O0 shape for
// a C++ virtual-dispatch thunk (load a vtable slot, tail-call through
// it, forwarding this function's own arguments unchanged) that
// liftTailCall's own "b <addr>" handling can't cover, since there's no
// resolvable address here at all. Exactly like liftTailCall, the call is
// the function's own ReturnStmt, forwarding the callee's result.
func (l *lifter) liftBr(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 1 || inst.Operands[0].Type != native.OperandReg {
		return nil
	}
	call := l.buildIndirectCall(inst.Operands[0].Reg, true)
	stmts := l.finishCall(call)
	l.consume(call)
	// As with a direct tail call, the callee's result is forwarded as
	// this function's own return value.
	return append(stmts, &ir.ReturnStmt{Value: call})
}

// looksLikeInstanceMethod reports whether a raw (still-mangled) Itanium
// C++ symbol name has the "_ZN...E" nested-name shape used for
// namespace/class members - a heuristic, not a real demangler: it
// can't distinguish a STATIC member function (mangled identically, but
// with no real `this` receiver) from an instance method. See
// liftCall's own doc comment for why that's an accepted limitation for
// now.
func looksLikeInstanceMethod(rawName string) bool {
	return strings.HasPrefix(rawName, "_ZN") && strings.Contains(rawName, "E")
}

// methodNameOnly extracts the last path component of a name that may
// contain "::" separators (e.g. "utils::is_root" -> "is_root") - used
// so a MethodCall's receiver.method(...) rendering doesn't repeat the
// class/namespace qualification a real "obj.method()" call site
// wouldn't spell out redundantly. Falls back to the whole name
// unchanged if it contains no "::".
func methodNameOnly(name string) string {
	if idx := strings.LastIndex(name, "::"); idx >= 0 {
		return name[idx+2:]
	}
	return name
}

// demangle renders an Itanium C++ ABI mangled symbol ("_Z...") down to
// its bare, readable qualified name via itaniumDemangle (demangle.go) -
// e.g. "std::__ndk1::basic_string<char, ...>::find". Falls back to the
// name unchanged whenever it isn't Itanium-mangled at all, or when
// itaniumDemangle hits any construct it doesn't recognize - matching
// this project's existing "never render something silently wrong"
// philosophy, since a partially-wrong demangling would be worse than
// the still-legible raw mangled form.
func demangle(name string) string {
	if d, ok := itaniumDemangle(name); ok {
		return d
	}
	return name
}

// flagCondition builds the expression a b.cond/cset/csel tests for the
// given comparison operator, using the most recent cmp/ccmp/tst/subs
// snapshot. A missing snapshot degrades to the explicit "cond"
// placeholder, matching the branch path's own fallback.
func (l *lifter) flagCondition(op string) ir.Expr {
	if l.lastCmp == nil || op == "" || op == "?" {
		if l.opts.CondMiss != nil {
			l.opts.CondMiss(op, l.curAddr)
		}
		return &ir.LocalVar{Name: "cond"}
	}
	cmp := &ir.BinaryExpr{Op: op, Left: l.lastCmp.lhs, Right: l.lastCmp.rhs}
	if l.lastCmp.combine != nil {
		return l.lastCmp.combine(op, cmp)
	}
	return cmp
}

// liftCsel lifts the conditional-select family:
//
//	csel  Rd, Rn, Rm, cond   Rd = cond ? Rn : Rm
//	csinc Rd, Rn, Rm, cond   Rd = cond ? Rn : Rm + 1
//	csinv Rd, Rn, Rm, cond   Rd = cond ? Rn : ~Rm
//	csneg Rd, Rn, Rm, cond   Rd = cond ? Rn : -Rm
//
// Capstone exposes the condition only in OpStr (there is no fourth
// structured operand for it), so it is parsed from the trailing
// ", <cond>" exactly like liftCset does.
func (l *lifter) liftCsel(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 3 {
		return nil
	}
	dstOp, trueOp, falseOp := inst.Operands[0], inst.Operands[1], inst.Operands[2]
	if dstOp.Type != native.OperandReg || trueOp.Type != native.OperandReg || falseOp.Type != native.OperandReg {
		return nil
	}

	condText := inst.OpStr
	if idx := strings.LastIndex(condText, ", "); idx >= 0 {
		condText = condText[idx+2:]
	}
	condOp := condOpFromMnemonic("b." + condText)
	cond := l.flagCondition(condOp)

	trueExpr := l.regValue(trueOp.Reg)
	l.consume(trueExpr)
	falseExpr := l.regValue(falseOp.Reg)
	l.consume(falseExpr)

	bits := uint(regWidth(falseOp.Reg) * 8)
	if bits == 0 || bits > 64 {
		bits = 64
	}
	switch inst.Mnemonic {
	case "csinc":
		if c, ok := constantOf(falseExpr); ok {
			falseExpr = &ir.IntLit{Value: int64(truncateToBits(c+1, bits))}
		} else {
			falseExpr = &ir.BinaryExpr{Op: "+", Left: falseExpr, Right: &ir.IntLit{Value: 1}}
		}
	case "csinv":
		if c, ok := constantOf(falseExpr); ok {
			falseExpr = &ir.IntLit{Value: int64(truncateToBits(^c, bits))}
		} else {
			falseExpr = &ir.UnaryExpr{Op: "~", Expr: falseExpr}
		}
	case "csneg":
		if c, ok := constantOf(falseExpr); ok {
			falseExpr = &ir.IntLit{Value: int64(truncateToBits(-c, bits))}
		} else {
			falseExpr = &ir.UnaryExpr{Op: "-", Expr: falseExpr}
		}
	}

	return l.setReg(dstOp.Reg, &ir.TernaryExpr{Cond: cond, TrueExpr: trueExpr, FalseExpr: falseExpr})
}

// liftCset lifts "cset Rd, <cond>" - sets Rd to 1 if the condition
// (tested against flags from the most recently lifted cmp, the same
// mechanism liftCondition uses for b.cond) holds, 0 otherwise - the
// standard -O0 codegen for a boolean-returning comparison expression
// like "return a == b;". Unlike b.cond, Capstone doesn't expose cset's
// condition as a separate structured field or operand; it's embedded in
// OpStr as plain text (e.g. "w0, eq"), so it's extracted from there
// directly rather than through inst.Operands.
func (l *lifter) liftCset(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 1 || inst.Operands[0].Type != native.OperandReg {
		return nil
	}
	dst := inst.Operands[0]

	// OpStr is "Rd, cond" (Capstone's text form) - the condition is
	// whatever's after the last ", ".
	condText := inst.OpStr
	if idx := strings.LastIndex(condText, ", "); idx >= 0 {
		condText = condText[idx+2:]
	}
	op := condOpFromMnemonic("b." + condText)

	return l.setReg(dst.Reg, l.flagCondition(op))
}

// consume marks e as accounted for - already embedded into some larger
// expression (a call argument, a comparison operand, a return value) -
// so flushRemaining and the inline orphan-detection in clobberReg never
// emit it as its own redundant statement. Safe to call with any Expr,
// including one that was never a call in the first place (consumed's
// only reader, isOrphanCandidate, already filters by type).
func (l *lifter) consume(e ir.Expr) {
	if e == nil {
		return
	}
	l.consumed[e] = true
}

// isOrphanCandidate reports whether e is a call expression that is
// about to become truly unreachable: not yet consumed, and not sitting
// in any OTHER register besides exceptReg (the one currently being
// overwritten/cleared) - e.g. a value mov'd into a callee-saved
// register earlier is still reachable under that second name even
// after its original register gets clobbered, so it must NOT be
// flushed yet.
func (l *lifter) isOrphanCandidate(e ir.Expr, exceptReg string) bool {
	if e == nil || l.consumed[e] {
		return false
	}
	switch e.(type) {
	case *ir.MethodCall, *ir.StaticMethodCall, *ir.IndirectCall:
	default:
		return false
	}
	for reg, v := range l.regs {
		if reg == exceptReg {
			continue
		}
		if v == e {
			return false
		}
	}
	return true
}

// clobberReg removes reg's current value, first flushing it as its own
// ExprStmt if it's an orphaned call result (see isOrphanCandidate) -
// the inline half of "a call whose result is never used still needs to
// appear in the output", covering the common case where a NEW write to
// the same register (another call's argument setup, another call's own
// return value, ...) supersedes it before anything reads it. The other
// half, flushRemaining, covers a call that survives all the way to the
// end of this lifter's path without ever being overwritten OR read.
// wRegToX returns the 64-bit register name aliasing the SAME physical
// register as reg, and true - or ("", false) if reg isn't a plain
// "w<N>" name. Writing a W register always zero-extends into the full
// X register on real AArch64 hardware, so clobberReg/setReg mirror
// every W-register write (or clobber) into its X alias too - the
// direction that matters for THIS lifter, since buildCall's
// arg-collection and liftRet both read the X-named register (per
// aapcs64IntArgRegs), even for a value that only ever makes sense as
// the 32-bit "int" a W-only write actually computed. The reverse (an
// X-register write propagating down into its W alias) is deliberately
// NOT done: a 64-bit value's low 32 bits aren't obviously "the same
// value" the way zero-extension makes the W->X direction exact, and
// nothing in this lifter currently needs it.
func wRegToX(reg string) (string, bool) {
	if len(reg) < 2 || reg[0] != 'w' {
		return "", false
	}
	for _, c := range reg[1:] {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	return "x" + reg[1:], true
}

func (l *lifter) clobberReg(reg string) []ir.Stmt {
	var stmts []ir.Stmt
	l.markWritten(reg)
	if old, ok := l.regs[reg]; ok && l.isOrphanCandidate(old, reg) {
		stmts = append(stmts, &ir.ExprStmt{Expr: old})
		l.consumed[old] = true
	}
	delete(l.regs, reg)
	delete(l.resultRegs, reg)
	delete(l.regWidths, reg)
	// Whatever reg is about to hold next, it isn't the address this
	// entry recorded any more - a caller that DOES know the new value
	// is (or extends) a known address, e.g. liftAddr or liftAdd's
	// immediate case propagating through "add Rd, Rn, #imm", re-adds
	// its own entry immediately after calling setReg/clobberReg.
	delete(l.addrRegs, reg)
	// See wRegToX's own doc comment: clobbering "w0" must also
	// invalidate "x0" (recursing exactly once, since wRegToX("x0")
	// itself returns ok=false) - done AFTER reg's own entry above is
	// already gone, so isOrphanCandidate's reachable-elsewhere check
	// for xReg's old value (if it happens to be the very same
	// still-aliased expression reg just held) correctly sees it as no
	// longer reachable under reg and flushes it here, exactly once,
	// rather than never (each alias's own isOrphanCandidate check
	// would otherwise always find the OTHER alias still holding it).
	if xReg, ok := wRegToX(reg); ok {
		stmts = append(stmts, l.clobberReg(xReg)...)
	}
	return stmts
}

// setReg is clobberReg followed by installing val as reg's new value -
// the single entry point every instruction that writes a register
// should use (instead of assigning l.regs[reg] directly) so an
// orphaned call sitting there never gets silently overwritten without
// being flushed first. A W-register write also installs val under its
// X alias (see wRegToX/clobberReg), so a value computed via a 32-bit
// "int"-width instruction is still visible to anything (buildCall,
// liftRet) that reads the 64-bit name instead.
func (l *lifter) setReg(reg string, val ir.Expr) []ir.Stmt {
	if reg == "x29" {
		l.x29Known = false
	}
	l.ensureRegName(reg)
	stmts := l.clobberReg(reg)
	l.regs[reg] = val
	delete(l.resultRegs, reg)
	l.markWritten(reg)
	switch {
	case strings.HasPrefix(reg, "w"):
		l.regWidths[reg] = 32
	case strings.HasPrefix(reg, "x"):
		l.regWidths[reg] = 64
	}
	if xReg, ok := wRegToX(reg); ok {
		l.regs[xReg] = val
		delete(l.resultRegs, xReg)
		l.markWritten(xReg)
		l.regWidths[xReg] = 32
	}
	return stmts
}

// markWritten records an explicit write to reg and its x/w alias.
func (l *lifter) markWritten(reg string) {
	if l.written == nil {
		l.written = make(map[string]bool)
	}
	l.written[reg] = true
	if xReg, ok := wRegToX(reg); ok {
		l.written[xReg] = true
		return
	}
	if strings.HasPrefix(reg, "x") {
		l.written["w"+reg[1:]] = true
	}
}

// flushRemaining returns an ExprStmt for every call this lifter (or an
// ancestor it was forked from) has produced that is still unconsumed,
// in original creation order - the calls that survived to the true end
// of this lifter's own control-flow path without ever being read or
// clobbered (see clobberReg for the complementary case: a call
// superseded mid-path). Must only be called once a caller has
// established that this path genuinely has no more instructions ahead
// of it (see LiftFunction and liftBlockGraph's own callers of this) -
// calling it at a mid-function segment boundary a later block might
// still read from would flush values a subsequent read was still going
// to legitimately consume.
func (l *lifter) flushRemaining() []ir.Stmt {
	var stmts []ir.Stmt
	for _, c := range l.calls {
		if l.consumed[c] {
			continue
		}
		stmts = append(stmts, &ir.ExprStmt{Expr: c})
		l.consumed[c] = true
	}
	return stmts
}

// regValue returns the IR expression currently associated with a
// register, or a placeholder LocalVar named after the register itself
// if the lifter never assigned it a value (e.g. a register read before
// any recognized write - this keeps lifting total/non-panicking on
// instruction shapes not yet handled, at the cost of an honestly-ugly
// "w3"-named variable in the output rather than a wrong guess).
// operandValue reads one source operand into an expression and applies
// its own shift (e.g. ", lsl #3"). Register values are consumed, since
// the caller embeds them into a comparison/result that is guaranteed to
// surface; immediate operands are already constants.
func (l *lifter) operandValue(op native.Operand) ir.Expr {
	switch op.Type {
	case native.OperandReg:
		v := applyOperandShift(op, l.regValue(op.Reg))
		l.consume(v)
		return v
	case native.OperandImm:
		return applyOperandShift(op, &ir.IntLit{Value: op.Imm})
	default:
		return nil
	}
}

// liftTst lifts "tst Rn, <Rm|#imm>" (an alias of "ands xzr, ...") into
// the same comparison snapshot liftCmp builds: the following b.cond /
// cset / csel tests "(Rn & rhs) == 0" or "!= 0".
func (l *lifter) liftTst(inst native.DetailedInstruction) {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg {
		return
	}
	lhs := l.regValue(inst.Operands[0].Reg)
	l.consume(lhs)
	rhs := l.operandValue(inst.Operands[1])
	if rhs == nil {
		l.lastCmp = nil
		return
	}
	l.lastCmp = &cmpOperands{
		lhs: &ir.BinaryExpr{Op: "&", Left: lhs, Right: rhs},
		rhs: &ir.IntLit{Value: 0},
	}
}

// liftFlagResult lifts the flag-writing three-operand forms
// "subs/adds/ands Rd, Rn, <Rm|#imm>". It installs the arithmetic result
// in Rd (unless Rd is the zero register, as in the "tst"/"cmp" aliases)
// and records the comparison a later condition consumer should use:
// sub's lhs/rhs for subtraction, or the computed result against zero
// for adds/ands.
func (l *lifter) liftFlagResult(inst native.DetailedInstruction, op string) []ir.Stmt {
	if len(inst.Operands) != 3 {
		return nil
	}
	dstOp, lhsOp, rhsOp := inst.Operands[0], inst.Operands[1], inst.Operands[2]
	if dstOp.Type != native.OperandReg || lhsOp.Type != native.OperandReg {
		return nil
	}
	lhs := l.regValue(lhsOp.Reg)
	l.consume(lhs)
	rhs := l.operandValue(rhsOp)
	if rhs == nil {
		l.lastCmp = nil
		return nil
	}
	result := &ir.BinaryExpr{Op: op, Left: lhs, Right: rhs}

	var stmts []ir.Stmt
	if !isZeroReg(dstOp.Reg) {
		stmts = l.setReg(dstOp.Reg, result)
	}

	if op == "-" {
		l.lastCmp = &cmpOperands{lhs: lhs, rhs: rhs}
	} else {
		l.lastCmp = &cmpOperands{lhs: result, rhs: &ir.IntLit{Value: 0}}
	}
	return stmts
}

func isZeroReg(reg string) bool {
	return reg == "xzr" || reg == "wzr"
}

// constantOf extracts a constant value from the expression forms the
// lifter produces for immediate materialisation.
func constantOf(e ir.Expr) (uint64, bool) {
	switch v := e.(type) {
	case *ir.IntLit:
		return uint64(v.Value), true
	case *ir.LongLit:
		return uint64(v.Value), true
	case *ir.AddrLit:
		return v.Value, true
	default:
		return 0, false
	}
}

func truncateToBits(v uint64, bits uint) uint64 {
	if bits >= 64 {
		return v
	}
	return v & ((uint64(1) << bits) - 1)
}

// liftCmp lifts "cmp Rn, Rm" - not into a statement of its own (a bare
// comparison with the result discarded has no source-level meaning by
// itself), but into l.lastCmp, for a following b.cond to build its
// actual condition expression from (see liftCondition).
func (l *lifter) liftCmp(inst native.DetailedInstruction) {
	if inst.Mnemonic == "ccmp" || inst.Mnemonic == "ccmn" || inst.Mnemonic == "fccmp" || inst.Mnemonic == "fccmpe" {
		l.liftCcmp(inst)
		return
	}
	if len(inst.Operands) != 2 {
		return
	}
	lhsOp, rhsOp := inst.Operands[0], inst.Operands[1]
	if lhsOp.Type != native.OperandReg {
		return
	}
	lhs := l.regValue(lhsOp.Reg)
	l.consume(lhs)

	switch rhsOp.Type {
	case native.OperandReg:
		rhs := applyOperandShift(rhsOp, l.regValue(rhsOp.Reg))
		l.consume(rhs)
		l.lastCmp = &cmpOperands{lhs: lhs, rhs: rhs}
	case native.OperandImm:
		l.lastCmp = &cmpOperands{lhs: lhs, rhs: applyOperandShift(rhsOp, &ir.IntLit{Value: rhsOp.Imm})}
	}
}

// liftCcmp lifts "ccmp Rn, <Rm|#imm>, #nzcv, <cond>" - a CONDITIONAL
// comparison chained onto the previous flag-setting instruction.  Its
// exact semantics: if the previous flags satisfy <cond>, this behaves
// as "cmp Rn, <Rm|#imm>" (setting new flags from that comparison);
// otherwise the flags become the literal NZCV bits in #nzcv.  A
// following b.cond therefore tests
//
//	P ? cmp(Rn, <Rm|#imm>) : K
//
// where P is the PREVIOUS comparison evaluated at <cond> and K is the
// branch's own test evaluated on the constant nzcv bits - which is
// exactly the "a && b" / "a || b" conjunction real ccmp code expresses
// (e.g. "cmp x8, x23; ccmp w9, #0, #0, ne" followed by "b.ne" tests
// "(x8 != x23) && (w9 != 0)").  cmpOperands.combine carries this
// composition forward to liftCondition, which applies it to the
// branch's own comparison operator.
//
// Anything unexpected (no previous comparison, no parsable condition
// suffix, malformed operands) CLEARS lastCmp rather than leaving the
// previous comparison in place: a b.cond after a ccmp tests the ccmp's
// result, so keeping the stale operands would emit an actively wrong
// condition instead of an honest placeholder.
func (l *lifter) liftCcmp(inst native.DetailedInstruction) {
	ops := inst.Operands
	if len(ops) != 3 || ops[0].Type != native.OperandReg || ops[2].Type != native.OperandImm || l.lastCmp == nil {
		l.lastCmp = nil
		return
	}
	condSuffix := inst.OpStr
	if idx := strings.LastIndex(condSuffix, ", "); idx >= 0 {
		condSuffix = condSuffix[idx+2:]
	}
	condOp := condOpFromMnemonic("b." + condSuffix)
	if condOp == "" {
		l.lastCmp = nil
		return
	}
	// Evaluate the PREVIOUS flags' condition at the ccmp's own suffix
	// before overwriting lastCmp.
	prev := l.lastCmp
	var prevPred ir.Expr = &ir.BinaryExpr{Op: condOp, Left: prev.lhs, Right: prev.rhs}
	if prev.combine != nil {
		prevPred = prev.combine(condOp, prevPred)
	}

	lhs := l.regValue(ops[0].Reg)
	l.consume(lhs)
	var rhs ir.Expr
	switch ops[1].Type {
	case native.OperandReg:
		rhs = applyOperandShift(ops[1], l.regValue(ops[1].Reg))
		l.consume(rhs)
	case native.OperandImm:
		rhs = applyOperandShift(ops[1], &ir.IntLit{Value: ops[1].Imm})
	default:
		l.lastCmp = nil
		return
	}
	if inst.Mnemonic == "ccmn" {
		rhs = &ir.UnaryExpr{Op: "-", Expr: rhs}
	}
	nzcv := int(ops[2].Imm) & 0xf
	l.lastCmp = &cmpOperands{lhs: lhs, rhs: rhs, combine: func(op string, cmp ir.Expr) ir.Expr {
		return combineCcmp(prevPred, op, cmp, nzcv)
	}}
}

// combineCcmp builds the full branch condition left behind by a ccmp:
// P ? cmp : K, where P is the previous flags' condition, cmp is the
// ccmp comparison tested with the branch's operator, and K is that same
// test evaluated on the constant nzcv bits.  K is always a known
// constant for the comparison operators this lifter produces, so the
// ternary collapses to a plain conjunction (K false: "P && cmp") or
// disjunction (K true: "!P || cmp") - the forms real ccmp-chained
// source wrote.
func combineCcmp(prev ir.Expr, op string, cmp ir.Expr, nzcv int) ir.Expr {
	k, known := testOnNzcv(op, nzcv)
	if !known {
		return cmp
	}
	if k {
		return &ir.BinaryExpr{Op: "||", Left: &ir.UnaryExpr{Op: "!", Expr: prev}, Right: cmp}
	}
	return &ir.BinaryExpr{Op: "&&", Left: prev, Right: cmp}
}

// testOnNzcv evaluates a b.cond-style comparison operator against the
// constant flags encoded in a ccmp's #nzcv immediate (bit 3 N, bit 2
// Z, bit 1 C, bit 0 V), returning whether the test holds and whether
// the operator is one of the six flags testable this way.  The
// unsigned-only codes (hs/lo/hi/ls) never reach here as such:
// condOpFromMnemonic already folds them onto the signed comparison
// operators, which is why the carry bit itself needs no case of its
// own.
func testOnNzcv(op string, nzcv int) (result, known bool) {
	n := nzcv>>3&1 == 1
	z := nzcv>>2&1 == 1
	v := nzcv&1 == 1
	switch op {
	case "==":
		return z, true
	case "!=":
		return !z, true
	case "<":
		return n != v, true
	case "<=":
		return z || n != v, true
	case ">":
		return !z && n == v, true
	case ">=":
		return n == v, true
	}
	return false, false
}

func (l *lifter) regValue(reg string) ir.Expr {
	// xzr/wzr are the architectural zero registers, not storage: a
	// write to either is discarded and a read always yields the
	// constant 0.  Without this they fell through to the placeholder
	// LocalVar below, so every use rendered as a variable literally
	// named "xzr"/"wzr" - including as the base of a struct access,
	// which produced "xzr.field_N" (not valid C) and hid the real
	// dereference.  See memBaseExpr's own doc comment for the memory-
	// base half of this.
	if reg == "xzr" || reg == "wzr" {
		return &ir.IntLit{Value: 0}
	}
	if v, ok := l.regs[reg]; ok {
		return v
	}
	return &ir.LocalVar{Name: l.regName(reg)}
}

// Register classes for RegsAsVars renaming: argument registers get
// argN names, other integer registers var_N, and SIMD registers
// (q/d/s/h/b0-31) fvar_N from their own counter so float state never
// mixes into the integer numbering.
const (
	regClassUnknown = iota
	regClassArg
	regClassGeneral
	regClassSIMD
)

// canonicalReg maps a physical register spelling to a stable key that
// aliases across widths ("w3" and "x3" -> "x3"; "s2"/"d2"/"q2" -> "v2")
// plus a register class. ok is false for non-register operands or
// names outside the general/SIMD register files.
func canonicalReg(reg string) (key string, class int, ok bool) {
	if len(reg) < 2 {
		return "", regClassUnknown, false
	}
	n := 0
	for _, c := range reg[1:] {
		if c < '0' || c > '9' {
			return "", regClassUnknown, false
		}
		n = n*10 + int(c-'0')
		if n > 31 {
			return "", regClassUnknown, false
		}
	}
	switch reg[0] {
	case 'x', 'w':
		if n > 30 {
			return "", regClassUnknown, false
		}
		if n < len(aapcs64IntArgRegs) {
			return "x" + reg[1:], regClassArg, true
		}
		return "x" + reg[1:], regClassGeneral, true
	case 'q', 'd', 's', 'h', 'b':
		return "v" + reg[1:], regClassSIMD, true
	}
	return "", regClassUnknown, false
}

// regName returns the source-level name for a register the lifter is
// about to render as a bare placeholder variable (see regValue). With
// RegsAsVars disabled - the default - that is the physical register
// name itself, preserving the original output. Enabled, it assigns a
// stable per-physical-register name on first use: argN for AAPCS64
// argument registers, var_N for the rest of the integer file, fvar_N
// for SIMD registers. Names are shared across all forks of a lift (see
// regNames) so the same register reads the same whichever branch
// discovered it first.
func (l *lifter) regName(reg string) string {
	if !l.opts.RegsAsVars {
		return reg
	}
	key, class, ok := canonicalReg(reg)
	if !ok {
		return reg
	}
	if n, seen := l.regNames[key]; seen {
		return n
	}
	var name string
	switch class {
	case regClassArg:
		name = "arg" + key[1:]
	case regClassSIMD:
		name = fmt.Sprintf("fvar_%d", *l.simdSeq)
		*l.simdSeq++
	default:
		name = fmt.Sprintf("var_%d", *l.regSeq)
		*l.regSeq++
	}
	l.regNames[key] = name
	return name
}

// ensureRegName registers the source-level name a write to reg will be
// read back under (see regName) at the moment of the FIRST write, so
// var_N numbering follows first-lvalue-use order even for a register
// whose placeholder form only surfaces later. A no-op when
// RegsAsVars is disabled.
func (l *lifter) ensureRegName(reg string) {
	if l.opts.RegsAsVars {
		_ = l.regName(reg)
	}
}

// memBaseExpr returns the expression to use as the object of a
// FieldAccess for a memory operand whose base register is `base`: the
// register's tracked value, or - when that value has collapsed to a
// constant literal (the zero register, a `mov Rd, #imm` pointer, or
// the merge-point state approximation leaving a register at 0) - a
// placeholder LocalVar named after the register itself.  A `.field_N`
// access on a literal ("0.field_40", "xzr.field_40") is not valid C and
// hides which register the real dereference went through; the
// register-named placeholder matches what regValue already emits for a
// register the lifter never assigned a value to (see its own doc
// comment).
func (l *lifter) memBaseExpr(base string) ir.Expr {
	if base == "xzr" || base == "wzr" {
		// A dereference THROUGH the zero register is a null dereference
		// in the source (never emitted by a compiler in real code, but
		// a valid encoding): render a named placeholder rather than
		// either "0.field_N" (not valid C) or "xzr.field_N" (the exact
		// wrong lift this whole path was fixed for).
		return &ir.LocalVar{Name: "null_ptr"}
	}
	v := l.regValue(base)
	switch v.(type) {
	case *ir.IntLit, *ir.LongLit, *ir.FloatLit, *ir.DoubleLit, *ir.StringLit, *ir.BoolLit, *ir.NullLit, *ir.AddrLit:
		// The register currently holds a raw constant (the merge-point
		// state approximation leaving 0, an adrp page, ...), so the
		// pointed-to value can't be expressed as a field access on it -
		// fall back to the register's own placeholder name.
		return &ir.LocalVar{Name: l.regName(base)}
	}
	return v
}

// liftRet lifts "ret" into a return statement carrying whatever value
// is currently in w0/x0 (the AAPCS64 return-value register) - the
// standard C calling convention's return slot.
func (l *lifter) liftRet() ir.Stmt {
	// With a known DWARF return type, return s0/d0 directly instead of
	// bitcasting the register into the generic uint64_t result.
	switch l.opts.ReturnType {
	case "double":
		if v, ok := l.regs["d0"]; ok {
			l.consume(v)
			return &ir.ReturnStmt{Value: v}
		}
	case "float":
		if v, ok := l.regs["s0"]; ok {
			l.consume(v)
			return &ir.ReturnStmt{Value: v}
		}
	}
	// FP-returning functions leave their result in s0/d0 and never
	// touch x0/w0. When neither integer return register was assigned,
	// return the FP value's bit pattern through the same bitcast macro
	// the fmov int<->FP path uses - the generated translation unit's
	// return type is uint64_t, so this preserves the ABI bits while
	// keeping the output valid C.
	if !l.written["x0"] && !l.written["w0"] {
		if v, ok := l.regs["d0"]; ok {
			l.consume(v)
			return &ir.ReturnStmt{Value: &ir.StaticMethodCall{Method: "ENI_BITCAST_U64", Args: []ir.Expr{v}}}
		}
		if v, ok := l.regs["s0"]; ok {
			l.consume(v)
			return &ir.ReturnStmt{Value: &ir.StaticMethodCall{Method: "ENI_BITCAST_U32", Args: []ir.Expr{v}}}
		}
		// Neither integer return register was written: the ABI value
		// is the incoming x0 argument unchanged.
		return &ir.ReturnStmt{Value: &ir.LocalVar{Name: l.regName("x0")}}
	}

	val := l.regValue("w0")
	if v, ok := l.regs["x0"]; ok {
		// Prefer x0 unless w0 holds the SAME value (a 32-bit write
		// mirrors into x0, so equality means either name is correct).
		// Parameter seeding installs the same expression under both
		// names; a later 64-bit write to x0 changes only x0's entry and
		// must win, while a later 32-bit write updates both and keeps
		// them equal.
		if w0, w0Set := l.regs["w0"]; !w0Set || w0 != v {
			val = v
		}
	}
	l.consume(val)
	return &ir.ReturnStmt{Value: l.zeroExtend("x0", val)}
}

// TODO(next iterations): this lifter now handles - across many rounds,
// see each function's own doc comment for the "why", not repeated here:
// calls (liftCall/liftTailCall/buildCall/finishCall/flushRemaining),
// if/else and while/do-while loops with arbitrary nested if/else,
// break/continue, and nested loops (liftBlockGraph/tryLiftWhileLoop/
// tryLiftDoWhileLoop/findDoWhileTail/liftDoWhileTail/liftLoopEdge),
// compound "&&"/"||" conditions of any depth (tryOrChainLink),
// adrp/adr string-literal and ldr-through-GOT global-object resolution
// (liftAddr/ELFParser.ResolveGOT), the common ALU/shift ops
// (liftAdd/liftALU), stack-spilled parameters AND ordinary local
// variables (liftStr/liftLdr's stack-slot handling), and general
// (non-stack) memory access - struct field/array element dereferences
// through an arbitrary pointer (liftStr/liftLdr's FieldAccess and
// ArrayAccess handling), including byte/halfword and unscaled
// ldrb/strb/ldrh/strh/ldur/stur forms, register-indexed addressing
// ("[Rn, Rm, lsl #N]" with sxtw/uxtw index extenders), movz/movk/movn
// constant materialisation, the tst/subs/adds/ands +
// csel/csinc/csinv/csneg condition family, pre/post-indexed writeback,
// general ldp/stp, madd/msub, udiv/sdiv, ubfx/sbfx, sxtb/sxth/sxtw/
// uxtb/uxth/uxtw, signed loads (ldrsb/ldrsh/ldrsw), basic
// acquire/release/exclusive accesses (ldar/stlr/ldxr/stxr), x29-
// relative stack slots, cmn/neg/negs/bics, mneg/extr/ubfiz/sbfiz, and
// scalar FP arithmetic/conversions (fadd/fsub/fmul/fdiv, fcmp/fcsel,
// scvtf/ucvtf, fcvtzs/fcvtzu, fmov bitcasts).
// Remaining known gaps, none narrow enough yet to single out as "next":
//   - No full type system: DWARF supplies function/parameter names and
//     simple frame-local types, and stack slots get a width-derived
//     int8/16/32/64 type, but the IR itself is still untyped and
//     struct/array/pointer types aren't recovered.
//   - Less common vector arrangements/lane forms (1d/2s/4h/8b,
//     by-element), per-statement source-line comments, full
//     struct/array/pointer types and some FP conversion modes remain.
//     Multi-register ld1/st1, lane-wise 4s/2d/16b/8h arithmetic,
//     fmla/fmls, dup, CAS and DWARF return types are lifted.
//   - No real per-iteration dataflow/fixpoint analysis for loop bodies
//     (see tryLiftWhileLoop's own doc comment) and no real merge-point
//     /dominance analysis for if/else reconvergence (see
//     liftBlockGraph's own doc comment) - both accepted, documented
//     trade-offs of this lifter's per-fork, no-shared-state model
//     rather than open gaps to close.
