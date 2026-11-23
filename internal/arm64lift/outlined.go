package arm64lift

import (
	"sort"
	"strings"

	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/native"
)

// eniOutlinedCtx is the generated-C context block used by outlined
// entries (jump-table case bodies and similar compiler-split blocks)
// that read callee-saved registers from the code that dispatches to
// them. The dispatcher stores the live x19..x28 values here immediately
// before the indirect branch; the outlined entry reloads them on entry.
// Index i corresponds to x(19+i).
const (
	eniOutlinedCtx        = "eni_outlined_ctx"
	eniOutlinedStackLabel = "ENI_OUTLINED_STACK"
	eniOutlinedStackSP    = "ENI_OUTLINED_STACK_SP"
	eniOutlinedSP         = "eni_outlined_sp"
	eniOutlinedFP         = "eni_outlined_fp"
)

// OutlinedContext describes the caller state an outlined entry inherits.
// Regs lists the callee-saved registers read before being written; Stack
// reports that the entry also addresses its dispatcher's stack frame
// through sp/x29.
type OutlinedContext struct {
	Regs  []string
	Stack bool
}

// outlinedDispatch is the per-"br" form of OutlinedContext used while
// lifting a dispatcher.
type outlinedDispatch struct {
	regs  []string
	stack bool
}

var outlinedContextRegs = []string{
	"x19", "x20", "x21", "x22", "x23",
	"x24", "x25", "x26", "x27", "x28",
}

func outlinedContextIndex(reg string) int {
	for i, r := range outlinedContextRegs {
		if r == reg {
			return i
		}
	}
	return -1
}

// CallerContextRegs returns the callee-saved registers a block reads
// before writing them - i.e. the state it inherits from its caller
// rather than producing itself. Jump-table case bodies and outlined
// subroutines are the common source of such entries.
func CallerContextRegs(insns []native.DetailedInstruction) []string {
	unwritten := make(map[string]bool, len(outlinedContextRegs))
	for _, r := range outlinedContextRegs {
		unwritten[r] = true
	}
	var out []string
	for _, in := range insns {
		reads, writes := instructionRegAccess(in)
		for _, reg := range outlinedContextRegs {
			if unwritten[reg] && reads[reg] {
				out = append(out, reg)
				delete(unwritten, reg)
			}
		}
		// A written register is no longer inherited; a later read is a
		// locally-produced value.
		for _, reg := range outlinedContextRegs {
			if writes[reg] {
				delete(unwritten, reg)
			}
		}
	}
	sort.Strings(out)
	return out
}

// CallerStackUsed reports whether a block addresses the caller's stack
// frame through sp or x29. Outlined entries with this property need the
// dispatcher's frame, not just its callee-saved registers.
func CallerStackUsed(insns []native.DetailedInstruction) bool {
	for _, in := range insns {
		for _, op := range in.Operands {
			switch op.Type {
			case native.OperandMem:
				if op.Mem.Base == "sp" || op.Mem.Base == "x29" {
					return true
				}
			case native.OperandReg:
				if normalizeXReg(op.Reg) == "sp" || normalizeXReg(op.Reg) == "x29" {
					return true
				}
			}
		}
	}
	return false
}

// instructionRegAccess reports the integer registers an instruction
// reads as values and writes. Stores to [sp] of callee-saved registers
// are compiler spills, not value uses, so they are ignored.
//
// This is deliberately a small, conservative operand model, not a full
// architecture decoder: the goal is only to distinguish inherited
// callee-saved state from locally-produced values.
func instructionRegAccess(in native.DetailedInstruction) (map[string]bool, map[string]bool) {
	reads := make(map[string]bool)
	writes := make(map[string]bool)
	addRead := func(reg string) {
		reg = normalizeXReg(reg)
		if reg != "" {
			reads[reg] = true
		}
	}
	addWrite := func(reg string) {
		reg = normalizeXReg(reg)
		if reg != "" {
			writes[reg] = true
		}
	}
	addMem := func(mem native.MemOperand) {
		addRead(mem.Base)
		addRead(mem.Index)
	}

	mn := in.Mnemonic
	ops := in.Operands

	switch {
	case strings.HasPrefix(mn, "st") && len(ops) > 0:
		// Store value operands are reads, except a callee-saved spill to
		// [sp, #d], which is pure ABI bookkeeping.
		spill := false
		for _, op := range ops {
			if op.Type == native.OperandMem && op.Mem.Base == "sp" && op.Mem.Index == "" {
				spill = true
			}
		}
		for _, op := range ops {
			switch op.Type {
			case native.OperandReg:
				if !spill || !isCalleeSavedReg(op.Reg) {
					addRead(op.Reg)
				}
			case native.OperandMem:
				addMem(op.Mem)
			}
		}
	case strings.HasPrefix(mn, "ld") && len(ops) > 0:
		for i, op := range ops {
			switch op.Type {
			case native.OperandReg:
				if i == 0 || (mn == "ldp" || mn == "ldnp") && i == 1 {
					addWrite(op.Reg)
				} else {
					addRead(op.Reg)
				}
			case native.OperandMem:
				addMem(op.Mem)
			}
		}
	case mn == "mrs":
		if len(ops) > 0 && ops[0].Type == native.OperandReg {
			addWrite(ops[0].Reg)
		}
	case mn == "msr":
		for _, op := range ops {
			if op.Type == native.OperandReg {
				addRead(op.Reg)
			}
		}
	case mn == "cmp" || mn == "cmn" || mn == "tst" ||
		mn == "fcmp" || mn == "fcmpe" || mn == "ccmp" || mn == "ccmn":
		for _, op := range ops {
			if op.Type == native.OperandReg {
				addRead(op.Reg)
			} else if op.Type == native.OperandMem {
				addMem(op.Mem)
			}
		}
	case mn == "ret" || mn == "br" || mn == "blr" || mn == "b" || mn == "bl" ||
		strings.HasPrefix(mn, "b.") || mn == "cbz" || mn == "cbnz" || mn == "tbz" || mn == "tbnz":
		for _, op := range ops {
			if op.Type == native.OperandReg {
				addRead(op.Reg)
			}
		}
	default:
		for i, op := range ops {
			switch op.Type {
			case native.OperandReg:
				if i == 0 {
					addWrite(op.Reg)
				} else {
					addRead(op.Reg)
				}
			case native.OperandMem:
				addMem(op.Mem)
			}
		}
	}
	return reads, writes
}

func normalizeXReg(reg string) string {
	if len(reg) > 1 && reg[0] == 'w' && reg[1] >= '0' && reg[1] <= '9' {
		return "x" + reg[1:]
	}
	return reg
}

// analyzeJumpTableContext finds indirect "br" dispatches whose jump
// table can reach an outlined entry, and returns the union of context
// registers those entries need. The result is keyed by the "br"
// instruction's address; only those sites need a context save.
func analyzeJumpTableContext(
	insns []native.DetailedInstruction,
	targets map[uint64]OutlinedContext,
	reader func(uint64, int) ([]byte, bool),
) map[uint64]outlinedDispatch {
	if len(targets) == 0 || reader == nil {
		return nil
	}
	out := make(map[uint64]outlinedDispatch)
	for i, in := range insns {
		if in.Mnemonic != "br" || len(in.Operands) != 1 {
			continue
		}
		targetReg := normalizeXReg(in.Operands[0].Reg)
		addIdx := -1
		var targetBase uint64
		var addScale int
		var indexReg string
		for j := i - 1; j >= 0 && j >= i-8; j-- {
			op := insns[j]
			if op.Mnemonic != "add" || len(op.Operands) < 3 {
				continue
			}
			if normalizeXReg(op.Operands[0].Reg) != targetReg {
				continue
			}
			base, ok := constantRegValue(insns, j, normalizeXReg(op.Operands[1].Reg))
			if !ok {
				continue
			}
			shift := 0
			if op.Operands[2].ShiftType == 1 { // AARCH64_SFT_LSL
				shift = op.Operands[2].ShiftValue
			}
			if len(op.Operands) == 4 && op.Operands[3].Type == native.OperandImm {
				shift = int(op.Operands[3].Imm)
			}
			if shift < 0 || shift > 4 {
				continue
			}
			targetBase = base
			indexReg = normalizeXReg(op.Operands[2].Reg)
			addScale = shift
			addIdx = j
			break
		}
		if addIdx < 0 {
			continue
		}
		loadIdx := -1
		tableReg := ""
		loadWidth := 0
		for j := addIdx - 1; j >= 0 && j >= addIdx-8; j-- {
			op := insns[j]
			if op.Mnemonic != "ldrb" && op.Mnemonic != "ldrh" {
				continue
			}
			if len(op.Operands) < 2 || op.Operands[1].Type != native.OperandMem {
				continue
			}
			if normalizeXReg(op.Operands[0].Reg) != indexReg {
				continue
			}
			mem := op.Operands[1].Mem
			tableReg = normalizeXReg(mem.Base)
			loadIdx = j
			if op.Mnemonic == "ldrb" {
				loadWidth = 1
			} else {
				loadWidth = 2
			}
			break
		}
		if loadIdx < 0 {
			continue
		}
		tableBase, ok := constantRegValue(insns, loadIdx, tableReg)
		if !ok {
			continue
		}
		data, ok := reader(tableBase, 512*loadWidth)
		if !ok || len(data) < loadWidth {
			continue
		}
		needed := make(map[string]bool)
		needStack := false
		entries := 0
		for off := 0; off+loadWidth <= len(data) && entries < 512; off += loadWidth {
			var v uint64
			if loadWidth == 1 {
				v = uint64(data[off])
			} else {
				v = uint64(data[off]) | uint64(data[off+1])<<8
			}
			target := targetBase + (v << uint(addScale))
			if target < targetBase || target > targetBase+0x100000 || target%4 != 0 {
				break
			}
			entries++
			if ctx, ok := targets[target]; ok {
				for _, reg := range ctx.Regs {
					needed[reg] = true
				}
				needStack = needStack || ctx.Stack
			}
		}
		if len(needed) == 0 && !needStack {
			continue
		}
		regs := make([]string, 0, len(needed))
		for _, reg := range outlinedContextRegs {
			if needed[reg] {
				regs = append(regs, reg)
			}
		}
		out[in.Address] = outlinedDispatch{regs: regs, stack: needStack}
	}
	return out
}

// constantRegValue recovers the constant value of reg from the closest
// preceding adrp/add, adr, or mov immediate at or before index end.
func constantRegValue(insns []native.DetailedInstruction, end int, reg string) (uint64, bool) {
	if reg == "" {
		return 0, false
	}
	for j := end - 1; j >= 0 && j >= end-48; j-- {
		op := insns[j]
		switch op.Mnemonic {
		case "adr":
			if len(op.Operands) == 2 && normalizeXReg(op.Operands[0].Reg) == reg &&
				op.Operands[1].Type == native.OperandImm {
				return uint64(op.Operands[1].Imm), true
			}
		case "adrp":
			if len(op.Operands) != 2 || normalizeXReg(op.Operands[0].Reg) != reg ||
				op.Operands[1].Type != native.OperandImm {
				continue
			}
			page := uint64(op.Operands[1].Imm)
			for k := j + 1; k <= end; k++ {
				add := insns[k]
				if add.Mnemonic == "add" && len(add.Operands) == 3 &&
					normalizeXReg(add.Operands[0].Reg) == reg &&
					normalizeXReg(add.Operands[1].Reg) == reg &&
					add.Operands[2].Type == native.OperandImm {
					return page + uint64(add.Operands[2].Imm), true
				}
			}
			return page, true
		case "mov", "movz":
			if len(op.Operands) == 2 && normalizeXReg(op.Operands[0].Reg) == reg &&
				op.Operands[1].Type == native.OperandImm {
				return uint64(op.Operands[1].Imm), true
			}
		}
	}
	return 0, false
}

// seedOutlinedContext emits the entry assignments that reload inherited
// callee-saved registers from eni_outlined_ctx. It also installs the
// registers as ordinary C locals so the lifted body keeps using the
// readable x19..x28 names instead of inlining the context loads
// everywhere.
func (l *lifter) seedOutlinedContext() []ir.Stmt {
	var stmts []ir.Stmt
	for _, reg := range outlinedContextRegs {
		if !containsString(l.opts.OutlinedContextRegs, reg) {
			continue
		}
		stmts = append(stmts, &ir.AssignStmt{
			Target: &ir.LocalVar{Name: reg},
			Value:  outlinedContextExpr(reg),
		})
		l.regs[reg] = &ir.LocalVar{Name: reg}
		l.markWritten(reg)
		l.regWidths[reg] = 64
	}
	return stmts
}

// saveOutlinedContext materializes and stores the live values of the
// given callee-saved registers into eni_outlined_ctx. Called right
// before a call or jump-table dispatch whose outlined targets inherit
// those registers.
func (l *lifter) saveOutlinedContext(regs []string) []ir.Stmt {
	var stmts []ir.Stmt
	for _, reg := range regs {
		val := l.regValue(reg)
		l.consume(val)
		if lv, ok := val.(*ir.LocalVar); !ok || lv.Name != reg {
			stmts = append(stmts, &ir.AssignStmt{
				Target: &ir.LocalVar{Name: reg},
				Value:  val,
			})
			l.regs[reg] = &ir.LocalVar{Name: reg}
			l.markWritten(reg)
			l.regWidths[reg] = 64
		}
		stmts = append(stmts, &ir.AssignStmt{
			Target: outlinedContextExpr(reg),
			Value:  &ir.LocalVar{Name: reg},
		})
	}
	return stmts
}

// directTargetNeedsOutlinedStack reports whether a direct "bl"/"b" in
// insns calls an outlined entry that inherits stack context.
func directTargetNeedsOutlinedStack(insns []native.DetailedInstruction, targets map[uint64]OutlinedContext) bool {
	if len(targets) == 0 {
		return false
	}
	for _, in := range insns {
		if in.Mnemonic != "bl" && in.Mnemonic != "b" {
			continue
		}
		if len(in.Operands) != 1 || in.Operands[0].Type != native.OperandImm {
			continue
		}
		if ctx, ok := targets[uint64(in.Operands[0].Imm)]; ok && ctx.Stack {
			return true
		}
	}
	return false
}

// saveOutlinedTarget is saveOutlinedDispatch for a directly named target.
func (l *lifter) saveOutlinedTarget(ctx OutlinedContext) []ir.Stmt {
	return l.saveOutlinedDispatch(outlinedDispatch{regs: ctx.Regs, stack: ctx.Stack})
}

// saveOutlinedDispatch saves everything a dispatcher's outlined target
// inherits: the callee-saved registers and, when requested, the stack
// pointer/frame pointer into the shared outlined stack block.
func (l *lifter) saveOutlinedDispatch(d outlinedDispatch) []ir.Stmt {
	stmts := l.saveOutlinedContext(d.regs)
	if d.stack && l.outlinedStack {
		stmts = append(stmts, l.saveOutlinedStack()...)
	}
	return stmts
}

// saveOutlinedStack materializes the current sp/x29 values and stores
// them for the outlined entry. Materialization matters because x29 is
// often still the lazy "sp + frameOffset" expression at this point.
func (l *lifter) saveOutlinedStack() []ir.Stmt {
	var stmts []ir.Stmt
	for _, reg := range []string{"sp", "x29"} {
		val := l.regValue(reg)
		l.consume(val)
		if lv, ok := val.(*ir.LocalVar); !ok || lv.Name != reg {
			stmts = append(stmts, &ir.AssignStmt{
				Target: &ir.LocalVar{Name: reg},
				Value:  val,
			})
			l.regs[reg] = &ir.LocalVar{Name: reg}
			l.markWritten(reg)
			l.regWidths[reg] = 64
		}
	}
	stmts = append(stmts, &ir.AssignStmt{
		Target: &ir.LocalVar{Name: eniOutlinedSP},
		Value:  &ir.LocalVar{Name: "sp"},
	})
	stmts = append(stmts, &ir.AssignStmt{
		Target: &ir.LocalVar{Name: eniOutlinedFP},
		Value:  &ir.LocalVar{Name: "x29"},
	})
	return stmts
}

// seedOutlinedStack prepares stack context. An outlined entry reloads
// its dispatcher's sp/x29; a dispatcher gets a fresh zeroed frame in the
// shared outlined stack block and points sp at it.
func (l *lifter) seedOutlinedStack() []ir.Stmt {
	if !l.outlinedStack {
		return nil
	}
	var stmts []ir.Stmt
	if l.opts.OutlinedStack {
		stmts = append(stmts, &ir.AssignStmt{
			Target: &ir.LocalVar{Name: "sp"},
			Value:  &ir.LocalVar{Name: eniOutlinedSP},
		})
		stmts = append(stmts, &ir.AssignStmt{
			Target: &ir.LocalVar{Name: "x29"},
			Value:  &ir.LocalVar{Name: eniOutlinedFP},
		})
		l.regs["sp"] = &ir.LocalVar{Name: "sp"}
		l.regs["x29"] = &ir.LocalVar{Name: "x29"}
		l.markWritten("sp")
		l.markWritten("x29")
		l.regWidths["sp"] = 64
		l.regWidths["x29"] = 64
		l.x29Known = false
		return stmts
	}
	stmts = append(stmts, &ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "ENI_OUTLINED_STACK_RESET"}})
	stmts = append(stmts, &ir.AssignStmt{
		Target: &ir.LocalVar{Name: "sp"},
		Value:  &ir.AddrLit{Label: eniOutlinedStackSP},
	})
	l.regs["sp"] = &ir.LocalVar{Name: "sp"}
	l.markWritten("sp")
	l.regWidths["sp"] = 64
	return stmts
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// outlinedContextExpr is the C expression for one saved context slot.
func outlinedContextExpr(reg string) ir.Expr {
	idx := outlinedContextIndex(reg)
	if idx < 0 {
		return &ir.IntLit{Value: 0}
	}
	return &ir.ArrayAccess{
		Array: &ir.LocalVar{Name: eniOutlinedCtx},
		Index: &ir.IntLit{Value: int64(idx)},
		Width: 8,
	}
}
