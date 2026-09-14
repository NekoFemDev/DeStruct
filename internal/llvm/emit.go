// Package llvm exports the project's lifted IR (internal/ir) as
// textual LLVM IR. It is a best-effort translation, not a verified
// backend: the lifted source has no real type system (every value is
// an untyped IR expression - see the trailing TODO in
// internal/arm64lift/lift.go), so every integer/pointer value is
// modelled as i64, locals become function-entry allocas with explicit
// load/store (exactly like clang's own -O0 output), and structured
// control flow is lowered to explicit basic blocks and branches
// (including LabelStmt/GotoStmt, which map directly onto LLVM labels).
//
// The result is intended to be good enough to feed into llvm-as,
// opt, or a disassembler for further analysis of a decompiled
// function - the same values, calls, and control flow the C-like
// pseudocode shows, in SSA-ish form.
package llvm

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/destruct/destruct/internal/ir"
)

// Module is a streaming LLVM IR module writer: one decompiled function
// at a time, without holding the whole binary's IR in memory. String
// globals are numbered from a shared counter, so literal names stay
// unique across every function in the module.
type Module struct {
	w        *bufio.Writer
	strCount int
	// defined tracks every function name emitted as a "define", so a
	// duplicate symbol (symbol-table aliases demangle to the same name)
	// can be skipped instead of producing an invalid redefinition, and
	// an external call to a function that IS defined doesn't also get a
	// redundant declaration.
	defined map[string]bool
	// refs / refsVoid track externally-referenced function names (i64-
	// and void-returning respectively); Finish declares whichever ones
	// the module didn't define - llvm-as rejects calls to undefined
	// values in current LLVM releases, so a lifted function calling
	// into libc/libc++ needs these declarations.
	refs     map[string]bool
	refsVoid map[string]bool
}

// NewModule wraps w as an LLVM module writer. Callers should flush via
// Finish (or by flushing the underlying writer themselves).
func NewModule(w io.Writer) *Module {
	return &Module{
		w:        bufio.NewWriter(w),
		defined:  make(map[string]bool),
		refs:     make(map[string]bool),
		refsVoid: make(map[string]bool),
	}
}

// Finish declares any externally-referenced (but undefined) callees and
// flushes the module.
func (m *Module) Finish() error {
	m.emitDeclarations()
	return m.w.Flush()
}

// emitDeclarations writes a variadic prototype for every referenced
// function the module never defined (all calls are modelled i64 in,
// i64 out; __cxa_throw is the one void-returning form). Names are
// sorted so output stays reproducible across runs.
func (m *Module) emitDeclarations() {
	names := make([]string, 0, len(m.refs))
	for n := range m.refs {
		if !m.defined[n] && !m.refsVoid[n] {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(m.w, "declare i64 @%s(...)\n", llvmName(n))
	}
	voidNames := make([]string, 0, len(m.refsVoid))
	for n := range m.refsVoid {
		if !m.defined[n] {
			voidNames = append(voidNames, n)
		}
	}
	sort.Strings(voidNames)
	for _, n := range voidNames {
		fmt.Fprintf(m.w, "declare void @%s(...)\n", llvmName(n))
	}
}

// EmitHeader writes the module prologue.
func (m *Module) EmitHeader(baseName, input string) {
	fmt.Fprintf(m.w, "; ModuleID = '%s'\n; DeStruct LLVM IR export of %s\ntarget triple = \"aarch64-unknown-linux-android\"\n", baseName, input)
}

// EmitFunction writes one lifted function as an LLVM IR definition.
// String literals used inside the function are emitted as private
// globals immediately before it (module-level entities are legal in
// any order), and the body starts at an "entry" block.
func (m *Module) EmitFunction(name string, stmts []ir.Stmt) {
	// Two symbol-table entries can demangle to the same name (aliases,
	// thunks). Emitting both would be a redefinition, which LLVM
	// rejects; keep the first body and skip the duplicates.
	if m.defined[name] {
		fmt.Fprintf(m.w, "\n; duplicate definition of %s skipped\n", llvmName(name))
		return
	}
	m.defined[name] = true

	e := &emitter{
		w:      m.w,
		mod:    m,
		locals: collectLocals(stmts),
	}

	// Pre-walk for string literals (in first-seen order) so their
	// globals can be declared before the define line.
	e.stringSeen = make(map[string]bool)
	e.collectStrings(stmts)
	e.globals = make(map[string]string, len(e.strings))
	for _, s := range e.strings {
		m.strCount++
		name := fmt.Sprintf("@.str%d", m.strCount)
		e.globals[s] = name
		e.emitGlobal(name, s)
	}

	fmt.Fprintf(e.w, "\ndefine i64 @%s() {\n", llvmName(name))
	fmt.Fprintf(e.w, "entry:\n")
	// Every local gets an entry alloca up front, so any use/def
	// (including across blocks) is a simple load/store pair.
	for _, local := range e.locals {
		fmt.Fprintf(e.w, "  %%%s = alloca i64\n", llvmLocal(local))
	}
	fmt.Fprintf(e.w, "  br label %%entry_body\n")

	e.startBlock("entry_body")
	e.stmts(stmts)
	if !e.terminated {
		e.terminator("ret i64 0")
	}
	fmt.Fprintf(e.w, "}\n")
}

// EmitFunction writes one lifted function to w as a complete minimal
// module (a convenience wrapper for single-function use and tests).
func EmitFunction(w io.Writer, name string, stmts []ir.Stmt) {
	m := NewModule(w)
	m.EmitFunction(name, stmts)
	m.Finish()
}

type emitter struct {
	w          *bufio.Writer
	mod        *Module
	locals     []string
	tmpN       int
	blockN     int
	loops      []loopLabels
	terminated bool
	// started tracks whether a basic block's label has been written yet
	// (the entry block is written by hand before the first startBlock
	// call), so startBlock knows whether it has a previous block to
	// close with a fall-through branch.
	started    bool
	strings    []string
	stringSeen map[string]bool
	globals    map[string]string
}

type loopLabels struct {
	head string
	exit string
}

func (e *emitter) emit(format string, args ...any) {
	fmt.Fprintf(e.w, "  "+format+"\n", args...)
}

func (e *emitter) terminator(format string, args ...any) {
	e.emit(format, args...)
	e.terminated = true
}

// callee records name as a referenced function and returns its LLVM
// spelling; Finish emits a declaration for it unless the module defines
// it (see Module.defined).
func (e *emitter) callee(name string) string {
	e.mod.refs[name] = true
	return llvmName(name)
}

// calleeVoid is callee for the void-returning runtime entry points.
func (e *emitter) calleeVoid(name string) string {
	e.mod.refsVoid[name] = true
	return llvmName(name)
}

func (e *emitter) tmp() string {
	e.tmpN++
	return fmt.Sprintf("%%t%d", e.tmpN)
}

func (e *emitter) label(prefix string) string {
	e.blockN++
	return fmt.Sprintf("%s%d", prefix, e.blockN)
}

// startBlock begins a new basic block, first closing the previous one
// if it was never terminated: LLVM blocks have no implicit
// fall-through, so an unterminated block immediately before a label
// (the "if_end" block ahead of a merge label, a dead block whose first
// statement is a label, etc.) needs the explicit branch its fall-through
// implies. The entry block is exempt via started - its terminator is
// written by hand in EmitFunction.
func (e *emitter) startBlock(label string) {
	if e.started && !e.terminated {
		fmt.Fprintf(e.w, "  br label %%%s\n", label)
	}
	fmt.Fprintf(e.w, "%s:\n", label)
	e.started = true
	e.terminated = false
}

// ensureBlock emits a fresh unreachable block when the current one has
// already been terminated but more statements follow (the lifter can
// emit code after a return - e.g. exception cleanup landing pads).
func (e *emitter) ensureBlock() {
	if e.terminated {
		e.startBlock(e.label("dead"))
	}
}

func (e *emitter) stmts(list []ir.Stmt) {
	for _, s := range list {
		e.stmt(s)
	}
}

func (e *emitter) stmt(s ir.Stmt) {
	if s == nil {
		return
	}
	e.ensureBlock()
	switch v := s.(type) {
	case *ir.AssignStmt:
		val := e.expr(v.Value)
		e.store(v.Target, val)
	case *ir.ReturnStmt:
		// Every value is modelled i64, so a value-less return still has
		// to return i64 (the function signature is i64 @f()).
		if v.Value == nil {
			e.terminator("ret i64 0")
			return
		}
		e.terminator("ret i64 %s", e.expr(v.Value))
	case *ir.ExprStmt:
		e.exprStmt(v.Expr)
	case *ir.IfStmt:
		e.ifStmt(v)
	case *ir.WhileStmt:
		e.whileStmt(v)
	case *ir.DoWhileStmt:
		e.doWhileStmt(v)
	case *ir.ForStmt:
		e.forStmt(v)
	case *ir.SwitchStmt:
		e.switchStmt(v)
	case *ir.LabelStmt:
		e.startBlock(llvmLocal(v.Name))
	case *ir.GotoStmt:
		e.terminator("br label %%%s", llvmLocal(v.Label))
	case *ir.BreakStmt:
		if n := len(e.loops); n > 0 {
			e.terminator("br label %%%s", e.loops[n-1].exit)
		} else {
			e.terminator("ret i64 0")
		}
	case *ir.ContinueStmt:
		if n := len(e.loops); n > 0 {
			e.terminator("br label %%%s", e.loops[n-1].head)
		}
	case *ir.VarDeclStmt:
		if v.Init != nil {
			val := e.expr(v.Init)
			e.emit("store i64 %s, i64* %%%s", val, llvmLocal(v.Name))
		}
	case *ir.ThrowStmt:
		e.emit("call void @%s(i8* null, i8* null, i8* null)", e.calleeVoid("__cxa_throw"))
		e.terminator("unreachable")
	case *ir.TryStmt:
		// LLVM's own EH lowering needs invoke/landingpad, which the
		// lifted IR doesn't carry; emit the body inline and the
		// handlers as comment-marked blocks so nothing is lost.
		e.emit("; try")
		if v.Body != nil {
			e.stmts(v.Body.Statements)
		}
		for _, c := range v.Catches {
			e.ensureBlock()
			e.emit("; catch %s", c.VarName)
			if c.Body != nil {
				e.stmts(c.Body.Statements)
			}
		}
		if v.Finally != nil {
			e.ensureBlock()
			e.emit("; finally")
			e.stmts(v.Finally.Statements)
		}
	case *ir.BlockStmt:
		if v.Block != nil {
			e.stmts(v.Block.Statements)
		}
	default:
		e.emit("; unsupported statement: %T", s)
	}
}

func (e *emitter) ifStmt(v *ir.IfStmt) {
	cond := e.cond(v.Cond)
	thenL := e.label("if_then")
	elseL := e.label("if_else")
	endL := e.label("if_end")
	if v.Else == nil || len(v.Else.Statements) == 0 {
		e.terminator("br i1 %s, label %%%s, label %%%s", cond, thenL, endL)
		e.startBlock(thenL)
		if v.Then != nil {
			e.stmts(v.Then.Statements)
		}
		if !e.terminated {
			e.terminator("br label %%%s", endL)
		}
		e.startBlock(endL)
		return
	}
	e.terminator("br i1 %s, label %%%s, label %%%s", cond, thenL, elseL)
	e.startBlock(thenL)
	if v.Then != nil {
		e.stmts(v.Then.Statements)
	}
	if !e.terminated {
		e.terminator("br label %%%s", endL)
	}
	e.startBlock(elseL)
	e.stmts(v.Else.Statements)
	if !e.terminated {
		e.terminator("br label %%%s", endL)
	}
	e.startBlock(endL)
}

func (e *emitter) whileStmt(v *ir.WhileStmt) {
	headL := e.label("while_head")
	bodyL := e.label("while_body")
	exitL := e.label("while_exit")
	e.terminator("br label %%%s", headL)
	e.startBlock(headL)
	cond := e.cond(v.Cond)
	e.terminator("br i1 %s, label %%%s, label %%%s", cond, bodyL, exitL)
	e.startBlock(bodyL)
	e.loops = append(e.loops, loopLabels{head: headL, exit: exitL})
	if v.Body != nil {
		e.stmts(v.Body.Statements)
	}
	e.loops = e.loops[:len(e.loops)-1]
	if !e.terminated {
		e.terminator("br label %%%s", headL)
	}
	e.startBlock(exitL)
}

func (e *emitter) doWhileStmt(v *ir.DoWhileStmt) {
	bodyL := e.label("do_body")
	tailL := e.label("do_tail")
	exitL := e.label("do_exit")
	e.terminator("br label %%%s", bodyL)
	e.startBlock(bodyL)
	e.loops = append(e.loops, loopLabels{head: tailL, exit: exitL})
	if v.Body != nil {
		e.stmts(v.Body.Statements)
	}
	e.loops = e.loops[:len(e.loops)-1]
	if !e.terminated {
		e.terminator("br label %%%s", tailL)
	}
	e.startBlock(tailL)
	cond := e.cond(v.Cond)
	e.terminator("br i1 %s, label %%%s, label %%%s", cond, bodyL, exitL)
	e.startBlock(exitL)
}

func (e *emitter) forStmt(v *ir.ForStmt) {
	if v.Init != nil {
		e.stmt(v.Init)
	}
	headL := e.label("for_head")
	bodyL := e.label("for_body")
	postL := e.label("for_post")
	exitL := e.label("for_exit")
	e.terminator("br label %%%s", headL)
	e.startBlock(headL)
	cond := "1"
	if v.Cond != nil {
		cond = e.cond(v.Cond)
	}
	e.terminator("br i1 %s, label %%%s, label %%%s", cond, bodyL, exitL)
	e.startBlock(bodyL)
	e.loops = append(e.loops, loopLabels{head: postL, exit: exitL})
	if v.Body != nil {
		e.stmts(v.Body.Statements)
	}
	e.loops = e.loops[:len(e.loops)-1]
	if !e.terminated {
		e.terminator("br label %%%s", postL)
	}
	e.startBlock(postL)
	if v.Post != nil {
		e.stmt(v.Post)
	}
	e.terminator("br label %%%s", headL)
	e.startBlock(exitL)
}

func (e *emitter) switchStmt(v *ir.SwitchStmt) {
	target := e.expr(v.Target)
	endL := e.label("switch_end")
	defaultL := endL
	if v.Default != nil && len(v.Default.Statements) > 0 {
		defaultL = e.label("switch_default")
	}
	caseL := make([]string, len(v.Cases))
	for i := range v.Cases {
		caseL[i] = e.label("switch_case")
	}

	if allIntegerCases(v) {
		if len(v.Cases) == 0 {
			e.terminator("br label %%%s", defaultL)
		} else {
			var sb strings.Builder
			fmt.Fprintf(&sb, "switch i64 %s, label %%%s [", target, defaultL)
			for i, c := range v.Cases {
				for _, val := range c.Values {
					fmt.Fprintf(&sb, " i64 %s, label %%%s", e.expr(val), caseL[i])
				}
			}
			sb.WriteString(" ]")
			e.terminator("%s", sb.String())
		}
	} else {
		// LLVM switch case values must be integer constants, so a
		// dispatch whose cases are the string literals of a folded
		// strcmp chain is lowered as an equality chain instead (strcmp
		// for string cases, icmp on the i64 value otherwise) - same
		// control flow, always-valid IR.
		nextL := ""
		for i, c := range v.Cases {
			if nextL != "" {
				e.startBlock(nextL)
			}
			cond := "0"
			for _, val := range c.Values {
				cmp := e.caseCompare(target, val)
				if cond == "0" {
					cond = cmp
					continue
				}
				merged := e.tmp()
				e.emit("%s = or i1 %s, %s", merged, cond, cmp)
				cond = merged
			}
			if i == len(v.Cases)-1 {
				e.terminator("br i1 %s, label %%%s, label %%%s", cond, caseL[i], defaultL)
			} else {
				nextL = e.label("switch_next")
				e.terminator("br i1 %s, label %%%s, label %%%s", cond, caseL[i], nextL)
			}
		}
		if len(v.Cases) == 0 {
			e.terminator("br label %%%s", defaultL)
		}
	}

	for i, c := range v.Cases {
		e.startBlock(caseL[i])
		if c.Body != nil {
			e.stmts(c.Body.Statements)
		}
		if !e.terminated {
			e.terminator("br label %%%s", endL)
		}
	}
	if defaultL != endL {
		e.startBlock(defaultL)
		e.stmts(v.Default.Statements)
		if !e.terminated {
			e.terminator("br label %%%s", endL)
		}
	}
	e.startBlock(endL)
}

// allIntegerCases reports whether every case value can be written as an
// integer constant directly - the only form LLVM's switch accepts.
func allIntegerCases(v *ir.SwitchStmt) bool {
	for _, c := range v.Cases {
		for _, val := range c.Values {
			switch val.(type) {
			case *ir.IntLit, *ir.LongLit, *ir.BoolLit, *ir.NullLit:
			default:
				return false
			}
		}
	}
	return true
}

// caseCompare lowers one case test to an i1 operand: a strcmp call
// against a string literal (the original comparison the dispatch was
// folded from), or a plain i64 equality for any other value.
func (e *emitter) caseCompare(target string, val ir.Expr) string {
	if lit, ok := val.(*ir.StringLit); ok {
		str := e.expr(lit)
		call := e.tmp()
		e.emit("%s = call i64 @%s(i64 %s, i64 %s)", call, e.callee("strcmp"), target, str)
		t := e.tmp()
		e.emit("%s = icmp eq i64 %s, 0", t, call)
		return t
	}
	v := e.expr(val)
	t := e.tmp()
	e.emit("%s = icmp eq i64 %s, %s", t, target, v)
	return t
}

// exprStmt emits an expression whose value is discarded: a call is a
// plain call instruction (LLVM allows ignoring the result).
func (e *emitter) exprStmt(x ir.Expr) {
	switch v := x.(type) {
	case *ir.StaticMethodCall:
		e.emit("call i64 @%s(%s)", e.callee(v.Method), e.args(v.Args))
	case *ir.MethodCall:
		recv := e.expr(v.Object)
		e.emit("call i64 @%s(i64 %s%s)", e.callee(v.Name), recv, e.argsTail(v.Args))
	case *ir.IndirectCall:
		callee := e.expr(v.Callee)
		fp := e.tmp()
		e.emit("%s = inttoptr i64 %s to i64 (...)*", fp, callee)
		e.emit("call i64 %s(%s)", fp, e.args(v.Args))
	default:
		e.emit("; discarded: %s", x)
	}
}

// store writes val to an lvalue target (local, field, or indexed
// element).
func (e *emitter) store(target ir.Expr, val string) {
	switch t := target.(type) {
	case *ir.LocalVar:
		e.emit("store i64 %s, i64* %%%s", val, llvmLocal(t.Name))
	case *ir.FieldAccess:
		ptr := e.fieldPtr(t)
		e.emit("store i64 %s, i64* %s", val, ptr)
	case *ir.ArrayAccess:
		ptr := e.elemPtr(t)
		e.emit("store i64 %s, i64* %s", val, ptr)
	default:
		e.emit("; store to unsupported target %T", target)
	}
}

func (e *emitter) fieldPtr(f *ir.FieldAccess) string {
	base := e.expr(f.Object)
	p := e.tmp()
	e.emit("%s = inttoptr i64 %s to i64*", p, base)
	return p
}

func (e *emitter) elemPtr(a *ir.ArrayAccess) string {
	base := e.expr(a.Array)
	idx := e.expr(a.Index)
	off := e.tmp()
	e.emit("%s = mul i64 %s, 8", off, idx)
	addr := e.tmp()
	e.emit("%s = add i64 %s, %s", addr, base, off)
	p := e.tmp()
	e.emit("%s = inttoptr i64 %s to i64*", p, addr)
	return p
}

// cond lowers a condition expression to an i1 operand.
func (e *emitter) cond(x ir.Expr) string {
	if x == nil {
		return "1"
	}
	if be, ok := x.(*ir.BinaryExpr); ok {
		if c, ok := e.compare(be); ok {
			return c
		}
	}
	if un, ok := x.(*ir.UnaryExpr); ok && un.Op == "!" {
		inner := e.cond(un.Expr)
		t := e.tmp()
		e.emit("%s = xor i1 %s, true", t, inner)
		return t
	}
	v := e.expr(x)
	t := e.tmp()
	e.emit("%s = icmp ne i64 %s, 0", t, v)
	return t
}

// compare lowers a comparison BinaryExpr to an i1 operand.
func (e *emitter) compare(be *ir.BinaryExpr) (string, bool) {
	var opcode string
	switch be.Op {
	case "==":
		opcode = "eq"
	case "!=":
		opcode = "ne"
	case "<":
		opcode = "slt"
	case ">":
		opcode = "sgt"
	case "<=":
		opcode = "sle"
	case ">=":
		opcode = "sge"
	default:
		return "", false
	}
	l := e.expr(be.Left)
	r := e.expr(be.Right)
	t := e.tmp()
	e.emit("%s = icmp %s i64 %s, %s", t, opcode, l, r)
	return t, true
}

// expr lowers an expression to an i64 operand, emitting any
// instructions it needs into the current block.
func (e *emitter) expr(x ir.Expr) string {
	if x == nil {
		return "0"
	}
	switch v := x.(type) {
	case *ir.IntLit:
		return fmt.Sprintf("%d", v.Value)
	case *ir.LongLit:
		return fmt.Sprintf("%d", v.Value)
	case *ir.BoolLit:
		if v.Value {
			return "1"
		}
		return "0"
	case *ir.NullLit:
		return "0"
	case *ir.FloatLit:
		// All values are modelled as i64; a float literal exports as its
		// raw IEEE-754 bit pattern.
		return fmt.Sprintf("%d", int64(math.Float32bits(v.Value)))
	case *ir.DoubleLit:
		return fmt.Sprintf("%d", int64(math.Float64bits(v.Value)))
	case *ir.StringLit:
		g := e.globals[v.Value]
		if g == "" {
			g = "@.str0"
		}
		t := e.tmp()
		e.emit("%s = ptrtoint i8* getelementptr inbounds ([%d x i8], [%d x i8]* %s, i64 0, i64 0) to i64",
			t, len(v.Value)+1, len(v.Value)+1, g)
		return t
	case *ir.LocalVar:
		t := e.tmp()
		e.emit("%s = load i64, i64* %%%s", t, llvmLocal(v.Name))
		return t
	case *ir.FieldAccess:
		ptr := e.fieldPtr(v)
		t := e.tmp()
		e.emit("%s = load i64, i64* %s", t, ptr)
		return t
	case *ir.ArrayAccess:
		ptr := e.elemPtr(v)
		t := e.tmp()
		e.emit("%s = load i64, i64* %s", t, ptr)
		return t
	case *ir.BinaryExpr:
		if c, ok := e.compare(v); ok {
			z := e.tmp()
			e.emit("%s = zext i1 %s to i64", z, c)
			return z
		}
		l := e.expr(v.Left)
		r := e.expr(v.Right)
		var opcode string
		switch v.Op {
		case "+":
			opcode = "add"
		case "-":
			opcode = "sub"
		case "*":
			opcode = "mul"
		case "/":
			opcode = "sdiv"
		case "%":
			opcode = "srem"
		case "&", "&&":
			opcode = "and"
		case "|", "||":
			opcode = "or"
		case "^":
			opcode = "xor"
		case "<<":
			opcode = "shl"
		case ">>":
			opcode = "ashr"
		case ">>>":
			opcode = "lshr"
		default:
			e.emit("; unsupported binary op %q", v.Op)
			return l
		}
		t := e.tmp()
		e.emit("%s = %s i64 %s, %s", t, opcode, l, r)
		return t
	case *ir.UnaryExpr:
		switch v.Op {
		case "!":
			c := e.cond(v.Expr)
			z := e.tmp()
			e.emit("%s = zext i1 %s to i64", z, c)
			return z
		case "-":
			inner := e.expr(v.Expr)
			t := e.tmp()
			e.emit("%s = sub i64 0, %s", t, inner)
			return t
		case "~":
			inner := e.expr(v.Expr)
			t := e.tmp()
			e.emit("%s = xor i64 %s, -1", t, inner)
			return t
		default:
			return e.expr(v.Expr)
		}
	case *ir.TernaryExpr:
		cond := e.cond(v.Cond)
		t := e.expr(v.TrueExpr)
		f := e.expr(v.FalseExpr)
		s := e.tmp()
		e.emit("%s = select i1 %s, i64 %s, i64 %s", s, cond, t, f)
		return s
	case *ir.CastExpr:
		return e.expr(v.Expr)
	case *ir.StaticMethodCall:
		t := e.tmp()
		e.emit("%s = call i64 @%s(%s)", t, e.callee(v.Method), e.args(v.Args))
		return t
	case *ir.MethodCall:
		recv := e.expr(v.Object)
		t := e.tmp()
		e.emit("%s = call i64 @%s(i64 %s%s)", t, e.callee(v.Name), recv, e.argsTail(v.Args))
		return t
	case *ir.IndirectCall:
		callee := e.expr(v.Callee)
		fp := e.tmp()
		e.emit("%s = inttoptr i64 %s to i64 (...)*", fp, callee)
		t := e.tmp()
		e.emit("%s = call i64 %s(%s)", t, fp, e.args(v.Args))
		return t
	case *ir.NewExpr:
		size := e.tmp()
		e.emit("%s = call i64 @%s(i64 16)", size, e.callee("malloc"))
		return size
	case *ir.NewArrayExpr:
		sizeExpr := e.expr(v.Size)
		size := e.tmp()
		e.emit("%s = mul i64 %s, 8", size, sizeExpr)
		p := e.tmp()
		e.emit("%s = call i64 @%s(i64 %s)", p, e.callee("malloc"), size)
		return p
	case *ir.ArrayInitExpr:
		size := e.tmp()
		e.emit("%s = call i64 @%s(i64 %d)", size, e.callee("malloc"), len(v.Elems)*8)
		return size
	case *ir.ThisExpr, *ir.SuperExpr:
		return "0"
	case *ir.ClassLiteral:
		return "0"
	case *ir.MethodRefExpr:
		e.emit("; method reference %s::%s", v.ClassName, v.MethodName)
		return "0"
	case *ir.LambdaExpr:
		e.emit("; lambda expression")
		return "0"
	default:
		e.emit("; unsupported expression %T", x)
		return "0"
	}
}

func (e *emitter) args(list []ir.Expr) string {
	parts := make([]string, 0, len(list))
	for _, a := range list {
		parts = append(parts, "i64 "+e.expr(a))
	}
	return strings.Join(parts, ", ")
}

func (e *emitter) argsTail(list []ir.Expr) string {
	if len(list) == 0 {
		return ""
	}
	return ", " + e.args(list)
}

// emitGlobal declares one string literal's private global.
func (e *emitter) emitGlobal(name, s string) {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			b.WriteString(`\5C`)
		case c == '"':
			b.WriteString(`\22`)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\%02X`, c)
		}
	}
	b.WriteString(`\00"`)
	fmt.Fprintf(e.w, "%s = private unnamed_addr constant [%d x i8] c%s\n", name, len(s)+1, b.String())
}

// collectStrings walks the statement tree for StringLit values (the
// globals must be declared before the function).
// collectStrings walks the statement tree for StringLit values (the
// globals must be declared before the function). Every statement type
// that can carry an expression has to be walked: a literal missed here
// becomes an undefined "@.str0" reference in the emitted body.
func (e *emitter) collectStrings(stmts []ir.Stmt) {
	for _, s := range stmts {
		switch v := s.(type) {
		case *ir.IfStmt:
			e.collectStringsExpr(v.Cond)
			if v.Then != nil {
				e.collectStrings(v.Then.Statements)
			}
			if v.Else != nil {
				e.collectStrings(v.Else.Statements)
			}
		case *ir.WhileStmt:
			e.collectStringsExpr(v.Cond)
			if v.Body != nil {
				e.collectStrings(v.Body.Statements)
			}
		case *ir.DoWhileStmt:
			e.collectStringsExpr(v.Cond)
			if v.Body != nil {
				e.collectStrings(v.Body.Statements)
			}
		case *ir.ForStmt:
			if v.Init != nil {
				e.collectStrings([]ir.Stmt{v.Init})
			}
			e.collectStringsExpr(v.Cond)
			if v.Post != nil {
				e.collectStrings([]ir.Stmt{v.Post})
			}
			if v.Body != nil {
				e.collectStrings(v.Body.Statements)
			}
		case *ir.ForEachStmt:
			e.collectStringsExpr(v.Expr)
			if v.Body != nil {
				e.collectStrings(v.Body.Statements)
			}
		case *ir.SwitchStmt:
			e.collectStringsExpr(v.Target)
			for _, c := range v.Cases {
				// Case values matter: a folded string dispatch renders
				// its case labels as StringLits.
				for _, val := range c.Values {
					e.collectStringsExpr(val)
				}
				if c.Body != nil {
					e.collectStrings(c.Body.Statements)
				}
			}
			if v.Default != nil {
				e.collectStrings(v.Default.Statements)
			}
		case *ir.TryStmt:
			for _, r := range v.Resources {
				e.collectStringsExpr(r.Init)
			}
			if v.Body != nil {
				e.collectStrings(v.Body.Statements)
			}
			for _, c := range v.Catches {
				if c.Body != nil {
					e.collectStrings(c.Body.Statements)
				}
			}
			if v.Finally != nil {
				e.collectStrings(v.Finally.Statements)
			}
		case *ir.BlockStmt:
			if v.Block != nil {
				e.collectStrings(v.Block.Statements)
			}
		default:
			e.collectStringsExprStmt(s)
		}
	}
}

func (e *emitter) collectStringsExprStmt(s ir.Stmt) {
	switch v := s.(type) {
	case *ir.AssignStmt:
		e.collectStringsExpr(v.Target)
		e.collectStringsExpr(v.Value)
	case *ir.ReturnStmt:
		e.collectStringsExpr(v.Value)
	case *ir.ExprStmt:
		e.collectStringsExpr(v.Expr)
	case *ir.SuperCallStmt:
		for _, a := range v.Args {
			e.collectStringsExpr(a)
		}
	case *ir.ThisCallStmt:
		for _, a := range v.Args {
			e.collectStringsExpr(a)
		}
	case *ir.VarDeclStmt:
		e.collectStringsExpr(v.Init)
	case *ir.ThrowStmt:
		e.collectStringsExpr(v.Value)
	case *ir.LabelStmt, *ir.GotoStmt, *ir.BreakStmt, *ir.ContinueStmt:
	}
}

func (e *emitter) collectStringsExpr(x ir.Expr) {
	if x == nil {
		return
	}
	switch v := x.(type) {
	case *ir.StringLit:
		if !e.stringSeen[v.Value] {
			e.stringSeen[v.Value] = true
			e.strings = append(e.strings, v.Value)
		}
	case *ir.BinaryExpr:
		e.collectStringsExpr(v.Left)
		e.collectStringsExpr(v.Right)
	case *ir.UnaryExpr:
		e.collectStringsExpr(v.Expr)
	case *ir.TernaryExpr:
		e.collectStringsExpr(v.Cond)
		e.collectStringsExpr(v.TrueExpr)
		e.collectStringsExpr(v.FalseExpr)
	case *ir.FieldAccess:
		e.collectStringsExpr(v.Object)
	case *ir.MethodCall:
		e.collectStringsExpr(v.Object)
		for _, a := range v.Args {
			e.collectStringsExpr(a)
		}
	case *ir.StaticMethodCall:
		for _, a := range v.Args {
			e.collectStringsExpr(a)
		}
	case *ir.IndirectCall:
		e.collectStringsExpr(v.Callee)
		for _, a := range v.Args {
			e.collectStringsExpr(a)
		}
	case *ir.NewExpr:
		for _, a := range v.Args {
			e.collectStringsExpr(a)
		}
	case *ir.NewArrayExpr:
		e.collectStringsExpr(v.Size)
	case *ir.ArrayInitExpr:
		for _, a := range v.Elems {
			e.collectStringsExpr(a)
		}
	case *ir.ArrayAccess:
		e.collectStringsExpr(v.Array)
		e.collectStringsExpr(v.Index)
	case *ir.CastExpr:
		e.collectStringsExpr(v.Expr)
	case *ir.LambdaExpr:
		if v.Body != nil {
			e.collectStrings(v.Body.Statements)
		}
	}
}

// collectLocals returns every LocalVar name referenced anywhere in the
// statements, so each gets an entry alloca. Names are returned in a
// stable first-seen order.
func collectLocals(stmts []ir.Stmt) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	var walkExpr func(x ir.Expr)
	var walkStmt func(s ir.Stmt)
	walkExpr = func(x ir.Expr) {
		switch v := x.(type) {
		case nil:
		case *ir.LocalVar:
			add(v.Name)
		case *ir.BinaryExpr:
			walkExpr(v.Left)
			walkExpr(v.Right)
		case *ir.UnaryExpr:
			walkExpr(v.Expr)
		case *ir.TernaryExpr:
			walkExpr(v.Cond)
			walkExpr(v.TrueExpr)
			walkExpr(v.FalseExpr)
		case *ir.FieldAccess:
			walkExpr(v.Object)
		case *ir.MethodCall:
			walkExpr(v.Object)
			for _, a := range v.Args {
				walkExpr(a)
			}
		case *ir.StaticMethodCall:
			for _, a := range v.Args {
				walkExpr(a)
			}
		case *ir.IndirectCall:
			walkExpr(v.Callee)
			for _, a := range v.Args {
				walkExpr(a)
			}
		case *ir.NewExpr:
			for _, a := range v.Args {
				walkExpr(a)
			}
		case *ir.NewArrayExpr:
			walkExpr(v.Size)
		case *ir.ArrayInitExpr:
			for _, a := range v.Elems {
				walkExpr(a)
			}
		case *ir.ArrayAccess:
			walkExpr(v.Array)
			walkExpr(v.Index)
		case *ir.CastExpr:
			walkExpr(v.Expr)
		case *ir.LambdaExpr:
			for _, p := range v.Params {
				add(p)
			}
			if v.Body != nil {
				for _, s := range v.Body.Statements {
					walkStmt(s)
				}
			}
		}
	}
	walkStmt = func(s ir.Stmt) {
		switch v := s.(type) {
		case *ir.AssignStmt:
			walkExpr(v.Target)
			walkExpr(v.Value)
		case *ir.ReturnStmt:
			walkExpr(v.Value)
		case *ir.ExprStmt:
			walkExpr(v.Expr)
		case *ir.SuperCallStmt:
			for _, a := range v.Args {
				walkExpr(a)
			}
		case *ir.ThisCallStmt:
			for _, a := range v.Args {
				walkExpr(a)
			}
		case *ir.IfStmt:
			walkExpr(v.Cond)
			if v.Then != nil {
				for _, s := range v.Then.Statements {
					walkStmt(s)
				}
			}
			if v.Else != nil {
				for _, s := range v.Else.Statements {
					walkStmt(s)
				}
			}
		case *ir.WhileStmt:
			walkExpr(v.Cond)
			if v.Body != nil {
				for _, s := range v.Body.Statements {
					walkStmt(s)
				}
			}
		case *ir.DoWhileStmt:
			walkExpr(v.Cond)
			if v.Body != nil {
				for _, s := range v.Body.Statements {
					walkStmt(s)
				}
			}
		case *ir.SwitchStmt:
			walkExpr(v.Target)
			for _, c := range v.Cases {
				for _, val := range c.Values {
					walkExpr(val)
				}
				if c.Body != nil {
					for _, s := range c.Body.Statements {
						walkStmt(s)
					}
				}
			}
			if v.Default != nil {
				for _, s := range v.Default.Statements {
					walkStmt(s)
				}
			}
		case *ir.VarDeclStmt:
			add(v.Name)
			walkExpr(v.Init)
		case *ir.ThrowStmt:
			walkExpr(v.Value)
		case *ir.ForStmt:
			walkStmt(v.Init)
			walkExpr(v.Cond)
			walkStmt(v.Post)
			if v.Body != nil {
				for _, s := range v.Body.Statements {
					walkStmt(s)
				}
			}
		case *ir.ForEachStmt:
			add(v.VarName)
			walkExpr(v.Expr)
			if v.Body != nil {
				for _, s := range v.Body.Statements {
					walkStmt(s)
				}
			}
		case *ir.TryStmt:
			for _, r := range v.Resources {
				add(r.VarName)
				walkExpr(r.Init)
			}
			if v.Body != nil {
				for _, s := range v.Body.Statements {
					walkStmt(s)
				}
			}
			for _, c := range v.Catches {
				add(c.VarName)
				if c.Body != nil {
					for _, s := range c.Body.Statements {
						walkStmt(s)
					}
				}
			}
			if v.Finally != nil {
				for _, s := range v.Finally.Statements {
					walkStmt(s)
				}
			}
		case *ir.BlockStmt:
			if v.Block != nil {
				for _, s := range v.Block.Statements {
					walkStmt(s)
				}
			}
		}
	}
	for _, s := range stmts {
		walkStmt(s)
	}
	return out
}

// llvmName quotes a function name for use as an LLVM global.
func llvmName(name string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '\\':
			b.WriteString(`\5C`)
		case c == '"':
			b.WriteString(`\22`)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\%02X`, c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// llvmLocal makes a LocalVar/label name safe for LLVM's %-sigil
// namespace. The lifter's names are already close to identifier-shaped;
// everything else is hex-escaped deterministically.
func llvmLocal(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '.':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "u%02x", c)
		}
	}
	if b.Len() == 0 {
		return "v"
	}
	return b.String()
}
