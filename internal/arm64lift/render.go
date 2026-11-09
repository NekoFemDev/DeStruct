package arm64lift

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/destruct/destruct/internal/ir"
)

// renderIfChain writes an if statement, collapsing the "else { if (...) }"
// shape every compiler produces for an if/else-if chain into the flat
// "} else if (...) {" form real source uses - which matters a lot for
// decompiled command dispatchers, where the previous nested-block
// rendering made an N-way string dispatch N levels deep. Recursion here
// is over the Else-only tail, so it is exactly as deep as the chain
// itself, not the enclosing statement nesting.
func renderIfChain(w io.Writer, s *ir.IfStmt, depth int, indent string) {
	fmt.Fprintf(w, "%sif (%s) {\n", indent, s.Cond)
	if s.Then != nil {
		RenderStmts(w, s.Then.Statements, depth+1)
	}
	fmt.Fprintf(w, "%s}", indent)
	if s.Else == nil || len(s.Else.Statements) == 0 {
		fmt.Fprintln(w)
		return
	}
	if inner, ok := s.Else.Statements[0].(*ir.IfStmt); ok && len(s.Else.Statements) == 1 {
		fmt.Fprint(w, " else ")
		renderIfChainTail(w, inner, depth, indent)
		return
	}
	fmt.Fprint(w, " else {\n")
	RenderStmts(w, s.Else.Statements, depth+1)
	fmt.Fprintf(w, "%s}\n", indent)
}

// renderIfChainTail is renderIfChain's continuation form: it assumes
// the caller already wrote " else " on the current line, so it must not
// re-emit the leading indent (which is what produced the mangled
// "} else      if (...)" spelling before this split). It only ever
// renders the chain's tail, never the first statement.
func renderIfChainTail(w io.Writer, s *ir.IfStmt, depth int, indent string) {
	fmt.Fprintf(w, "if (%s) {\n", s.Cond)
	if s.Then != nil {
		RenderStmts(w, s.Then.Statements, depth+1)
	}
	fmt.Fprintf(w, "%s}", indent)
	if s.Else == nil || len(s.Else.Statements) == 0 {
		fmt.Fprintln(w)
		return
	}
	if inner, ok := s.Else.Statements[0].(*ir.IfStmt); ok && len(s.Else.Statements) == 1 {
		fmt.Fprint(w, " else ")
		renderIfChainTail(w, inner, depth, indent)
		return
	}
	fmt.Fprint(w, " else {\n")
	RenderStmts(w, s.Else.Statements, depth+1)
	fmt.Fprintf(w, "%s}\n", indent)
}

// RenderStmts writes stmts as C-like pseudocode to w, indented one
// level ("    ") per depth. Recurses into IfStmt/WhileStmt/DoWhileStmt
// bodies so nested control flow prints in full; every other statement
// type (AssignStmt, ExprStmt, ReturnStmt, BreakStmt, ContinueStmt, ...)
// renders via its own ir.Stmt String() method instead, since none of
// them have anything nested worth recursing into.
//
// Each statement first goes through hoistSharedExprs (see its own doc
// comment): a statement whose expressions form a shared DAG would
// otherwise render exponentially large, since every String() method
// expands a shared node once per reference. Any temps that produces are
// printed immediately before the statement, at the same indent level.
//
// The single shared renderer for every consumer of this package's own
// output - cmd/lifttest (one function at a time) and the pipeline's
// whole-binary decompile (internal/pipeline) - so both stay in sync
// automatically with any future ir.Stmt addition instead of drifting
// into two, subtly different printers.
func RenderStmts(w io.Writer, stmts []ir.Stmt, depth int) {
	indent := strings.Repeat("    ", depth)
	for _, s := range stmts {
		prelude, s := hoistSharedExprs(s)
		for _, p := range prelude {
			fmt.Fprintf(w, "%s%s\n", indent, p)
		}
		switch v := s.(type) {
		case *ir.IfStmt:
			// A strcmp if/else-if chain is a command dispatcher: fold
			// it into the compact switch form before rendering.
			if sw, ok := tryStringDispatch(v); ok {
				renderSwitch(w, sw, depth, indent)
			} else {
				renderIfChain(w, v, depth, indent)
			}
		case *ir.WhileStmt:
			fmt.Fprintf(w, "%swhile (%s) {\n", indent, v.Cond)
			if v.Body != nil {
				RenderStmts(w, v.Body.Statements, depth+1)
			}
			fmt.Fprintf(w, "%s}\n", indent)
		case *ir.DoWhileStmt:
			fmt.Fprintf(w, "%sdo {\n", indent)
			if v.Body != nil {
				RenderStmts(w, v.Body.Statements, depth+1)
			}
			fmt.Fprintf(w, "%s} while (%s);\n", indent, v.Cond)
		case *ir.SwitchStmt:
			renderSwitch(w, v, depth, indent)
		case *ir.TryStmt:
			renderTry(w, v, depth, indent)
		default:
			fmt.Fprintf(w, "%s%s\n", indent, s)
		}
	}
}

// renderTry writes one try/catch/finally statement - see
// reconstructTryCatch for where the TryStmts it prints come from.
func renderTry(w io.Writer, v *ir.TryStmt, depth int, indent string) {
	fmt.Fprintf(w, "%stry {\n", indent)
	if v.Body != nil {
		RenderStmts(w, v.Body.Statements, depth+1)
	}
	fmt.Fprintf(w, "%s}", indent)
	for _, c := range v.Catches {
		fmt.Fprintf(w, " catch (%s %s) {\n", c.VarType, c.VarName)
		if c.Body != nil {
			RenderStmts(w, c.Body.Statements, depth+1)
		}
		fmt.Fprintf(w, "%s}", indent)
	}
	if v.Finally != nil && len(v.Finally.Statements) > 0 {
		fmt.Fprintf(w, " finally {\n")
		RenderStmts(w, v.Finally.Statements, depth+1)
		fmt.Fprintf(w, "%s}", indent)
	}
	fmt.Fprintln(w)
}

// renderSwitch writes one switch statement (or a folded string
// dispatch - see tryStringDispatch).
func renderSwitch(w io.Writer, v *ir.SwitchStmt, depth int, indent string) {
	fmt.Fprintf(w, "%sswitch (%s) {\n", indent, v.Target)
	for _, c := range v.Cases {
		for _, val := range c.Values {
			fmt.Fprintf(w, "%s    case %s:\n", indent, val)
		}
		if c.Body != nil {
			RenderStmts(w, c.Body.Statements, depth+2)
		}
	}
	if v.Default != nil && len(v.Default.Statements) > 0 {
		fmt.Fprintf(w, "%s    default:\n", indent)
		RenderStmts(w, v.Default.Statements, depth+2)
	}
	fmt.Fprintf(w, "%s}\n", indent)
}

// ---------------------------------------------------------------------------
// Unified pseudo-C translation-unit renderer
// ---------------------------------------------------------------------------
//
// RenderCFunction is the renderer used by the AArch64 --decompile /
// --emit-pseudo path. Unlike the legacy RenderStmts printer (which is
// shared with the Java/DEX IR and therefore keeps the Java-ish
// "x0.field_8" spelling), this renderer emits a complete, syntactically
// valid C function:
//
//   - a dummy function signature with the AAPCS64 x0-x7 arguments;
//   - declarations for every register/local/temporary the body uses;
//   - explicit width-correct dereferences with uintptr_t address
//     arithmetic: *(uint64_t*)((uintptr_t)x8 + 0x3b8);
//   - numeric ((uintptr_t)0x...) address constants instead of the
//     pseudo labels (.data+0x0, .got+0x8);
//   - normalized, function-unique goto labels (LABEL_1, LABEL_2, ...).
//
// Everything here is rendering-only: the lifted IR is not changed, and
// the lifter's CFG/merge/label logic is untouched.

// WriteCFilePreamble writes the fixed prologue shared by every generated
// pseudo-C translation unit. It only defines the fixed-width integer
// types the renderer uses (and a 128-bit storage type for q registers);
// it intentionally does not generate IL2CPP class layouts or other
// per-binary headers.
func WriteCFilePreamble(w io.Writer, sourceName string) {
	sourceName = strings.ReplaceAll(sourceName, "*/", "* /")
	fmt.Fprintf(w, "/*\n * DeStruct pseudo-C output for %s.\n * Unified --emit-pseudo mode: syntactically valid C, generated for\n * analysis/recompilation only (not intended to link as-is).\n */\n", sourceName)
	io.WriteString(w, "#include <stdint.h>\n#include <stddef.h>\n\n")
	io.WriteString(w, "#if defined(__SIZEOF_INT128__)\ntypedef unsigned __int128 eni_uint128;\n#else\ntypedef struct { uint64_t lo; uint64_t hi; } eni_uint128;\n#endif\n\n")
	// Virtual-dispatch helper. The body is exactly the lifted shape:
	// vtable = *(uint64_t**)obj; method = vtable[off/8]; method(args...).
	io.WriteString(w, "#define CALL_VTABLE(obj, off, ...) \\\n")
	io.WriteString(w, "    (((uint64_t (*)())(*(uint64_t*)((uintptr_t)(*(uint64_t*)((uintptr_t)(obj)))) + (off)))(__VA_ARGS__))\n\n")
}

// CRenderOptions controls the readability passes applied while emitting
// the unified pseudo-C translation unit.
type CRenderOptions struct {
	// Offsets, when non-nil, enables IL2CPP field-name comments on
	// non-zero memory displacements.
	Offsets *OffsetDB
	// OffsetComments appends "/* Class::field */" after a matching
	// memory access. It only has an effect when Offsets is set.
	OffsetComments bool
	// SimplifyVTableCalls rewrites the nested vtable-load/indirect-call
	// shape into CALL_VTABLE(obj, offset, args...).
	SimplifyVTableCalls bool
	// ReduceGotos runs the local goto/control-flow reduction pass.
	ReduceGotos bool
	// CharConstants renders printable integer constants in the ASCII
	// range as character literals with a hex comment.
	CharConstants bool
	// AddressComments appends /* ADDR */ to large numeric address
	// constants.
	AddressComments bool
}

// RenderCFunction writes one lifted function as a complete C function
// definition with the default (no readability passes) options.
func RenderCFunction(w io.Writer, name string, stmts []ir.Stmt) {
	RenderCFunctionWithOptions(w, name, stmts, CRenderOptions{})
}

// RenderCFunctionWithOptions writes one lifted function as a complete C
// function definition. name is the symbol/discovered name from the
// pipeline; it is sanitized to a valid C identifier. The return type is
// uint64_t rather than void because liftRet emits "return <value>" for
// functions whose result is read in w0/x0.
func RenderCFunctionWithOptions(w io.Writer, name string, stmts []ir.Stmt, opts CRenderOptions) {
	if opts.SimplifyVTableCalls || opts.ReduceGotos {
		stmts = OptimizeForC(stmts, COptimizerOptions{
			SimplifyVTableCalls: opts.SimplifyVTableCalls,
			ReduceGotos:         opts.ReduceGotos,
		})
	}
	r := newCRenderer(name)
	r.offsets = opts.Offsets
	r.offsetComments = opts.OffsetComments && opts.Offsets != nil
	r.charConstants = opts.CharConstants
	r.addressComments = opts.AddressComments
	r.scanStmts(stmts)

	var body bytes.Buffer
	r.stmtList(&body, stmts, 1)
	r.emitMissingLabels(&body, "    ")

	r.chooseParams()

	fmt.Fprintf(w, "uint64_t %s(", r.funcName)
	for i := 0; i < 8; i++ {
		if i > 0 {
			io.WriteString(w, ", ")
		}
		fmt.Fprintf(w, "uint64_t %s", r.params[i])
	}
	io.WriteString(w, ")\n{\n")

	r.writePrototypes(w)
	r.writeDecls(w)
	if body.Len() > 0 {
		_, _ = io.Copy(w, &body)
	}
	io.WriteString(w, "}\n\n")
}

// cRenderer holds the per-function state of the unified pseudo-C
// renderer: name maps, declaration collection, and label numbering.
type cRenderer struct {
	funcName string

	tmpCounter *int

	varNames     map[string]string // original IR name -> sanitized C name
	origByMapped map[string]string // sanitized C name -> original IR name
	varTypes     map[string]string // sanitized C name -> C declaration type
	usedOrig     map[string]bool   // original names seen in the body
	explicit     map[string]bool   // originals declared by VarDeclStmt
	paramSet     map[string]bool   // sanitized parameter names
	params       [8]string

	labels   map[string]string // original label -> normalized LABEL_n
	labelSeq int
	emitted  map[string]bool // normalized labels already defined
	gotoSeen map[string]bool
	gotoSeq  []string

	calls map[string]bool // sanitized callee names needing a prototype

	offsets         *OffsetDB
	offsetComments  bool
	charConstants   bool
	addressComments bool
}

func newCRenderer(name string) *cRenderer {
	r := &cRenderer{
		funcName:     safeCIdent(name),
		tmpCounter:   new(int),
		varNames:     make(map[string]string),
		origByMapped: make(map[string]string),
		varTypes:     make(map[string]string),
		usedOrig:     make(map[string]bool),
		explicit:     make(map[string]bool),
		paramSet:     make(map[string]bool),
		labels:       make(map[string]string),
		emitted:      make(map[string]bool),
		gotoSeen:     make(map[string]bool),
		calls:        make(map[string]bool),
	}
	if r.funcName == "" {
		r.funcName = "sub_unknown"
	}
	return r
}

// safeCIdent turns an arbitrary symbol/IR name into a valid C identifier.
func safeCIdent(name string) string {
	var b strings.Builder
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			if i == 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return ""
	}
	if cKeywords[out] {
		out = "_" + out
	}
	return out
}

var cKeywords = map[string]bool{
	"auto": true, "break": true, "case": true, "char": true,
	"const": true, "continue": true, "default": true, "do": true,
	"double": true, "else": true, "enum": true, "extern": true,
	"float": true, "for": true, "goto": true, "if": true,
	"inline": true, "int": true, "long": true, "register": true,
	"restrict": true, "return": true, "short": true, "signed": true,
	"sizeof": true, "static": true, "struct": true, "switch": true,
	"typedef": true, "union": true, "unsigned": true, "void": true,
	"volatile": true, "while": true, "_Alignas": true, "_Alignof": true,
	"_Atomic": true, "_Bool": true, "_Complex": true, "_Generic": true,
	"_Imaginary": true, "_Noreturn": true, "_Static_assert": true,
	"_Thread_local": true,
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// cVarType picks the C storage type for a pseudo variable from its name.
// x/w/q/d/s/h/bN are the physical register files; the synthetic local_N,
// var_N, fvar_N and tmpN names are integer scratch storage.
func cVarType(name string) string {
	if len(name) >= 2 && allDigits(name[1:]) {
		switch name[0] {
		case 'x':
			return "uint64_t"
		case 'w':
			return "uint32_t"
		case 'q':
			return "eni_uint128"
		case 'd':
			return "uint64_t"
		case 's':
			return "uint32_t"
		case 'h':
			return "uint16_t"
		case 'b':
			return "uint8_t"
		}
	}
	switch {
	case name == "this", name == "null_ptr", name == "sp", name == "fp", name == "lr":
		return "uintptr_t"
	case strings.HasPrefix(name, "var_"), strings.HasPrefix(name, "fvar_"),
		strings.HasPrefix(name, "local_"), strings.HasPrefix(name, "tmp"):
		return "int64_t"
	default:
		return "uint64_t"
	}
}

// cTypeForWidth is il2cppCastType's C-renderer counterpart, extended with
// the 16-byte q-register width.
func cTypeForWidth(width int) string {
	switch width {
	case 1:
		return "uint8_t"
	case 2:
		return "uint16_t"
	case 4:
		return "uint32_t"
	case 16:
		return "eni_uint128"
	default:
		return "uint64_t"
	}
}

func (r *cRenderer) useVar(raw string) string {
	if raw == "" {
		raw = "_unnamed"
	}
	if mapped, ok := r.varNames[raw]; ok {
		r.usedOrig[raw] = true
		return mapped
	}
	base := safeCIdent(raw)
	if base == "" {
		base = "_unnamed"
	}
	mapped := base
	for n := 2; ; n++ {
		other, exists := r.origByMapped[mapped]
		if !exists || other == raw {
			break
		}
		mapped = fmt.Sprintf("%s_%d", base, n)
	}
	r.varNames[raw] = mapped
	r.origByMapped[mapped] = raw
	r.usedOrig[raw] = true
	if !r.explicit[raw] {
		r.varTypes[mapped] = cVarType(raw)
	}
	return mapped
}

func (r *cRenderer) markExplicit(raw string) {
	if raw == "" {
		return
	}
	r.explicit[raw] = true
	r.useVar(raw)
}

func (r *cRenderer) chooseParams() {
	for i := 0; i < 8; i++ {
		x := "x" + strconv.Itoa(i)
		a := "arg" + strconv.Itoa(i)
		chosen := x
		if r.usedOrig[a] && !r.usedOrig[x] {
			if mapped, ok := r.varNames[a]; ok {
				chosen = mapped
			} else {
				chosen = a
			}
		} else if mapped, ok := r.varNames[x]; ok {
			chosen = mapped
		}
		r.params[i] = chosen
		r.paramSet[chosen] = true
	}
}

func (r *cRenderer) writePrototypes(w io.Writer) {
	names := make([]string, 0, len(r.calls))
	for name := range r.calls {
		if name == r.funcName || name == "CALL_VTABLE" || r.paramSet[name] {
			continue
		}
		if _, isVar := r.varTypes[name]; isVar {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "    extern uint64_t %s();\n", name)
	}
}

func (r *cRenderer) writeDecls(w io.Writer) {
	typeOrder := []string{
		"uint64_t", "uint32_t", "uint16_t", "uint8_t",
		"int64_t", "uintptr_t", "eni_uint128",
	}
	groups := make(map[string][]string)
	for name, typ := range r.varTypes {
		orig := r.origByMapped[name]
		if r.paramSet[name] || r.explicit[orig] {
			continue
		}
		groups[typ] = append(groups[typ], name)
	}
	seen := make(map[string]bool)
	for _, typ := range typeOrder {
		seen[typ] = true
		names := groups[typ]
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		fmt.Fprintf(w, "    %s %s;\n", typ, strings.Join(names, ", "))
	}
	// Any unexpected declaration type (a VarDeclStmt-inferred type, say)
	// still gets a deterministic line rather than being dropped.
	var extra []string
	for typ := range groups {
		if !seen[typ] {
			extra = append(extra, typ)
		}
	}
	sort.Strings(extra)
	for _, typ := range extra {
		names := groups[typ]
		sort.Strings(names)
		fmt.Fprintf(w, "    %s %s;\n", typ, strings.Join(names, ", "))
	}
}

func (r *cRenderer) labelFor(orig string) string {
	if l, ok := r.labels[orig]; ok {
		return l
	}
	r.labelSeq++
	l := fmt.Sprintf("LABEL_%d", r.labelSeq)
	r.labels[orig] = l
	return l
}

func (r *cRenderer) emitLabel(orig string) string {
	l := r.labelFor(orig)
	if r.emitted[l] {
		r.labelSeq++
		l = fmt.Sprintf("LABEL_%d", r.labelSeq)
	}
	r.emitted[l] = true
	return l
}

func (r *cRenderer) noteGoto(orig string) {
	r.labelFor(orig)
	if !r.gotoSeen[orig] {
		r.gotoSeen[orig] = true
		r.gotoSeq = append(r.gotoSeq, orig)
	}
}

// emitMissingLabels defines any goto target the lifted IR referenced
// without ever emitting the matching LabelStmt (a merge/loop label
// dropped by CFG simplification). C requires every goto target to have
// a label in the same function; placing the missing ones at the end
// keeps the translation unit valid while preserving the jump's meaning
// (fall out of the function's current path).
func (r *cRenderer) emitMissingLabels(w *bytes.Buffer, indent string) {
	for _, orig := range r.gotoSeq {
		l := r.labels[orig]
		if l == "" || r.emitted[l] {
			continue
		}
		fmt.Fprintf(w, "%s%s:;\n", indent, l)
		r.emitted[l] = true
	}
}

func (r *cRenderer) callName(raw string) string {
	name := safeCIdent(raw)
	if name == "" {
		name = "sub_unknown"
	}
	// libc/C++ names (strlen, fopen, std::... ) collide with compiler
	// builtins and library prototypes; the declarations here are the
	// deliberately unprototyped "extern uint64_t name();" form, so give
	// external calls a distinct prefix. Calls to lifted sub_/func_
	// symbols keep their names, matching the dummy definitions and the
	// existing pseudo-C vocabulary.
	if name != "CALL_VTABLE" && !strings.HasPrefix(name, "sub_") && !strings.HasPrefix(name, "func_") {
		name = "ext_" + name
	}
	r.calls[name] = true
	return name
}

func (r *cRenderer) scanStmts(stmts []ir.Stmt) {
	for _, s := range stmts {
		switch v := s.(type) {
		case *ir.IfStmt:
			if v.Then != nil {
				r.scanStmts(v.Then.Statements)
			}
			if v.Else != nil {
				r.scanStmts(v.Else.Statements)
			}
		case *ir.WhileStmt:
			if v.Body != nil {
				r.scanStmts(v.Body.Statements)
			}
		case *ir.DoWhileStmt:
			if v.Body != nil {
				r.scanStmts(v.Body.Statements)
			}
		case *ir.ForStmt:
			if v.Body != nil {
				r.scanStmts(v.Body.Statements)
			}
		case *ir.ForEachStmt:
			if v.Body != nil {
				r.scanStmts(v.Body.Statements)
			}
		case *ir.SwitchStmt:
			for _, c := range v.Cases {
				if c != nil && c.Body != nil {
					r.scanStmts(c.Body.Statements)
				}
			}
			if v.Default != nil {
				r.scanStmts(v.Default.Statements)
			}
		case *ir.TryStmt:
			if v.Body != nil {
				r.scanStmts(v.Body.Statements)
			}
			for _, c := range v.Catches {
				if c != nil && c.Body != nil {
					r.scanStmts(c.Body.Statements)
				}
			}
			if v.Finally != nil {
				r.scanStmts(v.Finally.Statements)
			}
		case *ir.BlockStmt:
			if v.Block != nil {
				r.scanStmts(v.Block.Statements)
			}
		case *ir.VarDeclStmt:
			r.markExplicit(v.Name)
		case *ir.LabelStmt:
			r.labelFor(v.Name)
		}
	}
}

func (r *cRenderer) stmtList(w *bytes.Buffer, stmts []ir.Stmt, depth int) {
	indent := strings.Repeat("    ", depth)
	for _, s := range stmts {
		if s == nil {
			continue
		}
		prelude, s := hoistSharedExprsWithCounter(s, r.tmpCounter)
		for _, p := range prelude {
			r.stmt(w, p, depth, indent)
		}
		r.stmt(w, s, depth, indent)
	}
}

func (r *cRenderer) stmt(w *bytes.Buffer, s ir.Stmt, depth int, indent string) {
	if s == nil {
		return
	}
	switch v := s.(type) {
	case *ir.IfStmt:
		r.ifChain(w, v, depth, indent, false)
	case *ir.WhileStmt:
		cond := "1"
		if v.Cond != nil {
			cond = r.expr(v.Cond)
		}
		fmt.Fprintf(w, "%swhile (%s) {\n", indent, cond)
		if v.Body != nil {
			r.stmtList(w, v.Body.Statements, depth+1)
		}
		fmt.Fprintf(w, "%s}\n", indent)
	case *ir.DoWhileStmt:
		cond := "1"
		if v.Cond != nil {
			cond = r.expr(v.Cond)
		}
		fmt.Fprintf(w, "%sdo {\n", indent)
		if v.Body != nil {
			r.stmtList(w, v.Body.Statements, depth+1)
		}
		fmt.Fprintf(w, "%s} while (%s);\n", indent, cond)
	case *ir.SwitchStmt:
		r.switchStmt(w, v, depth, indent)
	case *ir.TryStmt:
		r.tryStmt(w, v, depth, indent)
	case *ir.ForStmt:
		init := r.inlineStmt(v.Init)
		cond := "1"
		if v.Cond != nil {
			cond = r.expr(v.Cond)
		}
		post := r.inlineStmt(v.Post)
		fmt.Fprintf(w, "%sfor (%s; %s; %s) {\n", indent, init, cond, post)
		if v.Body != nil {
			r.stmtList(w, v.Body.Statements, depth+1)
		}
		fmt.Fprintf(w, "%s}\n", indent)
	case *ir.ForEachStmt:
		fmt.Fprintf(w, "%s/* for each %s %s in %s */\n%s{\n", indent, cTypeName(v.VarType), safeCIdent(v.VarName), r.expr(v.Expr), indent)
		if v.Body != nil {
			r.stmtList(w, v.Body.Statements, depth+1)
		}
		fmt.Fprintf(w, "%s}\n", indent)
	case *ir.BlockStmt:
		fmt.Fprintf(w, "%s{\n", indent)
		if v.Block != nil {
			r.stmtList(w, v.Block.Statements, depth+1)
		}
		fmt.Fprintf(w, "%s}\n", indent)
	case *ir.LabelStmt:
		fmt.Fprintf(w, "%s%s:;\n", indent, r.emitLabel(v.Name))
	case *ir.GotoStmt:
		r.noteGoto(v.Label)
		fmt.Fprintf(w, "%sgoto %s;\n", indent, r.labelFor(v.Label))
	default:
		fmt.Fprintf(w, "%s%s;\n", indent, r.inlineStmt(s))
	}
}

func (r *cRenderer) ifChain(w *bytes.Buffer, s *ir.IfStmt, depth int, indent string, tail bool) {
	cond := "1"
	if s.Cond != nil {
		cond = r.expr(s.Cond)
	}
	if tail {
		fmt.Fprintf(w, "if (%s) {\n", cond)
	} else {
		fmt.Fprintf(w, "%sif (%s) {\n", indent, cond)
	}
	if s.Then != nil {
		r.stmtList(w, s.Then.Statements, depth+1)
	}
	fmt.Fprintf(w, "%s}", indent)
	if s.Else == nil || len(s.Else.Statements) == 0 {
		fmt.Fprintln(w)
		return
	}
	if inner, ok := s.Else.Statements[0].(*ir.IfStmt); ok && len(s.Else.Statements) == 1 {
		fmt.Fprint(w, " else ")
		r.ifChain(w, inner, depth, indent, true)
		return
	}
	fmt.Fprint(w, " else {\n")
	r.stmtList(w, s.Else.Statements, depth+1)
	fmt.Fprintf(w, "%s}\n", indent)
}

func stmtEndsTerminally(s ir.Stmt) bool {
	switch s.(type) {
	case *ir.ReturnStmt, *ir.GotoStmt, *ir.BreakStmt, *ir.ContinueStmt, *ir.ThrowStmt:
		return true
	}
	return false
}

func blockEndsTerminally(b *ir.Block) bool {
	if b == nil || len(b.Statements) == 0 {
		return false
	}
	return stmtEndsTerminally(b.Statements[len(b.Statements)-1])
}

func (r *cRenderer) switchStmt(w *bytes.Buffer, v *ir.SwitchStmt, depth int, indent string) {
	target := "0"
	if v.Target != nil {
		target = r.expr(v.Target)
	}
	fmt.Fprintf(w, "%sswitch (%s) {\n", indent, target)
	for _, c := range v.Cases {
		if c == nil {
			continue
		}
		stringCase := false
		for _, val := range c.Values {
			if _, ok := val.(*ir.StringLit); ok {
				// C switch labels are integer constants; string
				// dispatch does not belong in a switch. Keep the value
				// visible as a comment and fall through to the body.
				fmt.Fprintf(w, "%s    /* case %s: (string dispatch) */\n", indent, r.expr(val))
				stringCase = true
				continue
			}
			fmt.Fprintf(w, "%s    case %s:\n", indent, r.expr(val))
		}
		if c.Body != nil {
			r.stmtList(w, c.Body.Statements, depth+2)
		}
		if !c.Fallthrough && !stringCase && c.Body != nil && !blockEndsTerminally(c.Body) {
			fmt.Fprintf(w, "%s        break;\n", indent)
		}
	}
	if v.Default != nil && len(v.Default.Statements) > 0 {
		fmt.Fprintf(w, "%s    default:\n", indent)
		r.stmtList(w, v.Default.Statements, depth+2)
	}
	fmt.Fprintf(w, "%s}\n", indent)
}

func (r *cRenderer) tryStmt(w *bytes.Buffer, v *ir.TryStmt, depth int, indent string) {
	fmt.Fprintf(w, "%s/* try */\n%s{\n", indent, indent)
	if v.Body != nil {
		r.stmtList(w, v.Body.Statements, depth+1)
	}
	fmt.Fprintf(w, "%s}\n", indent)
	for _, c := range v.Catches {
		if c == nil {
			continue
		}
		fmt.Fprintf(w, "%s/* catch (%s %s) */\n%s{\n", indent, cTypeName(c.VarType), safeCIdent(c.VarName), indent)
		if c.Body != nil {
			r.stmtList(w, c.Body.Statements, depth+1)
		}
		fmt.Fprintf(w, "%s}\n", indent)
	}
	if v.Finally != nil && len(v.Finally.Statements) > 0 {
		fmt.Fprintf(w, "%s/* finally */\n%s{\n", indent, indent)
		r.stmtList(w, v.Finally.Statements, depth+1)
		fmt.Fprintf(w, "%s}\n", indent)
	}
}

func (r *cRenderer) inlineStmt(s ir.Stmt) string {
	switch v := s.(type) {
	case nil:
		return ""
	case *ir.AssignStmt:
		return r.expr(v.Target) + " = " + r.expr(v.Value)
	case *ir.ExprStmt:
		return r.expr(v.Expr)
	case *ir.VarDeclStmt:
		name := r.useVar(v.Name)
		decl := cTypeName(v.Type) + " " + name
		if v.Init != nil {
			decl += " = " + r.expr(v.Init)
		}
		return decl
	case *ir.ReturnStmt:
		if v.Value == nil {
			return "return 0"
		}
		return "return " + r.expr(v.Value)
	case *ir.BreakStmt:
		return "break"
	case *ir.ContinueStmt:
		return "continue"
	case *ir.GotoStmt:
		r.noteGoto(v.Label)
		return "goto " + r.labelFor(v.Label)
	case *ir.LabelStmt:
		return r.labelFor(v.Name)
	case *ir.ThrowStmt:
		return "0 /* throw */"
	default:
		return "/* unsupported statement */"
	}
}

func (r *cRenderer) exprList(list []ir.Expr) string {
	parts := make([]string, len(list))
	for i, e := range list {
		parts[i] = r.expr(e)
	}
	return strings.Join(parts, ", ")
}

// callArgs renders a call's argument list. Internal sub_/func_ callees
// have a fixed eight-argument definition in this translation unit (the
// dummy AAPCS64 signature), so short calls are padded with zeroes to
// keep C's prototype checking happy. External calls use the unprototyped
// "extern uint64_t name();" form and are left exactly as lifted.
func (r *cRenderer) callArgs(fn string, args []ir.Expr) string {
	if fn != "CALL_VTABLE" && (strings.HasPrefix(fn, "sub_") || strings.HasPrefix(fn, "func_")) {
		for len(args) < 8 {
			args = append(args, &ir.IntLit{Value: 0})
		}
	}
	return r.exprList(args)
}

func (r *cRenderer) exprParen(e ir.Expr) string {
	s := r.expr(e)
	switch e.(type) {
	case *ir.BinaryExpr, *ir.TernaryExpr:
		return "(" + s + ")"
	}
	return s
}

func (r *cRenderer) addressBase(e ir.Expr, rendered string) string {
	switch v := e.(type) {
	case *ir.LocalVar:
		return "(uintptr_t)" + r.useVar(v.Name)
	case *ir.AddrLit:
		return fmt.Sprintf("(uintptr_t)0x%x", v.Value)
	default:
		return "(uintptr_t)(" + rendered + ")"
	}
}

func (r *cRenderer) fieldAccess(v *ir.FieldAccess) string {
	obj := "0"
	if v.Object != nil {
		obj = r.expr(v.Object)
	}
	if v.FieldName != "" && v.TypeName != "" {
		typ := SanitizeCType(v.TypeName)
		field := safeCIdent(v.FieldName)
		return r.withFieldComment(fmt.Sprintf("((%s*)((uintptr_t)(%s)))->%s", typ, obj, field), v)
	}
	ctype := cTypeForWidth(v.Width)
	base := r.addressBase(v.Object, obj)
	if v.HasOffset && v.Offset != 0 {
		return r.withFieldComment(fmt.Sprintf("*(%s*)(%s + 0x%x)", ctype, base, v.Offset), v)
	}
	return fmt.Sprintf("*(%s*)(%s)", ctype, base)
}

// withFieldComment appends the human-readable IL2CPP field name when the
// offset dump can resolve the displacement. Zero-offset accesses are the
// IL2CPP object header/vtable pointer, not fields, so they stay
// unannotated.
func (r *cRenderer) withFieldComment(expr string, v *ir.FieldAccess) string {
	if r.offsets == nil || !r.offsetComments || !v.HasOffset || v.Offset == 0 {
		return expr
	}
	// A non-zero access through a zero-offset load is a vtable method
	// slot, not an IL2CPP object field; offset dumps describe object
	// layouts, so a field comment there would be misleading.
	if isVTableSlotAccess(v) {
		return expr
	}
	var owner, name string
	candidates := 0
	if v.TypeName != "" && v.FieldName != "" {
		owner, name = v.TypeName, v.FieldName
	} else if v.TypeName != "" {
		if f, ok := r.offsets.FieldAtOffset(v.TypeName, v.Offset); ok {
			owner, name = f.Owner, f.Name
		}
	}
	if name == "" {
		candidates = r.offsets.FieldCountAtOffset(v.Offset)
		if f, ok := r.offsets.FieldAtOffsetAny(v.Offset, v.Width); ok {
			owner, name = f.Owner, f.Name
		}
	}
	if name == "" {
		return expr
	}
	comment := owner + "::" + name
	if owner == "" {
		comment = name
	}
	if candidates > 1 {
		comment += fmt.Sprintf(" (best match, %d candidates)", candidates)
	}
	return expr + " /* " + comment + " */"
}

// isVTableSlotAccess reports whether v is a method-slot load through a
// vtable pointer, i.e. a non-zero displacement from a zero-offset load.
func isVTableSlotAccess(v *ir.FieldAccess) bool {
	inner, ok := v.Object.(*ir.FieldAccess)
	return ok && inner.HasOffset && inner.Offset == 0 && inner.Width == 8
}

func isComparisonOp(op string) bool {
	switch op {
	case "==", "!=", "<", "<=", ">", ">=":
		return true
	}
	return false
}

// compareOperand renders a direct comparison operand. Only here do
// printable ASCII values become character literals; arithmetic operands
// such as the 32 in "(w8 | 32) == 120" keep their numeric spelling.
func (r *cRenderer) compareOperand(e ir.Expr) string {
	if lit, ok := e.(*ir.IntLit); ok && r.charConstants && lit.Value >= 32 && lit.Value <= 126 {
		return fmt.Sprintf("'%s' /* 0x%x */", escapeCChar(rune(lit.Value)), lit.Value)
	}
	return r.expr(e)
}

func (r *cRenderer) binary(v *ir.BinaryExpr) string {
	op := v.Op
	if op == ">>>" {
		op = ">>"
	}
	if op == "?" {
		// condOpFromMnemonic's fallback for an unrecognized branch
		// condition. The IR has no dedicated node for it, so render a
		// conservative comparison that keeps both operands and is valid C.
		op = "!="
	}
	if op == "instanceof" || op == "" {
		return "0"
	}
	operand := r.expr
	if isComparisonOp(v.Op) {
		operand = r.compareOperand
	}
	left := operand(v.Left)
	right := operand(v.Right)
	switch v.Left.(type) {
	case *ir.BinaryExpr, *ir.TernaryExpr:
		left = "(" + left + ")"
	}
	switch v.Right.(type) {
	case *ir.BinaryExpr, *ir.TernaryExpr:
		right = "(" + right + ")"
	}
	return left + " " + op + " " + right
}

func (r *cRenderer) expr(e ir.Expr) string {
	if e == nil {
		return "0"
	}
	switch v := e.(type) {
	case *ir.IntLit:
		return strconv.FormatInt(v.Value, 10)
	case *ir.LongLit:
		return fmt.Sprintf("%dLL", v.Value)
	case *ir.FloatLit:
		return cFloatLit(float64(v.Value), 32)
	case *ir.DoubleLit:
		return cFloatLit(v.Value, 64)
	case *ir.StringLit:
		// A register/local is integer-typed, so a bare string literal
		// is not assignable to it. The address of the literal is the
		// useful pseudo-C value anyway.
		return "((uintptr_t)" + quoteCString(v.Value) + ")"
	case *ir.BoolLit:
		if v.Value {
			return "1"
		}
		return "0"
	case *ir.NullLit:
		return "0"
	case *ir.AddrLit:
		s := fmt.Sprintf("((uintptr_t)0x%x)", v.Value)
		if r.addressComments && v.Value >= 0x10000 {
			s += " /* ADDR */"
		}
		return s
	case *ir.LocalVar:
		return r.useVar(v.Name)
	case *ir.FieldAccess:
		return r.fieldAccess(v)
	case *ir.BinaryExpr:
		return r.binary(v)
	case *ir.UnaryExpr:
		operand := r.expr(v.Expr)
		switch v.Expr.(type) {
		case *ir.BinaryExpr, *ir.TernaryExpr:
			operand = "(" + operand + ")"
		}
		return v.Op + operand
	case *ir.TernaryExpr:
		return r.exprParen(v.Cond) + " ? " + r.exprParen(v.TrueExpr) + " : " + r.exprParen(v.FalseExpr)
	case *ir.CastExpr:
		return "(" + cTypeName(v.Type) + ")" + r.exprParen(v.Expr)
	case *ir.MethodCall:
		args := make([]ir.Expr, 0, len(v.Args)+1)
		if v.Object != nil {
			args = append(args, v.Object)
		}
		args = append(args, v.Args...)
		fn := r.callName(v.Name)
		return fn + "(" + r.callArgs(fn, args) + ")"
	case *ir.StaticMethodCall:
		if v.Method == "CALL_VTABLE" && len(v.Args) >= 2 {
			off := "0x0"
			switch o := v.Args[1].(type) {
			case *ir.IntLit:
				off = fmt.Sprintf("0x%x", uint64(o.Value))
			case *ir.AddrLit:
				off = fmt.Sprintf("0x%x", o.Value)
			default:
				off = r.expr(v.Args[1])
			}
			parts := []string{r.expr(v.Args[0]), off}
			for _, a := range v.Args[2:] {
				parts = append(parts, r.expr(a))
			}
			return "CALL_VTABLE(" + strings.Join(parts, ", ") + ")"
		}
		name := v.Method
		if v.Class != "" && v.Class != "." {
			name = v.Class + "_" + v.Method
		}
		fn := r.callName(name)
		return fn + "(" + r.callArgs(fn, v.Args) + ")"
	case *ir.IndirectCall:
		return "((uint64_t (*)())(" + r.expr(v.Callee) + "))(" + r.exprList(v.Args) + ")"
	case *ir.ArrayAccess:
		return "((uint64_t*)((uintptr_t)(" + r.expr(v.Array) + ")))[" + r.expr(v.Index) + "]"
	case *ir.ThisExpr:
		return r.useVar("this")
	case *ir.SuperExpr:
		return r.useVar("super")
	case *ir.ClassType:
		return "0"
	case *ir.NewExpr, *ir.NewArrayExpr, *ir.ArrayInitExpr, *ir.MethodRefExpr, *ir.LambdaExpr, *ir.ClassLiteral:
		return "((uintptr_t)0)"
	default:
		return "0"
	}
}

func cFloatLit(v float64, bits int) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "0.0"
	}
	s := strconv.FormatFloat(v, 'g', -1, bits)
	if bits == 32 {
		return s + "f"
	}
	return s
}

// escapeCChar renders one printable ASCII rune as a C character
// literal body. Only the quote and backslash need escaping in the
// 32..126 range.
func escapeCChar(r rune) string {
	switch r {
	case '\'':
		return `\'`
	case '\\':
		return `\\`
	default:
		return string(r)
	}
}

func quoteCString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 || r == 0x7f {
				// Octal, not \uXXXX: C universal character names
				// cannot denote most control characters.
				fmt.Fprintf(&b, `\%03o`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func cPrimitiveType(name string) string {
	switch name {
	case "byte":
		return "uint8_t"
	case "sbyte":
		return "int8_t"
	case "char":
		return "uint16_t"
	case "short":
		return "int16_t"
	case "ushort":
		return "uint16_t"
	case "int":
		return "int32_t"
	case "uint":
		return "uint32_t"
	case "long":
		return "int64_t"
	case "ulong":
		return "uint64_t"
	case "float":
		return "float"
	case "double":
		return "double"
	case "bool", "boolean":
		return "uint8_t"
	case "void":
		return "void"
	default:
		return safeCIdent(name)
	}
}

func cTypeName(t ir.Type) string {
	switch v := t.(type) {
	case nil:
		return "uint64_t"
	case *ir.PrimitiveType:
		return cPrimitiveType(v.Name)
	case *ir.ClassType:
		name := v.Name
		stars := ""
		for strings.HasSuffix(name, "*") {
			stars += "*"
			name = strings.TrimSuffix(name, "*")
		}
		return safeCIdent(name) + stars
	case *ir.ArrayType:
		return cTypeName(v.Elem) + "*"
	case *ir.TypeVarRef:
		return safeCIdent(v.Name)
	default:
		return "uint64_t"
	}
}
