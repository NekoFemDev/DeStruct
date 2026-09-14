package arm64lift

import (
	"fmt"
	"io"
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
