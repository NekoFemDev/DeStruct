package arm64lift

import (
	"fmt"

	"github.com/destruct/destruct/internal/ir"
)

// Shared-subexpression hoisting for rendering.
//
// The lifter keeps each register's value as an IR expression DAG, and
// routinely lets several registers (or several consumers of the same
// register) point at the identical subexpression instead of copying it.
// Rendering such a DAG naively - which is what every ir node's String()
// method does - expands every shared node once per reference, so a
// chain of instructions like "add x, x, x" (doubling the same value at
// each step) produces a rendered expression whose text is exponential
// in the number of instructions: a real packed binary produced a single
// 12.9 MB source line from a 2 KB function this way, taking seconds and
// hundreds of MB of transient allocations to format.
//
// hoistSharedExprs fixes that by giving every shared node (referenced
// more than once inside the same statement) its own synthetic "tmpN"
// local: one assignment emitted just before the statement, and every
// reference replaced by that local's name. The rendered text then grows
// with the number of unique nodes rather than the size of their
// expansion. It also makes the output more faithful: a shared call
// result is evaluated once, as the real code did, instead of appearing
// as several duplicated calls.
//
// Only statement-local sharing is handled. A node reused across
// statements stays inline and could still expand within each one, but
// that pattern is rare compared to the single pathological statement
// and would need control-flow-aware placement to hoist correctly.

// hoistableExpr reports whether it's worth/safe to give e its own
// temporary. Literals and simple names have nothing to evaluate, so a
// temp would only add noise; everything else (including calls, whose
// single evaluation is also more faithful) is hoisted once shared.
func hoistableExpr(e ir.Expr) bool {
	switch e.(type) {
	case *ir.IntLit, *ir.LongLit, *ir.FloatLit, *ir.DoubleLit,
		*ir.StringLit, *ir.BoolLit, *ir.NullLit,
		*ir.LocalVar, *ir.ThisExpr, *ir.SuperExpr,
		*ir.ClassLiteral, *ir.ClassType, *ir.MethodRefExpr:
		return false
	}
	return true
}

// exprChildren returns every direct child expression of e - the
// traversal half of the reference-counting walk (rewriteExpr below is
// the mutation half).
func exprChildren(e ir.Expr) []ir.Expr {
	switch v := e.(type) {
	case *ir.BinaryExpr:
		return []ir.Expr{v.Left, v.Right}
	case *ir.UnaryExpr:
		return []ir.Expr{v.Expr}
	case *ir.TernaryExpr:
		return []ir.Expr{v.Cond, v.TrueExpr, v.FalseExpr}
	case *ir.FieldAccess:
		return []ir.Expr{v.Object}
	case *ir.MethodCall:
		return append([]ir.Expr{v.Object}, v.Args...)
	case *ir.StaticMethodCall:
		return v.Args
	case *ir.IndirectCall:
		return append([]ir.Expr{v.Callee}, v.Args...)
	case *ir.NewExpr:
		return v.Args
	case *ir.NewArrayExpr:
		return []ir.Expr{v.Size}
	case *ir.ArrayInitExpr:
		return v.Elems
	case *ir.ArrayAccess:
		return []ir.Expr{v.Array, v.Index}
	case *ir.CastExpr:
		return []ir.Expr{v.Expr}
	}
	return nil
}

// countExprRefs increments refs for every occurrence of every node in
// root's DAG, descending into each unique node only once (via seen), so
// the walk itself stays linear in the DAG rather than in its expansion.
func countExprRefs(root ir.Expr, refs map[ir.Expr]int, seen map[ir.Expr]bool) {
	if root == nil {
		return
	}
	refs[root]++
	if seen[root] {
		return
	}
	seen[root] = true
	for _, c := range exprChildren(root) {
		countExprRefs(c, refs, seen)
	}
}

type exprHoister struct {
	refs    map[ir.Expr]int
	names   map[ir.Expr]string
	counter *int
	prelude *[]ir.Stmt
}

// rewriteExpr rewrites e's children depth-first, then replaces e itself
// with a fresh "tmpN" local if it's shared (leaving its assignment in
// the prelude). Because the replacement happens after the children are
// rewritten, a hoisted node's own assignment already refers to the
// temps of any shared descendants, in dependency order.
func (h *exprHoister) rewriteExpr(e ir.Expr) ir.Expr {
	if e == nil {
		return nil
	}
	// Already materialized: every later reference is just the temp name,
	// without re-walking (and potentially re-expanding) its subtree.
	if name, ok := h.names[e]; ok {
		return &ir.LocalVar{Name: name}
	}
	e = h.rewriteChildren(e)

	if h.refs[e] > 1 && hoistableExpr(e) {
		name := fmt.Sprintf("tmp%d", *h.counter)
		*h.counter++
		h.names[e] = name
		*h.prelude = append(*h.prelude, &ir.AssignStmt{
			Target: &ir.LocalVar{Name: name},
			Value:  e,
		})
		return &ir.LocalVar{Name: name}
	}
	return e
}

// rewriteChildren rewrites e's children in place and returns e without
// considering e itself for hoisting - the variant used for an
// assignment target, which must stay an assignable expression (a temp
// local is not one). Its children (an object, an index, ...) are
// ordinary rvalues and are still hoisted normally.
func (h *exprHoister) rewriteChildren(e ir.Expr) ir.Expr {
	switch v := e.(type) {
	case *ir.BinaryExpr:
		v.Left = h.rewriteExpr(v.Left)
		v.Right = h.rewriteExpr(v.Right)
	case *ir.UnaryExpr:
		v.Expr = h.rewriteExpr(v.Expr)
	case *ir.TernaryExpr:
		v.Cond = h.rewriteExpr(v.Cond)
		v.TrueExpr = h.rewriteExpr(v.TrueExpr)
		v.FalseExpr = h.rewriteExpr(v.FalseExpr)
	case *ir.FieldAccess:
		v.Object = h.rewriteExpr(v.Object)
	case *ir.MethodCall:
		v.Object = h.rewriteExpr(v.Object)
		for i := range v.Args {
			v.Args[i] = h.rewriteExpr(v.Args[i])
		}
	case *ir.StaticMethodCall:
		for i := range v.Args {
			v.Args[i] = h.rewriteExpr(v.Args[i])
		}
	case *ir.IndirectCall:
		v.Callee = h.rewriteExpr(v.Callee)
		for i := range v.Args {
			v.Args[i] = h.rewriteExpr(v.Args[i])
		}
	case *ir.NewExpr:
		for i := range v.Args {
			v.Args[i] = h.rewriteExpr(v.Args[i])
		}
	case *ir.NewArrayExpr:
		v.Size = h.rewriteExpr(v.Size)
	case *ir.ArrayInitExpr:
		for i := range v.Elems {
			v.Elems[i] = h.rewriteExpr(v.Elems[i])
		}
	case *ir.ArrayAccess:
		v.Array = h.rewriteExpr(v.Array)
		v.Index = h.rewriteExpr(v.Index)
	case *ir.CastExpr:
		v.Expr = h.rewriteExpr(v.Expr)
	}
	return e
}

// hasHoistableShare reports whether any node in refs is referenced more
// than once and is worth hoisting - the cheap fast-path check that
// skips all rewriting for the overwhelmingly common statement whose
// expressions are plain trees.
func hasHoistableShare(refs map[ir.Expr]int) bool {
	for e, n := range refs {
		if n > 1 && hoistableExpr(e) {
			return true
		}
	}
	return false
}

// hoistSharedExprs returns the temp assignments a statement needs
// before it, followed by the (possibly rewritten) statement itself.
// Statements this doesn't know about are returned unchanged - every
// expression-bearing statement type this package actually emits is
// listed, so the zero-value case only ever covers expression-free
// statements like break/continue.
func hoistSharedExprs(s ir.Stmt) ([]ir.Stmt, ir.Stmt) {
	if s == nil {
		return nil, nil
	}

	h := &exprHoister{
		refs:    make(map[ir.Expr]int),
		names:   make(map[ir.Expr]string),
		counter: new(int),
		prelude: &[]ir.Stmt{},
	}
	seen := make(map[ir.Expr]bool)

	countRoot := func(e ir.Expr) {
		countExprRefs(e, h.refs, seen)
	}

	// AssignStmt's target must not be replaced by a temp itself, but is
	// otherwise an ordinary expression to rewrite (see rewriteChildren).
	switch v := s.(type) {
	case *ir.AssignStmt:
		countRoot(v.Target)
		countRoot(v.Value)
	case *ir.ExprStmt:
		countRoot(v.Expr)
	case *ir.ReturnStmt:
		countRoot(v.Value)
	case *ir.IfStmt:
		countRoot(v.Cond)
	case *ir.WhileStmt:
		countRoot(v.Cond)
	case *ir.DoWhileStmt:
		countRoot(v.Cond)
	case *ir.SwitchStmt:
		countRoot(v.Target)
		for _, c := range v.Cases {
			for _, val := range c.Values {
				countRoot(val)
			}
		}
	case *ir.ThrowStmt:
		countRoot(v.Value)
	case *ir.VarDeclStmt:
		countRoot(v.Init)
	case *ir.ForStmt:
		countRoot(v.Cond)
	case *ir.ForEachStmt:
		countRoot(v.Expr)
	case *ir.SuperCallStmt:
		for _, a := range v.Args {
			countRoot(a)
		}
	case *ir.ThisCallStmt:
		for _, a := range v.Args {
			countRoot(a)
		}
	}

	if !hasHoistableShare(h.refs) {
		return nil, s
	}

	switch v := s.(type) {
	case *ir.AssignStmt:
		if v.Target != nil {
			v.Target = h.rewriteChildren(v.Target)
		}
		v.Value = h.rewriteExpr(v.Value)
	case *ir.ExprStmt:
		v.Expr = h.rewriteExpr(v.Expr)
	case *ir.ReturnStmt:
		v.Value = h.rewriteExpr(v.Value)
	case *ir.IfStmt:
		v.Cond = h.rewriteExpr(v.Cond)
	case *ir.WhileStmt:
		v.Cond = h.rewriteExpr(v.Cond)
	case *ir.DoWhileStmt:
		v.Cond = h.rewriteExpr(v.Cond)
	case *ir.SwitchStmt:
		v.Target = h.rewriteExpr(v.Target)
		for _, c := range v.Cases {
			for i := range c.Values {
				c.Values[i] = h.rewriteExpr(c.Values[i])
			}
		}
	case *ir.ThrowStmt:
		v.Value = h.rewriteExpr(v.Value)
	case *ir.VarDeclStmt:
		v.Init = h.rewriteExpr(v.Init)
	case *ir.ForStmt:
		v.Cond = h.rewriteExpr(v.Cond)
	case *ir.ForEachStmt:
		v.Expr = h.rewriteExpr(v.Expr)
	case *ir.SuperCallStmt:
		for i := range v.Args {
			v.Args[i] = h.rewriteExpr(v.Args[i])
		}
	case *ir.ThisCallStmt:
		for i := range v.Args {
			v.Args[i] = h.rewriteExpr(v.Args[i])
		}
	}

	return *h.prelude, s
}
