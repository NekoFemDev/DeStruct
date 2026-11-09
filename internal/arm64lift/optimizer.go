package arm64lift

import "github.com/destruct/destruct/internal/ir"

// optimizer.go contains the IR-level readability passes applied before
// the unified pseudo-C renderer. They preserve the runnable shape of the
// lifted code; only the spelling changes.

// COptimizerOptions controls the pre-render IR passes.
type COptimizerOptions struct {
	// SimplifyVTableCalls rewrites the
	// "load vtable pointer -> load method slot -> indirect call" shape
	// into a CALL_VTABLE(obj, offset, args...) static call. The renderer
	// and the translation-unit preamble define that macro, so the
	// generated C stays valid.
	SimplifyVTableCalls bool
	// ReduceGotos runs the local goto/control-flow peepholes (goto
	// chains, fallthrough elimination, if-inversion and simple
	// while-loop reconstruction).
	ReduceGotos bool
}

// OptimizeForC runs the enabled readability passes over one lifted
// function. Shared expression nodes are memoized, so the DAG shape the
// lifter produces is preserved instead of being expanded.
func OptimizeForC(stmts []ir.Stmt, opts COptimizerOptions) []ir.Stmt {
	if !opts.SimplifyVTableCalls && !opts.ReduceGotos {
		return stmts
	}
	out := stmts
	if opts.SimplifyVTableCalls {
		o := &cOptimizer{
			exprMemo: make(map[ir.Expr]ir.Expr),
			stmtMemo: make(map[ir.Stmt]ir.Stmt),
		}
		rewritten := make([]ir.Stmt, 0, len(out))
		for _, s := range out {
			if s == nil {
				continue
			}
			rewritten = append(rewritten, o.stmt(s))
		}
		out = rewritten
	}
	if opts.ReduceGotos {
		out = ReduceGotos(out)
	}
	return out
}

type cOptimizer struct {
	exprMemo map[ir.Expr]ir.Expr
	stmtMemo map[ir.Stmt]ir.Stmt
}

func (o *cOptimizer) block(b *ir.Block) *ir.Block {
	if b == nil {
		return nil
	}
	out := &ir.Block{Statements: make([]ir.Stmt, 0, len(b.Statements))}
	for _, s := range b.Statements {
		if s == nil {
			continue
		}
		out.Statements = append(out.Statements, o.stmt(s))
	}
	return out
}

func (o *cOptimizer) stmt(s ir.Stmt) ir.Stmt {
	if s == nil {
		return nil
	}
	if n, ok := o.stmtMemo[s]; ok {
		return n
	}
	var out ir.Stmt
	switch v := s.(type) {
	case *ir.AssignStmt:
		out = &ir.AssignStmt{Target: o.expr(v.Target), Value: o.expr(v.Value)}
	case *ir.ReturnStmt:
		out = &ir.ReturnStmt{Value: o.expr(v.Value)}
	case *ir.ExprStmt:
		out = &ir.ExprStmt{Expr: o.expr(v.Expr)}
	case *ir.IfStmt:
		out = &ir.IfStmt{Cond: o.expr(v.Cond), Then: o.block(v.Then), Else: o.block(v.Else)}
	case *ir.WhileStmt:
		out = &ir.WhileStmt{Cond: o.expr(v.Cond), Body: o.block(v.Body)}
	case *ir.DoWhileStmt:
		out = &ir.DoWhileStmt{Cond: o.expr(v.Cond), Body: o.block(v.Body)}
	case *ir.ForStmt:
		out = &ir.ForStmt{Init: o.stmt(v.Init), Cond: o.expr(v.Cond), Post: o.stmt(v.Post), Body: o.block(v.Body)}
	case *ir.SwitchStmt:
		sw := &ir.SwitchStmt{Target: o.expr(v.Target), Default: o.block(v.Default)}
		for _, c := range v.Cases {
			if c == nil {
				continue
			}
			nc := &ir.CaseClause{Body: o.block(c.Body), Fallthrough: c.Fallthrough}
			for _, val := range c.Values {
				nc.Values = append(nc.Values, o.expr(val))
			}
			sw.Cases = append(sw.Cases, nc)
		}
		out = sw
	case *ir.TryStmt:
		tr := &ir.TryStmt{Body: o.block(v.Body), Finally: o.block(v.Finally)}
		for _, res := range v.Resources {
			if res == nil {
				continue
			}
			tr.Resources = append(tr.Resources, &ir.ResourceDecl{VarType: res.VarType, VarName: res.VarName, Init: o.expr(res.Init)})
		}
		for _, c := range v.Catches {
			if c == nil {
				continue
			}
			tr.Catches = append(tr.Catches, &ir.CatchClause{VarName: c.VarName, VarType: c.VarType, Body: o.block(c.Body)})
		}
		out = tr
	case *ir.ForEachStmt:
		out = &ir.ForEachStmt{VarName: v.VarName, VarType: v.VarType, Expr: o.expr(v.Expr), Body: o.block(v.Body)}
	case *ir.BlockStmt:
		out = &ir.BlockStmt{Block: o.block(v.Block)}
	case *ir.ThrowStmt:
		out = &ir.ThrowStmt{Value: o.expr(v.Value)}
	case *ir.VarDeclStmt:
		out = &ir.VarDeclStmt{Name: v.Name, Type: v.Type, Init: o.expr(v.Init)}
	case *ir.SuperCallStmt:
		out = &ir.SuperCallStmt{Args: o.exprs(v.Args)}
	case *ir.ThisCallStmt:
		out = &ir.ThisCallStmt{Args: o.exprs(v.Args)}
	default:
		out = s
	}
	o.stmtMemo[s] = out
	return out
}

func (o *cOptimizer) exprs(list []ir.Expr) []ir.Expr {
	if list == nil {
		return nil
	}
	out := make([]ir.Expr, len(list))
	for i, e := range list {
		out[i] = o.expr(e)
	}
	return out
}

func (o *cOptimizer) expr(e ir.Expr) ir.Expr {
	if e == nil {
		return nil
	}
	if n, ok := o.exprMemo[e]; ok {
		return n
	}
	var out ir.Expr
	switch v := e.(type) {
	case *ir.IndirectCall:
		callee := o.expr(v.Callee)
		args := o.exprs(v.Args)
		if obj, off, ok := matchVTableCall(callee); ok {
			// CALL_VTABLE(obj, method_offset, original args...)
			all := make([]ir.Expr, 0, len(args)+2)
			all = append(all, obj, &ir.IntLit{Value: int64(off)})
			all = append(all, args...)
			out = &ir.StaticMethodCall{Method: "CALL_VTABLE", Args: all}
		} else {
			out = &ir.IndirectCall{Callee: callee, Args: args}
		}
	case *ir.FieldAccess:
		out = &ir.FieldAccess{
			Object:    o.expr(v.Object),
			Name:      v.Name,
			Offset:    v.Offset,
			HasOffset: v.HasOffset,
			Width:     v.Width,
			FieldName: v.FieldName,
			TypeName:  v.TypeName,
		}
	case *ir.BinaryExpr:
		out = &ir.BinaryExpr{Op: v.Op, Left: o.expr(v.Left), Right: o.expr(v.Right)}
	case *ir.UnaryExpr:
		out = &ir.UnaryExpr{Op: v.Op, Expr: o.expr(v.Expr)}
	case *ir.TernaryExpr:
		out = &ir.TernaryExpr{Cond: o.expr(v.Cond), TrueExpr: o.expr(v.TrueExpr), FalseExpr: o.expr(v.FalseExpr)}
	case *ir.CastExpr:
		out = &ir.CastExpr{Type: v.Type, Expr: o.expr(v.Expr)}
	case *ir.MethodCall:
		out = &ir.MethodCall{Object: o.expr(v.Object), Name: v.Name, Args: o.exprs(v.Args)}
	case *ir.StaticMethodCall:
		out = &ir.StaticMethodCall{Class: v.Class, Method: v.Method, Args: o.exprs(v.Args)}
	case *ir.NewExpr:
		out = &ir.NewExpr{Type: v.Type, Args: o.exprs(v.Args)}
	case *ir.NewArrayExpr:
		out = &ir.NewArrayExpr{ElemType: v.ElemType, Size: o.expr(v.Size)}
	case *ir.ArrayInitExpr:
		out = &ir.ArrayInitExpr{ElemType: v.ElemType, Elems: o.exprs(v.Elems)}
	case *ir.ArrayAccess:
		out = &ir.ArrayAccess{Array: o.expr(v.Array), Index: o.expr(v.Index)}
	default:
		out = e
	}
	o.exprMemo[e] = out
	return out
}

// matchVTableCall recognizes the canonical virtual-dispatch shape:
//
//	*(uint64_t*)((uintptr_t)(*(uint64_t*)((uintptr_t)obj)) + off)
//
// i.e. a field access through the vtable pointer loaded from [obj].
// The returned object is the receiver expression; off is the method slot
// displacement. The pattern is deliberately strict about width (8) and
// the zero-offset vtable load so ordinary nested field chains are not
// rewritten by accident.
func matchVTableCall(callee ir.Expr) (ir.Expr, uint64, bool) {
	slot, ok := callee.(*ir.FieldAccess)
	if !ok || !slot.HasOffset || slot.Offset == 0 || slot.Width != 8 {
		return nil, 0, false
	}
	if slot.FieldName != "" {
		return nil, 0, false
	}
	vtable, ok := slot.Object.(*ir.FieldAccess)
	if !ok || !vtable.HasOffset || vtable.Offset != 0 || vtable.Width != 8 {
		return nil, 0, false
	}
	if vtable.Object == nil {
		return nil, 0, false
	}
	return vtable.Object, slot.Offset, true
}

// ---------------------------------------------------------------------------
// Local goto/control-flow reduction
// ---------------------------------------------------------------------------

// ReduceGotos applies a conservative, local peephole optimization to a
// function's IR:
//
//   - goto chains:        L1: goto L2;  =>  all "goto L1" become "goto L2"
//   - fallthrough merges: goto L; L:    =>  goto removed (label removed
//     when nothing else references it)
//   - if-inversion:       if (c) goto L; else { A } L:
//     => if (!c) { A } L:
//   - simple loops:       L: if (c) goto END; BODY; goto L; END:
//     => L: while (!c) { BODY } END:
//
// The pass only works on adjacent statements in the same list (or in a
// directly nested block). It does not attempt whole-function dominator
// analysis; if a shape is not locally provable, it is left untouched.
func ReduceGotos(stmts []ir.Stmt) []ir.Stmt {
	r := &gotoReducer{refs: make(map[string]int)}
	countGotoRefsList(stmts, r.refs)
	for i := 0; i < 64; i++ {
		changed := false
		stmts = r.reduceList(stmts, &changed)
		if !changed {
			break
		}
	}
	return stmts
}

type gotoReducer struct {
	refs map[string]int
}

func (r *gotoReducer) reduceList(stmts []ir.Stmt, changed *bool) []ir.Stmt {
	for _, s := range stmts {
		r.reduceNested(s, changed)
	}
	stmts = r.resolveChains(stmts, changed)
	stmts = r.removeFallthrough(stmts, changed)
	stmts = r.invertIfs(stmts, changed)
	stmts = r.removeIfTailFallthrough(stmts, changed)
	stmts = r.simplifyEmptyIfs(stmts, changed)
	stmts = r.collapseLoops(stmts, changed)
	stmts = r.dropUnreferencedLabels(stmts, changed)
	return stmts
}

func (r *gotoReducer) reduceNested(s ir.Stmt, changed *bool) {
	switch v := s.(type) {
	case *ir.IfStmt:
		if v.Then != nil {
			v.Then.Statements = r.reduceList(v.Then.Statements, changed)
		}
		if v.Else != nil {
			v.Else.Statements = r.reduceList(v.Else.Statements, changed)
		}
	case *ir.WhileStmt:
		if v.Body != nil {
			v.Body.Statements = r.reduceList(v.Body.Statements, changed)
		}
	case *ir.DoWhileStmt:
		if v.Body != nil {
			v.Body.Statements = r.reduceList(v.Body.Statements, changed)
		}
	case *ir.ForStmt:
		if v.Body != nil {
			v.Body.Statements = r.reduceList(v.Body.Statements, changed)
		}
	case *ir.ForEachStmt:
		if v.Body != nil {
			v.Body.Statements = r.reduceList(v.Body.Statements, changed)
		}
	case *ir.SwitchStmt:
		for _, c := range v.Cases {
			if c != nil && c.Body != nil {
				c.Body.Statements = r.reduceList(c.Body.Statements, changed)
			}
		}
		if v.Default != nil {
			v.Default.Statements = r.reduceList(v.Default.Statements, changed)
		}
	case *ir.TryStmt:
		if v.Body != nil {
			v.Body.Statements = r.reduceList(v.Body.Statements, changed)
		}
		for _, c := range v.Catches {
			if c != nil && c.Body != nil {
				c.Body.Statements = r.reduceList(c.Body.Statements, changed)
			}
		}
		if v.Finally != nil {
			v.Finally.Statements = r.reduceList(v.Finally.Statements, changed)
		}
	case *ir.BlockStmt:
		if v.Block != nil {
			v.Block.Statements = r.reduceList(v.Block.Statements, changed)
		}
	}
}

func countGotoRefsList(stmts []ir.Stmt, refs map[string]int) {
	for _, s := range stmts {
		switch v := s.(type) {
		case *ir.GotoStmt:
			refs[v.Label]++
		case *ir.IfStmt:
			if v.Then != nil {
				countGotoRefsList(v.Then.Statements, refs)
			}
			if v.Else != nil {
				countGotoRefsList(v.Else.Statements, refs)
			}
		case *ir.WhileStmt:
			if v.Body != nil {
				countGotoRefsList(v.Body.Statements, refs)
			}
		case *ir.DoWhileStmt:
			if v.Body != nil {
				countGotoRefsList(v.Body.Statements, refs)
			}
		case *ir.ForStmt:
			if v.Body != nil {
				countGotoRefsList(v.Body.Statements, refs)
			}
		case *ir.ForEachStmt:
			if v.Body != nil {
				countGotoRefsList(v.Body.Statements, refs)
			}
		case *ir.SwitchStmt:
			for _, c := range v.Cases {
				if c != nil && c.Body != nil {
					countGotoRefsList(c.Body.Statements, refs)
				}
			}
			if v.Default != nil {
				countGotoRefsList(v.Default.Statements, refs)
			}
		case *ir.TryStmt:
			if v.Body != nil {
				countGotoRefsList(v.Body.Statements, refs)
			}
			for _, c := range v.Catches {
				if c != nil && c.Body != nil {
					countGotoRefsList(c.Body.Statements, refs)
				}
			}
			if v.Finally != nil {
				countGotoRefsList(v.Finally.Statements, refs)
			}
		case *ir.BlockStmt:
			if v.Block != nil {
				countGotoRefsList(v.Block.Statements, refs)
			}
		}
	}
}

// resolveChains maps labels whose body is immediately a goto (or another
// label) to their target and rewrites every goto transitively.
func (r *gotoReducer) resolveChains(stmts []ir.Stmt, changed *bool) []ir.Stmt {
	targets := make(map[string]string)
	for i := 0; i+1 < len(stmts); i++ {
		lab, ok := stmts[i].(*ir.LabelStmt)
		if !ok {
			continue
		}
		switch next := stmts[i+1].(type) {
		case *ir.GotoStmt:
			targets[lab.Name] = next.Label
		case *ir.LabelStmt:
			targets[lab.Name] = next.Name
		}
	}
	if len(targets) == 0 {
		return stmts
	}
	resolve := func(label string) string {
		seen := make(map[string]bool)
		for {
			next, ok := targets[label]
			if !ok || next == label || seen[label] {
				return label
			}
			seen[label] = true
			label = next
		}
	}
	r.rewriteGotos(stmts, resolve, changed)
	return stmts
}

func (r *gotoReducer) rewriteGotos(stmts []ir.Stmt, resolve func(string) string, changed *bool) {
	for _, s := range stmts {
		switch v := s.(type) {
		case *ir.GotoStmt:
			if next := resolve(v.Label); next != v.Label {
				r.refs[v.Label]--
				r.refs[next]++
				v.Label = next
				*changed = true
			}
		case *ir.IfStmt:
			if v.Then != nil {
				r.rewriteGotos(v.Then.Statements, resolve, changed)
			}
			if v.Else != nil {
				r.rewriteGotos(v.Else.Statements, resolve, changed)
			}
		case *ir.WhileStmt:
			if v.Body != nil {
				r.rewriteGotos(v.Body.Statements, resolve, changed)
			}
		case *ir.DoWhileStmt:
			if v.Body != nil {
				r.rewriteGotos(v.Body.Statements, resolve, changed)
			}
		case *ir.ForStmt:
			if v.Body != nil {
				r.rewriteGotos(v.Body.Statements, resolve, changed)
			}
		case *ir.ForEachStmt:
			if v.Body != nil {
				r.rewriteGotos(v.Body.Statements, resolve, changed)
			}
		case *ir.SwitchStmt:
			for _, c := range v.Cases {
				if c != nil && c.Body != nil {
					r.rewriteGotos(c.Body.Statements, resolve, changed)
				}
			}
			if v.Default != nil {
				r.rewriteGotos(v.Default.Statements, resolve, changed)
			}
		case *ir.TryStmt:
			if v.Body != nil {
				r.rewriteGotos(v.Body.Statements, resolve, changed)
			}
			for _, c := range v.Catches {
				if c != nil && c.Body != nil {
					r.rewriteGotos(c.Body.Statements, resolve, changed)
				}
			}
			if v.Finally != nil {
				r.rewriteGotos(v.Finally.Statements, resolve, changed)
			}
		case *ir.BlockStmt:
			if v.Block != nil {
				r.rewriteGotos(v.Block.Statements, resolve, changed)
			}
		}
	}
}

// removeFallthrough drops "goto L;" when the very next statement is
// "L:;". The label itself is left for dropUnreferencedLabels.
func (r *gotoReducer) removeFallthrough(stmts []ir.Stmt, changed *bool) []ir.Stmt {
	for i := 0; i+1 < len(stmts); {
		g, ok := stmts[i].(*ir.GotoStmt)
		if !ok {
			i++
			continue
		}
		lab, ok := stmts[i+1].(*ir.LabelStmt)
		if !ok || g.Label != lab.Name {
			i++
			continue
		}
		r.refs[g.Label]--
		stmts = append(stmts[:i], stmts[i+1:]...)
		*changed = true
	}
	return stmts
}

// invertIfs handles:
//
//	if (c) goto L; else { A } L:   =>  if (!c) { A } L:
//	if (c) { A } else goto L; L:   =>  if (c) { A } L:
//	if (c) goto L; L:              =>  (removed)
func (r *gotoReducer) invertIfs(stmts []ir.Stmt, changed *bool) []ir.Stmt {
	for i := 0; i < len(stmts); i++ {
		ifs, ok := stmts[i].(*ir.IfStmt)
		if !ok || i+1 >= len(stmts) {
			continue
		}
		next, ok := stmts[i+1].(*ir.LabelStmt)
		if !ok {
			continue
		}
		thenGoto, thenOnly := singleGoto(ifs.Then)
		elseGoto, elseOnly := singleGoto(ifs.Else)
		elseEmpty := ifs.Else == nil || len(ifs.Else.Statements) == 0
		thenEmpty := ifs.Then == nil || len(ifs.Then.Statements) == 0

		switch {
		case thenOnly && thenGoto == next.Name:
			r.refs[thenGoto]--
			if elseEmpty {
				if isPureExpr(ifs.Cond) {
					stmts = append(stmts[:i], stmts[i+1:]...)
					i--
				} else {
					// Keep the condition's side effects even though
					// both branches just fall through to L.
					stmts[i] = &ir.ExprStmt{Expr: ifs.Cond}
				}
			} else {
				ifs.Cond = negateCondition(ifs.Cond)
				ifs.Then = ifs.Else
				ifs.Else = nil
			}
			*changed = true
		case elseOnly && elseGoto == next.Name:
			r.refs[elseGoto]--
			ifs.Else = nil
			if thenEmpty {
				if isPureExpr(ifs.Cond) {
					stmts = append(stmts[:i], stmts[i+1:]...)
					i--
				} else {
					stmts[i] = &ir.ExprStmt{Expr: ifs.Cond}
				}
			}
			*changed = true
		}
	}
	return stmts
}

// removeIfTailFallthrough drops a trailing "goto L;" from an if/else
// block when the statement immediately after the if is "L:;" - both
// paths reach L anyway.
func (r *gotoReducer) removeIfTailFallthrough(stmts []ir.Stmt, changed *bool) []ir.Stmt {
	for i := 0; i+1 < len(stmts); i++ {
		ifs, ok := stmts[i].(*ir.IfStmt)
		if !ok {
			continue
		}
		next, ok := stmts[i+1].(*ir.LabelStmt)
		if !ok {
			continue
		}
		r.dropTailGoto(ifs.Then, next.Name, changed)
		r.dropTailGoto(ifs.Else, next.Name, changed)
	}
	return stmts
}

// dropTailGoto removes a trailing "goto target" from a branch tail,
// following else-if chains and bare blocks. It does not descend into
// loops or switches: a goto there does not simply fall out to the
// statement after the enclosing if.
func (r *gotoReducer) dropTailGoto(b *ir.Block, target string, changed *bool) {
	if b == nil || len(b.Statements) == 0 {
		return
	}
	last := b.Statements[len(b.Statements)-1]
	switch v := last.(type) {
	case *ir.GotoStmt:
		if v.Label != target {
			return
		}
		b.Statements = b.Statements[:len(b.Statements)-1]
		r.refs[target]--
		*changed = true
	case *ir.IfStmt:
		r.dropTailGoto(v.Then, target, changed)
		r.dropTailGoto(v.Else, target, changed)
	case *ir.BlockStmt:
		r.dropTailGoto(v.Block, target, changed)
	}
}

// simplifyEmptyIfs inverts/drops branches that became empty after a
// trailing goto was removed: "if (c) {} else { A }" becomes
// "if (!c) { A }", and a fully empty if with a side-effect-free
// condition disappears.
func (r *gotoReducer) simplifyEmptyIfs(stmts []ir.Stmt, changed *bool) []ir.Stmt {
	out := make([]ir.Stmt, 0, len(stmts))
	for _, s := range stmts {
		ifs, ok := s.(*ir.IfStmt)
		if !ok {
			out = append(out, s)
			continue
		}
		thenEmpty := ifs.Then == nil || len(ifs.Then.Statements) == 0
		elseEmpty := ifs.Else == nil || len(ifs.Else.Statements) == 0
		switch {
		case thenEmpty && !elseEmpty:
			ifs.Cond = negateCondition(ifs.Cond)
			ifs.Then = ifs.Else
			ifs.Else = nil
			*changed = true
		case !thenEmpty && elseEmpty:
			ifs.Else = nil
		case thenEmpty && elseEmpty:
			if isPureExpr(ifs.Cond) {
				*changed = true
				continue
			}
		}
		out = append(out, ifs)
	}
	return out
}

// isPureExpr reports whether evaluating e has no observable side effect
// (calls, allocations). Field/array loads count as pure here; the
// renderer already models them as plain memory reads.
func isPureExpr(e ir.Expr) bool {
	switch v := e.(type) {
	case nil:
		return true
	case *ir.MethodCall, *ir.StaticMethodCall, *ir.IndirectCall,
		*ir.NewExpr, *ir.NewArrayExpr, *ir.ArrayInitExpr, *ir.LambdaExpr:
		return false
	case *ir.BinaryExpr:
		return isPureExpr(v.Left) && isPureExpr(v.Right)
	case *ir.UnaryExpr:
		return isPureExpr(v.Expr)
	case *ir.TernaryExpr:
		return isPureExpr(v.Cond) && isPureExpr(v.TrueExpr) && isPureExpr(v.FalseExpr)
	case *ir.CastExpr:
		return isPureExpr(v.Expr)
	case *ir.FieldAccess:
		return isPureExpr(v.Object)
	case *ir.ArrayAccess:
		return isPureExpr(v.Array) && isPureExpr(v.Index)
	default:
		return true
	}
}

func singleGoto(b *ir.Block) (string, bool) {
	if b == nil || len(b.Statements) != 1 {
		return "", false
	}
	if g, ok := b.Statements[0].(*ir.GotoStmt); ok {
		return g.Label, true
	}
	return "", false
}

func negateCondition(e ir.Expr) ir.Expr {
	if e == nil {
		return nil
	}
	if u, ok := e.(*ir.UnaryExpr); ok && u.Op == "!" {
		return u.Expr
	}
	if b, ok := e.(*ir.BinaryExpr); ok {
		switch b.Op {
		case "==":
			b.Op = "!="
			return b
		case "!=":
			b.Op = "=="
			return b
		case "<":
			b.Op = ">="
			return b
		case "<=":
			b.Op = ">"
			return b
		case ">":
			b.Op = "<="
			return b
		case ">=":
			b.Op = "<"
			return b
		}
	}
	return &ir.UnaryExpr{Op: "!", Expr: e}
}

// collapseLoops recognizes the local two-label loop shape:
//
//	L: if (exit) goto END; BODY; goto L; END:
//
// and rewrites it to:
//
//	L: while (!exit) { BODY } END:
//
// The L and END labels are kept only when something else still jumps to
// them. Bodies containing a break/continue that would bind to an outer
// loop are left untouched.
func (r *gotoReducer) collapseLoops(stmts []ir.Stmt, changed *bool) []ir.Stmt {
	for i := 0; i < len(stmts); i++ {
		start, ok := stmts[i].(*ir.LabelStmt)
		if !ok || i+1 >= len(stmts) {
			continue
		}
		guard, ok := stmts[i+1].(*ir.IfStmt)
		if !ok {
			continue
		}
		endLabel, loopCond, ok := loopGuard(guard)
		if !ok {
			continue
		}
		back := -1
		for j := i + 2; j < len(stmts); j++ {
			if g, ok := stmts[j].(*ir.GotoStmt); ok && g.Label == start.Name {
				back = j
				break
			}
		}
		if back < 0 || back+1 >= len(stmts) {
			continue
		}
		end, ok := stmts[back+1].(*ir.LabelStmt)
		if !ok || end.Name != endLabel {
			continue
		}
		body := stmts[i+2 : back]
		if hasCurrentLevelBreakContinue(body) {
			continue
		}

		// The guard goto and the back-edge are consumed by the loop.
		r.refs[endLabel]--
		r.refs[start.Name]--

		repl := make([]ir.Stmt, 0, 3)
		if r.refs[start.Name] > 0 {
			repl = append(repl, start)
		}
		repl = append(repl, &ir.WhileStmt{
			Cond: loopCond,
			Body: &ir.Block{Statements: append([]ir.Stmt(nil), body...)},
		})
		if r.refs[endLabel] > 0 {
			repl = append(repl, end)
		}

		out := make([]ir.Stmt, 0, len(stmts)-(back+2-i)+len(repl))
		out = append(out, stmts[:i]...)
		out = append(out, repl...)
		out = append(out, stmts[back+2:]...)
		stmts = out
		*changed = true
		i += len(repl) - 1
	}
	return stmts
}

func loopGuard(ifs *ir.IfStmt) (endLabel string, cond ir.Expr, ok bool) {
	if ifs == nil || ifs.Cond == nil {
		return "", nil, false
	}
	thenGoto, thenOnly := singleGoto(ifs.Then)
	elseGoto, elseOnly := singleGoto(ifs.Else)
	thenEmpty := ifs.Then == nil || len(ifs.Then.Statements) == 0
	elseEmpty := ifs.Else == nil || len(ifs.Else.Statements) == 0
	switch {
	case thenOnly && elseEmpty:
		return thenGoto, negateCondition(ifs.Cond), true
	case elseOnly && thenEmpty:
		return elseGoto, ifs.Cond, true
	}
	return "", nil, false
}

// hasCurrentLevelBreakContinue reports whether stmts contains a
// break/continue that would bind to the loop being introduced. Breaks
// inside an existing nested loop are fine and not visited.
func hasCurrentLevelBreakContinue(stmts []ir.Stmt) bool {
	for _, s := range stmts {
		switch v := s.(type) {
		case *ir.BreakStmt, *ir.ContinueStmt:
			return true
		case *ir.IfStmt:
			if v.Then != nil && hasCurrentLevelBreakContinue(v.Then.Statements) {
				return true
			}
			if v.Else != nil && hasCurrentLevelBreakContinue(v.Else.Statements) {
				return true
			}
		case *ir.SwitchStmt:
			for _, c := range v.Cases {
				if c != nil && c.Body != nil && hasCurrentLevelBreakContinue(c.Body.Statements) {
					return true
				}
			}
			if v.Default != nil && hasCurrentLevelBreakContinue(v.Default.Statements) {
				return true
			}
		case *ir.TryStmt:
			if v.Body != nil && hasCurrentLevelBreakContinue(v.Body.Statements) {
				return true
			}
			for _, c := range v.Catches {
				if c != nil && c.Body != nil && hasCurrentLevelBreakContinue(c.Body.Statements) {
					return true
				}
			}
			if v.Finally != nil && hasCurrentLevelBreakContinue(v.Finally.Statements) {
				return true
			}
		case *ir.BlockStmt:
			if v.Block != nil && hasCurrentLevelBreakContinue(v.Block.Statements) {
				return true
			}
		}
	}
	return false
}

func (r *gotoReducer) dropUnreferencedLabels(stmts []ir.Stmt, changed *bool) []ir.Stmt {
	out := make([]ir.Stmt, 0, len(stmts))
	for _, s := range stmts {
		if lab, ok := s.(*ir.LabelStmt); ok && r.refs[lab.Name] == 0 {
			*changed = true
			continue
		}
		out = append(out, s)
	}
	return out
}
