package arm64lift

import "github.com/destruct/destruct/internal/ir"

// Deprecated: RewriteForIL2CPP is the legacy rewrite helper for the
// removed --emit-il2cpp-c mode. The unified pseudo-C renderer
// (RenderCFunction) applies its C spellings at print time, so the
// pipeline no longer calls this. It is kept only for API compatibility.
//
// RewriteForIL2CPP converts one lifted function's IR statements into
// the shapes the removed --emit-il2cpp-c output mode wanted, without touching
// the pseudo-C (-emit-pseudo / default) rendering path at all:
//
//   - a field access whose IL2CPP field name was resolved becomes
//     ((FieldOwner*)base)->field - an arrow access through a pointer
//     cast, which is the only valid C spelling of that dereference;
//   - every other field access the lifter built from a memory
//     displacement becomes an explicit, width-correct dereference:
//     *(uint64_t*)(base + 0x3b8), or *(uint64_t*)base when the
//     displacement is zero. The synthetic "base.field_952" name it
//     replaces encodes a decimal byte displacement, which is a lifter
//     artifact - C has no such member;
//   - address constants drop their symbolic label (".rodata+0x1fa0")
//     so they render as plain hex numbers, matching the numeric style
//     of C output.
//
// Everything else passes through structurally unchanged. Shared nodes
// are memoized, so an IR DAG (see hoistSharedExprs) stays a DAG rather
// than being expanded exponentially; nodes without IL2CPP metadata -
// e.g. anything the JVM/DEX side produced - are returned as-is.
func RewriteForIL2CPP(stmts []ir.Stmt) []ir.Stmt {
	rw := &il2cppRewriter{
		exprMemo: make(map[ir.Expr]ir.Expr),
		stmts:    make(map[ir.Stmt]ir.Stmt),
	}
	out := make([]ir.Stmt, 0, len(stmts))
	for _, s := range stmts {
		if s == nil {
			continue
		}
		out = append(out, rw.stmt(s))
	}
	return out
}

type il2cppRewriter struct {
	exprMemo map[ir.Expr]ir.Expr
	stmts    map[ir.Stmt]ir.Stmt
}

// il2cppCastType returns the C integer type a field access of the given
// byte width dereferences through: an 8-byte access (ldr/str xN) is a
// uint64_t, a 4-byte one (wN) a uint32_t, and the byte/halfword loads
// map down accordingly. Unknown widths default to 8, the width of the
// plain "ldr" the lifter understands.
func il2cppCastType(width int) string {
	switch width {
	case 1:
		return "uint8_t"
	case 2:
		return "uint16_t"
	case 4:
		return "uint32_t"
	default:
		return "uint64_t"
	}
}

func (rw *il2cppRewriter) block(b *ir.Block) *ir.Block {
	if b == nil {
		return nil
	}
	out := &ir.Block{Statements: make([]ir.Stmt, 0, len(b.Statements))}
	for _, s := range b.Statements {
		if s == nil {
			continue
		}
		out.Statements = append(out.Statements, rw.stmt(s))
	}
	return out
}

func (rw *il2cppRewriter) stmt(s ir.Stmt) ir.Stmt {
	if s == nil {
		return nil
	}
	if n, ok := rw.stmts[s]; ok {
		return n
	}
	var out ir.Stmt
	switch v := s.(type) {
	case *ir.AssignStmt:
		out = &ir.AssignStmt{Target: rw.expr(v.Target), Value: rw.expr(v.Value)}
	case *ir.ReturnStmt:
		out = &ir.ReturnStmt{Value: rw.expr(v.Value)}
	case *ir.ExprStmt:
		out = &ir.ExprStmt{Expr: rw.expr(v.Expr)}
	case *ir.IfStmt:
		out = &ir.IfStmt{Cond: rw.expr(v.Cond), Then: rw.block(v.Then), Else: rw.block(v.Else)}
	case *ir.WhileStmt:
		out = &ir.WhileStmt{Cond: rw.expr(v.Cond), Body: rw.block(v.Body)}
	case *ir.DoWhileStmt:
		out = &ir.DoWhileStmt{Cond: rw.expr(v.Cond), Body: rw.block(v.Body)}
	case *ir.ForStmt:
		out = &ir.ForStmt{Init: rw.stmt(v.Init), Cond: rw.expr(v.Cond), Post: rw.stmt(v.Post), Body: rw.block(v.Body)}
	case *ir.SwitchStmt:
		sw := &ir.SwitchStmt{Target: rw.expr(v.Target), Default: rw.block(v.Default)}
		for _, c := range v.Cases {
			if c == nil {
				continue
			}
			nc := &ir.CaseClause{Body: rw.block(c.Body), Fallthrough: c.Fallthrough}
			for _, val := range c.Values {
				nc.Values = append(nc.Values, rw.expr(val))
			}
			sw.Cases = append(sw.Cases, nc)
		}
		out = sw
	case *ir.TryStmt:
		tr := &ir.TryStmt{Body: rw.block(v.Body), Finally: rw.block(v.Finally)}
		for _, res := range v.Resources {
			if res == nil {
				continue
			}
			tr.Resources = append(tr.Resources, &ir.ResourceDecl{VarType: res.VarType, VarName: res.VarName, Init: rw.expr(res.Init)})
		}
		for _, c := range v.Catches {
			if c == nil {
				continue
			}
			tr.Catches = append(tr.Catches, &ir.CatchClause{VarName: c.VarName, VarType: c.VarType, Body: rw.block(c.Body)})
		}
		out = tr
	case *ir.ForEachStmt:
		out = &ir.ForEachStmt{VarName: v.VarName, VarType: v.VarType, Expr: rw.expr(v.Expr), Body: rw.block(v.Body)}
	case *ir.BlockStmt:
		out = &ir.BlockStmt{Block: rw.block(v.Block)}
	case *ir.ThrowStmt:
		out = &ir.ThrowStmt{Value: rw.expr(v.Value)}
	case *ir.VarDeclStmt:
		out = &ir.VarDeclStmt{Name: v.Name, Type: v.Type, Init: rw.expr(v.Init)}
	case *ir.SuperCallStmt:
		out = &ir.SuperCallStmt{Args: rw.exprs(v.Args)}
	case *ir.ThisCallStmt:
		out = &ir.ThisCallStmt{Args: rw.exprs(v.Args)}
	default:
		out = s
	}
	rw.stmts[s] = out
	return out
}

func (rw *il2cppRewriter) exprs(list []ir.Expr) []ir.Expr {
	if list == nil {
		return nil
	}
	out := make([]ir.Expr, len(list))
	for i, e := range list {
		out[i] = rw.expr(e)
	}
	return out
}

func (rw *il2cppRewriter) expr(e ir.Expr) ir.Expr {
	if e == nil {
		return nil
	}
	if n, ok := rw.exprMemo[e]; ok {
		return n
	}
	var out ir.Expr
	switch v := e.(type) {
	case *ir.FieldAccess:
		out = rw.fieldAccess(v)
	case *ir.AddrLit:
		// C output wants the numeric address; the symbolic label only
		// makes sense in the pseudo-C rendering.
		out = &ir.AddrLit{Value: v.Value}
	case *ir.BinaryExpr:
		out = &ir.BinaryExpr{Op: v.Op, Left: rw.expr(v.Left), Right: rw.expr(v.Right)}
	case *ir.UnaryExpr:
		out = &ir.UnaryExpr{Op: v.Op, Expr: rw.expr(v.Expr)}
	case *ir.TernaryExpr:
		out = &ir.TernaryExpr{Cond: rw.expr(v.Cond), TrueExpr: rw.expr(v.TrueExpr), FalseExpr: rw.expr(v.FalseExpr)}
	case *ir.CastExpr:
		out = &ir.CastExpr{Type: v.Type, Expr: rw.expr(v.Expr)}
	case *ir.MethodCall:
		out = &ir.MethodCall{Object: rw.expr(v.Object), Name: v.Name, Args: rw.exprs(v.Args)}
	case *ir.StaticMethodCall:
		out = &ir.StaticMethodCall{Class: v.Class, Method: v.Method, Args: rw.exprs(v.Args)}
	case *ir.IndirectCall:
		out = &ir.IndirectCall{Callee: rw.expr(v.Callee), Args: rw.exprs(v.Args)}
	case *ir.NewExpr:
		out = &ir.NewExpr{Type: v.Type, Args: rw.exprs(v.Args)}
	case *ir.NewArrayExpr:
		out = &ir.NewArrayExpr{ElemType: v.ElemType, Size: rw.expr(v.Size)}
	case *ir.ArrayInitExpr:
		out = &ir.ArrayInitExpr{ElemType: v.ElemType, Elems: rw.exprs(v.Elems)}
	case *ir.ArrayAccess:
		out = &ir.ArrayAccess{Array: rw.expr(v.Array), Index: rw.expr(v.Index)}
	default:
		out = e
	}
	rw.exprMemo[e] = out
	return out
}

// fieldAccess rewrites one field access node - see RewriteForIL2CPP's
// own doc comment for the two output shapes.
func (rw *il2cppRewriter) fieldAccess(v *ir.FieldAccess) ir.Expr {
	obj := rw.expr(v.Object)
	if v.FieldName != "" && v.TypeName != "" {
		return &ir.FieldAccess{
			Object: &ir.CastExpr{
				Type: &ir.ClassType{Name: SanitizeCType(v.TypeName) + "*"},
				Expr: obj,
			},
			Name: v.FieldName,
		}
	}
	if v.HasOffset {
		var inner ir.Expr = obj
		if v.Offset != 0 {
			// AddrLit is the IR's hex integer literal (see its doc
			// comment); a decimal displacement like 952 reads as an
			// arbitrary index, while 0x3b8 reads as a byte offset.
			inner = &ir.BinaryExpr{
				Op:    "+",
				Left:  obj,
				Right: &ir.AddrLit{Value: v.Offset},
			}
		}
		return &ir.UnaryExpr{
			Op: "*",
			Expr: &ir.CastExpr{
				Type: &ir.ClassType{Name: il2cppCastType(v.Width) + "*"},
				Expr: inner,
			},
		}
	}
	return &ir.FieldAccess{
		Object:    obj,
		Name:      v.Name,
		Offset:    v.Offset,
		HasOffset: v.HasOffset,
		Width:     v.Width,
		FieldName: v.FieldName,
		TypeName:  v.TypeName,
	}
}
