package jvm

import (
	"strings"

	"github.com/destruct/destruct/internal/ir"
)

// postprocessClass applies IR-level clean-ups to a decompiled class that
// improve readability but are hard or impossible to get right during the
// initial bytecode-to-IR translation.
func postprocessClass(class *ir.Class) {
	for _, method := range class.Methods {
		if method.Body == nil {
			continue
		}
		method.Body = postprocessBlock(method.Body)
	}
}

func postprocessBlock(block *ir.Block) *ir.Block {
	if block == nil {
		return block
	}
	var filtered []ir.Stmt
	for _, stmt := range block.Statements {
		// Skip synthetic lambda body markers - these methods are
		// inlined at their call sites and the marker is just noise.
		if isLambdaBodyMarker(stmt) {
			continue
		}
		filtered = append(filtered, postprocessStmt(stmt))
	}
	// Remove trailing void return statements - they're implicit in Java.
	filtered = trimTrailingVoidReturn(filtered)
	block.Statements = filtered
	return block
}

// isLambdaBodyMarker checks if a statement is the DESTRUCT synthetic
// marker that gets prepended to lambda$ methods.
func isLambdaBodyMarker(stmt ir.Stmt) bool {
	if es, ok := stmt.(*ir.ExprStmt); ok {
		if sl, ok := es.Expr.(*ir.StringLit); ok {
			return strings.HasPrefix(sl.Value, "DESTRUCT:")
		}
	}
	return false
}

// trimTrailingVoidReturn removes a trailing "return;" from a statement list
// when it's the last statement and the surrounding context is a void method.
func trimTrailingVoidReturn(stmts []ir.Stmt) []ir.Stmt {
	if len(stmts) == 0 {
		return stmts
	}
	if _, ok := stmts[len(stmts)-1].(*ir.ReturnStmt); ok {
		last := stmts[len(stmts)-1].(*ir.ReturnStmt)
		if last.Value == nil {
			return stmts[:len(stmts)-1]
		}
	}
	return stmts
}

func postprocessStmt(stmt ir.Stmt) ir.Stmt {
	switch v := stmt.(type) {
	case *ir.ExprStmt:
		v.Expr = postprocessExpr(v.Expr)
		return v
	case *ir.ReturnStmt:
		if v.Value != nil {
			v.Value = postprocessExpr(v.Value)
		}
		return v
	case *ir.AssignStmt:
		v.Value = postprocessExpr(v.Value)
		return v
	case *ir.VarDeclStmt:
		if v.Init != nil {
			v.Init = postprocessExpr(v.Init)
		}
		return v
	case *ir.IfStmt:
		v.Cond = postprocessExpr(v.Cond)
		if v.Then != nil {
			v.Then = postprocessBlock(v.Then)
		}
		if v.Else != nil {
			v.Else = postprocessBlock(v.Else)
		}
		return v
	case *ir.WhileStmt:
		v.Cond = postprocessExpr(v.Cond)
		if v.Body != nil {
			v.Body = postprocessBlock(v.Body)
		}
		return v
	case *ir.ForEachStmt:
		v.Expr = postprocessExpr(v.Expr)
		if v.Body != nil {
			v.Body = postprocessBlock(v.Body)
		}
		return v
	case *ir.SwitchStmt:
		v.Target = postprocessExpr(v.Target)
		for _, c := range v.Cases {
			if c.Body != nil {
				c.Body = postprocessBlock(c.Body)
			}
		}
		if v.Default != nil {
			v.Default = postprocessBlock(v.Default)
		}
		return v
	case *ir.TryStmt:
		if v.Body != nil {
			v.Body = postprocessBlock(v.Body)
		}
		for _, c := range v.Catches {
			if c.Body != nil {
				c.Body = postprocessBlock(c.Body)
			}
		}
		return v
	}
	return stmt
}

func postprocessExpr(expr ir.Expr) ir.Expr {
	if expr == nil {
		return expr
	}

	// First, flatten StringBuilder chains at this level (before recursing,
	// because flattening needs to see the full chain top-down)
	expr = flattenStringBuilderChain(expr)

	// Simplify + chains: collapse adjacent string literals, drop ""
	if be, ok := expr.(*ir.BinaryExpr); ok && be.Op == "+" {
		expr = simplifyConcatChain(be)
	}

	// Simplify float comparison: (x dcmpl y) == 0 → x == y, etc.
	if be, ok := expr.(*ir.BinaryExpr); ok {
		if intLit, ok := be.Right.(*ir.IntLit); ok && intLit.Value == 0 {
			if inner, ok := be.Left.(*ir.BinaryExpr); ok {
				switch inner.Op {
				case "dcmpl", "dcmpg", "fcmpl", "fcmpg":
					return &ir.BinaryExpr{Op: "==", Left: inner.Left, Right: inner.Right}
				}
			}
		}
		// (x dcmpl y) > 0 → x > y, (x dcmpl y) < 0 → x < y
		if inner, ok := be.Left.(*ir.BinaryExpr); ok {
			switch inner.Op {
			case "dcmpl", "fcmpl":
				switch be.Op {
				case ">":
					return &ir.BinaryExpr{Op: ">", Left: inner.Left, Right: inner.Right}
				case "<":
					return &ir.BinaryExpr{Op: "<", Left: inner.Left, Right: inner.Right}
				case ">=":
					return &ir.BinaryExpr{Op: ">=", Left: inner.Left, Right: inner.Right}
				case "<=":
					return &ir.BinaryExpr{Op: "<=", Left: inner.Left, Right: inner.Right}
				}
			case "dcmpg", "fcmpg":
				switch be.Op {
				case ">":
					return &ir.BinaryExpr{Op: ">", Left: inner.Left, Right: inner.Right}
				case "<":
					return &ir.BinaryExpr{Op: "<", Left: inner.Left, Right: inner.Right}
				}
			}
		}
	}

	// Simplify boolean negation: method() == 0 → !method()
	if be, ok := expr.(*ir.BinaryExpr); ok && be.Op == "==" {
		if intLit, ok := be.Right.(*ir.IntLit); ok && intLit.Value == 0 {
			if isMethodCallExpr(be.Left) {
				return &ir.UnaryExpr{Op: "!", Expr: be.Left}
			}
			// (x instanceof Y) == 0 → !(x instanceof Y)
			if bin, ok := be.Left.(*ir.BinaryExpr); ok && bin.Op == "instanceof" {
				return &ir.UnaryExpr{Op: "!", Expr: bin}
			}
		}
	}

	// Then, recurse into child expressions
	switch v := expr.(type) {
	case *ir.MethodCall:
		if v.Object != nil {
			v.Object = postprocessExpr(v.Object)
		}
		for i, a := range v.Args {
			v.Args[i] = postprocessExpr(a)
		}
	case *ir.StaticMethodCall:
		for i, a := range v.Args {
			v.Args[i] = postprocessExpr(a)
		}
	case *ir.BinaryExpr:
		v.Left = postprocessExpr(v.Left)
		v.Right = postprocessExpr(v.Right)
	case *ir.UnaryExpr:
		v.Expr = postprocessExpr(v.Expr)
	case *ir.CastExpr:
		v.Expr = postprocessExpr(v.Expr)
	case *ir.NewExpr:
		for i, a := range v.Args {
			v.Args[i] = postprocessExpr(a)
		}
	case *ir.FieldAccess:
		if v.Object != nil {
			v.Object = postprocessExpr(v.Object)
		}
	case *ir.TernaryExpr:
		v.Cond = postprocessExpr(v.Cond)
		v.TrueExpr = postprocessExpr(v.TrueExpr)
		v.FalseExpr = postprocessExpr(v.FalseExpr)
	case *ir.ArrayAccess:
		v.Array = postprocessExpr(v.Array)
		v.Index = postprocessExpr(v.Index)
	case *ir.LambdaExpr:
		if v.Body != nil {
			v.Body = postprocessBlock(v.Body)
		}
	}

	return expr
}

// flattenStringBuilderChain detects the pattern:
//
//	new StringBuilder().append(x).append(y).toString()
//	new StringBuilder().append(x).append(y)
//	new StringBuilder(arg).append(x).toString()
//
// and replaces it with:
//
//	arg + x + y
//	x + y  (when no constructor arg, first append is the start)
//	arg + x
//
// This walks the chain top-down: if the outermost call is .toString(),
// strip it. Then for each .append(x), accumulate the concatenation.
func flattenStringBuilderChain(expr ir.Expr) ir.Expr {
	// .toString() on a StringBuilder chain → strip and process inner
	if mc, ok := expr.(*ir.MethodCall); ok {
		if mc.Name == "toString" && len(mc.Args) == 0 && isStringBuilderExpr(mc.Object) {
			return flattenStringBuilderChain(mc.Object)
		}
		// .append(x) on a StringBuilder chain → accumulate
		if mc.Name == "append" && len(mc.Args) == 1 && isStringBuilderExpr(mc.Object) {
			inner := mc.Object
			arg := mc.Args[0]
			accum := collectSBParts(inner)
			return &ir.BinaryExpr{Op: "+", Left: accum, Right: arg}
		}
	}
	return expr
}

// collectSBParts walks a StringBuilder chain bottom-up and collects all the
// parts that should be concatenated together. It returns a left-folded
// BinaryExpr tree.
//
//	new StringBuilder("hello") → StringLit{"hello"}
//	new StringBuilder()        → StringLit{""}
//	<prev>.append(x)           → collectSBParts(prev) + x
func collectSBParts(expr ir.Expr) ir.Expr {
	if mc, ok := expr.(*ir.MethodCall); ok {
		if mc.Name == "append" && len(mc.Args) == 1 {
			left := collectSBParts(mc.Object)
			return &ir.BinaryExpr{Op: "+", Left: left, Right: mc.Args[0]}
		}
	}
	if ne, ok := expr.(*ir.NewExpr); ok && isStringBuilderType(ne.Type) {
		if len(ne.Args) == 0 {
			return &ir.StringLit{Value: ""}
		}
		if len(ne.Args) == 1 {
			return ne.Args[0]
		}
	}
	return expr
}

// isStringBuilderType checks if a type name refers to StringBuilder.
func isStringBuilderType(name string) bool {
	return name == "java.lang.StringBuilder" || name == "StringBuilder" ||
		name == "java/lang/StringBuilder" || name == "StringBuffer" ||
		name == "java.lang.StringBuffer" || name == "java/lang/StringBuffer"
}

// isStringBuilderExpr checks if an expression is a StringBuilder construction
// (new StringBuilder(...)) or a chained append on one.
func isStringBuilderExpr(expr ir.Expr) bool {
	if ne, ok := expr.(*ir.NewExpr); ok {
		return isStringBuilderType(ne.Type)
	}
	if mc, ok := expr.(*ir.MethodCall); ok {
		if (mc.Name == "append" || mc.Name == "toString") && len(mc.Args) <= 1 {
			return isStringBuilderExpr(mc.Object)
		}
	}
	return false
}

// isMethodCallExpr checks if an expression is a method call (instance or static).
func isMethodCallExpr(expr ir.Expr) bool {
	switch expr.(type) {
	case *ir.MethodCall, *ir.StaticMethodCall:
		return true
	}
	return false
}

// simplifyConcatChain flattens nested + chains and merges adjacent string
// literals, e.g. "" + "hello " + name → "hello " + name.
func simplifyConcatChain(expr *ir.BinaryExpr) ir.Expr {
	var parts []ir.Expr
	flattenPlus(expr, &parts)

	// Merge adjacent string literals
	var merged []ir.Expr
	for _, p := range parts {
		if sl, ok := p.(*ir.StringLit); ok {
			if len(merged) > 0 {
				if prev, ok := merged[len(merged)-1].(*ir.StringLit); ok {
					merged[len(merged)-1] = &ir.StringLit{Value: prev.Value + sl.Value}
					continue
				}
			}
		}
		merged = append(merged, p)
	}

	// Drop empty string parts (unless it's the only part)
	var filtered []ir.Expr
	for _, p := range merged {
		if sl, ok := p.(*ir.StringLit); ok && sl.Value == "" {
			continue
		}
		filtered = append(filtered, p)
	}
	if len(filtered) == 0 {
		return &ir.StringLit{Value: ""}
	}
	if len(filtered) == 1 {
		return filtered[0]
	}

	result := filtered[0]
	for i := 1; i < len(filtered); i++ {
		result = &ir.BinaryExpr{Op: "+", Left: result, Right: filtered[i]}
	}
	return result
}

func flattenPlus(expr ir.Expr, parts *[]ir.Expr) {
	if be, ok := expr.(*ir.BinaryExpr); ok && be.Op == "+" {
		flattenPlus(be.Left, parts)
		flattenPlus(be.Right, parts)
		return
	}
	*parts = append(*parts, expr)
}
