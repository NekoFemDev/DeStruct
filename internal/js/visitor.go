package js

import (
	"math"
	"strconv"
	"strings"

	tjs "github.com/tdewolff/parse/v2/js"
)

// transform applies the v1 deobfuscation passes to ast in place.
//
// The rewrite is a depth-first post-order walk: children are rewritten before
// their parent is examined, so folds compose — `!![]` works because `![]`
// folds to `false` before the outer `!` is evaluated. Every helper returns a
// replacement node when it changes something and the original node otherwise;
// callers always assign the result back into the parent.
func transform(ast *tjs.AST) {
	ast.List = transformStmts(ast.List)
}

// transformStmts rewrites a statement list, dropping debugger statements. The
// slice is compacted in place, so the common case allocates nothing.
func transformStmts(list []tjs.IStmt) []tjs.IStmt {
	out := list[:0]
	for _, s := range list {
		// debugger statements carry no semantics for a deobfuscated copy and
		// are removed outright when they sit in a statement list.
		if _, ok := s.(*tjs.DebuggerStmt); ok {
			continue
		}
		out = append(out, transformStmt(s))
	}
	return out
}

// transformStmt rewrites a single statement, returning its replacement when a
// pass changes the node into a different one (IIFE unwrapping, debugger
// removal) and the original node otherwise.
func transformStmt(s tjs.IStmt) tjs.IStmt {
	switch s := s.(type) {
	case *tjs.BlockStmt:
		s.List = transformStmts(s.List)

	case *tjs.ExprStmt:
		s.Value = transformExpr(s.Value)
		if block, ok := unwrapIIFE(s.Value); ok {
			return block
		}

	case *tjs.VarDecl:
		transformBindingElements(s.List)

	case *tjs.IfStmt:
		s.Cond = transformExpr(s.Cond)
		s.Body = transformStmt(s.Body)
		if s.Else != nil {
			s.Else = transformStmt(s.Else)
		}

	case *tjs.DoWhileStmt:
		s.Body = transformStmt(s.Body)
		s.Cond = transformExpr(s.Cond)

	case *tjs.WhileStmt:
		s.Cond = transformExpr(s.Cond)
		s.Body = transformStmt(s.Body)

	case *tjs.ForStmt:
		s.Init = transformExpr(s.Init)
		s.Cond = transformExpr(s.Cond)
		s.Post = transformExpr(s.Post)
		if s.Body != nil {
			s.Body.List = transformStmts(s.Body.List)
		}

	case *tjs.ForInStmt:
		s.Init = transformExpr(s.Init)
		s.Value = transformExpr(s.Value)
		if s.Body != nil {
			s.Body.List = transformStmts(s.Body.List)
		}

	case *tjs.ForOfStmt:
		s.Init = transformExpr(s.Init)
		s.Value = transformExpr(s.Value)
		if s.Body != nil {
			s.Body.List = transformStmts(s.Body.List)
		}

	case *tjs.SwitchStmt:
		s.Init = transformExpr(s.Init)
		for i := range s.List {
			clause := &s.List[i]
			clause.Cond = transformExpr(clause.Cond)
			clause.List = transformStmts(clause.List)
		}

	case *tjs.ReturnStmt:
		s.Value = transformExpr(s.Value)

	case *tjs.WithStmt:
		s.Cond = transformExpr(s.Cond)
		s.Body = transformStmt(s.Body)

	case *tjs.LabelledStmt:
		s.Value = transformStmt(s.Value)

	case *tjs.ThrowStmt:
		s.Value = transformExpr(s.Value)

	case *tjs.TryStmt:
		if s.Body != nil {
			s.Body.List = transformStmts(s.Body.List)
		}
		s.Binding = transformBinding(s.Binding)
		if s.Catch != nil {
			s.Catch.List = transformStmts(s.Catch.List)
		}
		if s.Finally != nil {
			s.Finally.List = transformStmts(s.Finally.List)
		}

	case *tjs.ExportStmt:
		s.Decl = transformExpr(s.Decl)

	case *tjs.FuncDecl:
		transformFunc(s)

	case *tjs.ClassDecl:
		transformClass(s)

	case *tjs.DebuggerStmt:
		// Reached only when a debugger is not part of a statement list (it is
		// the sole body of an if/loop). The slot must stay filled, so it
		// collapses to an empty statement instead of disappearing.
		return &tjs.EmptyStmt{}
	}

	return s
}

// transformExpr rewrites an expression subtree and returns its replacement,
// which is the original node unless a fold changed it.
func transformExpr(e tjs.IExpr) tjs.IExpr {
	if e == nil {
		return nil
	}

	switch e := e.(type) {
	case *tjs.UnaryExpr:
		e.X = transformExpr(e.X)
		if folded, ok := foldUnary(e); ok {
			return folded
		}

	case *tjs.BinaryExpr:
		e.X = transformExpr(e.X)
		e.Y = transformExpr(e.Y)
		if folded, ok := foldBinary(e); ok {
			return folded
		}

	case *tjs.CallExpr:
		e.X = transformExpr(e.X)
		transformArgs(&e.Args)

	case *tjs.NewExpr:
		e.X = transformExpr(e.X)
		if e.Args != nil {
			transformArgs(e.Args)
		}

	case *tjs.DotExpr:
		e.X = transformExpr(e.X)
		e.Y = transformExpr(e.Y)

	case *tjs.IndexExpr:
		e.X = transformExpr(e.X)
		e.Y = transformExpr(e.Y)

	case *tjs.GroupExpr:
		e.X = transformExpr(e.X)

	case *tjs.CondExpr:
		e.Cond = transformExpr(e.Cond)
		e.X = transformExpr(e.X)
		e.Y = transformExpr(e.Y)

	case *tjs.CommaExpr:
		for i := range e.List {
			e.List[i] = transformExpr(e.List[i])
		}

	case *tjs.ArrayExpr:
		for i := range e.List {
			e.List[i].Value = transformExpr(e.List[i].Value)
		}

	case *tjs.ObjectExpr:
		for i := range e.List {
			prop := &e.List[i]
			if prop.Name != nil {
				prop.Name.Computed = transformExpr(prop.Name.Computed)
			}
			prop.Value = transformExpr(prop.Value)
			prop.Init = transformExpr(prop.Init)
		}

	case *tjs.TemplateExpr:
		e.Tag = transformExpr(e.Tag)
		for i := range e.List {
			e.List[i].Expr = transformExpr(e.List[i].Expr)
		}

	case *tjs.YieldExpr:
		e.X = transformExpr(e.X)

	case *tjs.ArrowFunc:
		transformParams(&e.Params)
		e.Body.List = transformStmts(e.Body.List)

	case *tjs.FuncDecl:
		transformFunc(e)

	case *tjs.MethodDecl:
		transformMethod(e)

	case *tjs.VarDecl:
		// Not a real expression: appears in for-initialisers and export
		// declarations.
		transformBindingElements(e.List)

	case *tjs.ClassDecl:
		transformClass(e)
	}

	return e
}

// transformBinding walks a binding pattern, rewriting default values and
// computed keys in object patterns.
func transformBinding(b tjs.IBinding) tjs.IBinding {
	switch b := b.(type) {
	case *tjs.BindingArray:
		transformBindingElements(b.List)
		b.Rest = transformBinding(b.Rest)

	case *tjs.BindingObject:
		for i := range b.List {
			item := &b.List[i]
			if item.Key != nil {
				item.Key.Computed = transformExpr(item.Key.Computed)
			}
			transformBindingElement(&item.Value)
		}
	}

	return b
}

func transformBindingElements(list []tjs.BindingElement) {
	for i := range list {
		transformBindingElement(&list[i])
	}
}

func transformBindingElement(be *tjs.BindingElement) {
	be.Binding = transformBinding(be.Binding)
	be.Default = transformExpr(be.Default)
}

func transformParams(p *tjs.Params) {
	transformBindingElements(p.List)
	p.Rest = transformBinding(p.Rest)
}

func transformFunc(fn *tjs.FuncDecl) {
	transformParams(&fn.Params)
	fn.Body.List = transformStmts(fn.Body.List)
}

func transformMethod(m *tjs.MethodDecl) {
	transformParams(&m.Params)
	m.Body.List = transformStmts(m.Body.List)
}

func transformClass(c *tjs.ClassDecl) {
	c.Extends = transformExpr(c.Extends)
	for i := range c.List {
		el := &c.List[i]
		switch {
		case el.StaticBlock != nil:
			el.StaticBlock.List = transformStmts(el.StaticBlock.List)
		case el.Method != nil:
			transformMethod(el.Method)
		default:
			el.Init = transformExpr(el.Init)
		}
	}
}

func transformArgs(args *tjs.Args) {
	for i := range args.List {
		args.List[i].Value = transformExpr(args.List[i].Value)
	}
}

// foldUnary applies unary constant folding to e and reports whether it was
// replaced:
//
//	!x      -> true/false literal, when x's truthiness is statically known
//	void 0  -> undefined
func foldUnary(e *tjs.UnaryExpr) (tjs.IExpr, bool) {
	switch e.Op {
	case tjs.NotToken:
		if truthy, ok := staticTruthiness(e.X); ok {
			return boolLiteral(!truthy), true
		}
	case tjs.VoidToken:
		// `void <numeric zero>` evaluates with no side effects and always
		// yields undefined; v1 rewrites the canonical void 0 form and its
		// numeric spellings (void 0x0, void -0, ...).
		if v, ok := literalNumber(e.X); ok && v == 0 {
			return undefinedVar(), true
		}
	}
	return e, false
}

// foldBinary folds arithmetic between two numeric literals (`1+2` -> `3`).
// Results that are NaN or infinite are left alone: representing them would
// require Infinity/NaN references rather than literals, which is beyond v1.
func foldBinary(e *tjs.BinaryExpr) (tjs.IExpr, bool) {
	x, ok := literalNumber(e.X)
	if !ok {
		return e, false
	}
	y, ok := literalNumber(e.Y)
	if !ok {
		return e, false
	}

	var v float64
	switch e.Op {
	case tjs.AddToken:
		v = x + y
	case tjs.SubToken:
		v = x - y
	case tjs.MulToken:
		v = x * y
	case tjs.DivToken:
		v = x / y
	case tjs.ModToken:
		v = math.Mod(x, y)
	case tjs.ExpToken:
		v = math.Pow(x, y)
	default:
		return e, false
	}

	if lit, ok := numberLiteral(v); ok {
		return lit, true
	}
	return e, false
}

// staticTruthiness reports whether e's boolean value is statically known.
//
// Only side-effect-free expressions are considered, because folding a `!`
// removes the operand along with everything it would have evaluated: anything
// that could call code or trigger a getter must be left for the runtime.
func staticTruthiness(e tjs.IExpr) (bool, bool) {
	switch e := e.(type) {
	case *tjs.LiteralExpr:
		return literalTruthiness(e)

	case *tjs.Var:
		switch string(e.Data) {
		case "undefined", "NaN":
			return false, true
		}

	case *tjs.ArrayExpr:
		// Arrays are always truthy. Only the empty literal is guaranteed
		// side-effect free; a non-empty one may contain calls.
		if len(e.List) == 0 {
			return true, true
		}

	case *tjs.ObjectExpr:
		if len(e.List) == 0 {
			return true, true
		}

	case *tjs.FuncDecl, *tjs.ArrowFunc:
		// Creating a function value never has side effects; the body only
		// runs when called.
		return true, true

	case *tjs.UnaryExpr:
		// Parser and folds represent signed numbers as unary +/- over a
		// literal.
		if e.Op == tjs.NegToken || e.Op == tjs.PosToken {
			if v, ok := literalNumber(e); ok && !math.IsNaN(v) {
				return v != 0, true
			}
		}

	case *tjs.GroupExpr:
		return staticTruthiness(e.X)
	}
	return false, false
}

func literalTruthiness(lit *tjs.LiteralExpr) (bool, bool) {
	switch lit.TokenType {
	case tjs.TrueToken, tjs.ThisToken, tjs.RegExpToken:
		return true, true
	case tjs.FalseToken, tjs.NullToken:
		return false, true
	case tjs.StringToken:
		// Only the empty string is falsy; the literal data includes quotes.
		return len(lit.Data) > 2, true
	}
	if v, ok := parseNumericLiteral(lit); ok {
		return v != 0 && !math.IsNaN(v), true
	}
	return false, false
}

// literalNumber returns the numeric value of e when e is a numeric literal
// (integer, decimal, hex, binary, or octal) or a sign applied to one. BigInt
// literals and everything non-numeric report ok=false.
func literalNumber(e tjs.IExpr) (float64, bool) {
	switch e := e.(type) {
	case *tjs.LiteralExpr:
		return parseNumericLiteral(e)
	case *tjs.UnaryExpr:
		v, ok := literalNumber(e.X)
		if !ok {
			return 0, false
		}
		switch e.Op {
		case tjs.NegToken:
			return -v, true
		case tjs.PosToken:
			return v, true
		}
	}
	return 0, false
}

func parseNumericLiteral(lit *tjs.LiteralExpr) (float64, bool) {
	if !tjs.IsNumeric(lit.TokenType) {
		return 0, false
	}
	data := string(lit.Data)
	// BigInt literals carry an 'n' suffix; strconv would reject them anyway,
	// but be explicit — BigInt arithmetic is not folded in v1.
	if len(data) == 0 || data[len(data)-1] == 'n' {
		return 0, false
	}
	// Numeric separators (1_000) are valid JS but not parseable by strconv.
	data = strings.ReplaceAll(data, "_", "")

	switch lit.TokenType {
	case tjs.IntegerToken, tjs.DecimalToken:
		v, err := strconv.ParseFloat(data, 64)
		return v, err == nil
	case tjs.HexadecimalToken, tjs.BinaryToken, tjs.OctalToken:
		if len(data) < 2 {
			return 0, false
		}
		base := 16
		if lit.TokenType == tjs.BinaryToken {
			base = 2
		} else if lit.TokenType == tjs.OctalToken {
			base = 8
		}
		v, err := strconv.ParseUint(data[2:], base, 64)
		return float64(v), err == nil
	}
	return 0, false
}

// boolLiteral builds a true/false literal matching the parser's
// representation (token type plus raw data).
func boolLiteral(b bool) *tjs.LiteralExpr {
	if b {
		return &tjs.LiteralExpr{TokenType: tjs.TrueToken, Data: []byte("true")}
	}
	return &tjs.LiteralExpr{TokenType: tjs.FalseToken, Data: []byte("false")}
}

// undefinedVar returns a reference to the global `undefined`.
func undefinedVar() *tjs.Var {
	return &tjs.Var{Data: []byte("undefined")}
}

// numberLiteral builds a literal for a folded numeric result. Integer results
// use IntegerToken to mirror the lexer's classification; negative results
// become a unary minus over a positive literal, which is how the parser
// represents negative numbers in the first place.
func numberLiteral(v float64) (tjs.IExpr, bool) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, false
	}

	negative := math.Signbit(v)
	a := math.Abs(v)

	var text string
	if a == math.Trunc(a) && a < 1e21 {
		text = strconv.FormatFloat(a, 'f', 0, 64)
	} else {
		text = strconv.FormatFloat(a, 'g', -1, 64)
	}

	tt := tjs.IntegerToken
	if strings.ContainsAny(text, ".eE") {
		tt = tjs.DecimalToken
	}

	lit := &tjs.LiteralExpr{TokenType: tt, Data: []byte(text)}
	if negative {
		return &tjs.UnaryExpr{Op: tjs.NegToken, X: lit}, true
	}
	return lit, true
}

// unwrapIIFE recognises the `!function(){...}()` wrapper obfuscators use to run
// a block of code in function scope, and replaces it with the function body as
// a plain block statement.
func unwrapIIFE(e tjs.IExpr) (*tjs.BlockStmt, bool) {
	unary, ok := e.(*tjs.UnaryExpr)
	if !ok || unary.Op != tjs.NotToken {
		return nil, false
	}
	call, ok := unary.X.(*tjs.CallExpr)
	if !ok || len(call.Args.List) != 0 {
		return nil, false
	}
	fn, ok := iifeCallee(call.X)
	if !ok || !iifeSafeToUnwrap(fn) {
		return nil, false
	}
	return &fn.Body, true
}

// iifeCallee peels the optional parenthesised form: both `!function(){}()` and
// `!(function(){})()` parse to the same call shape.
func iifeCallee(e tjs.IExpr) (*tjs.FuncDecl, bool) {
	if group, ok := e.(*tjs.GroupExpr); ok {
		e = group.X
	}
	fn, ok := e.(*tjs.FuncDecl)
	return fn, ok
}

// iifeSafeToUnwrap reports whether hoisting fn's body into the enclosing block
// preserves the program's meaning. The rewrite is declined when:
//
//   - the function is async or a generator — its await/yield semantics depend
//     on the function wrapper;
//   - the call passes arguments or the function declares parameters — the
//     body would start resolving those names in the enclosing scope;
//   - the function expression is named — the name enables self-reference;
//   - the body contains a return, or references this / arguments /
//     new.target — all of which resolve against the function frame being
//     removed.
//
// Known v1 limitation: `var` declarations inside the IIFE leak to the
// enclosing scope after unwrapping. Obfuscator wrappers rarely depend on the
// difference, and collision analysis against the enclosing scope is future
// work.
func iifeSafeToUnwrap(fn *tjs.FuncDecl) bool {
	if fn.Async || fn.Generator || fn.Name != nil {
		return false
	}
	if len(fn.Params.List) != 0 || fn.Params.Rest != nil {
		return false
	}
	f := &frameUsageFinder{}
	tjs.Walk(f, &fn.Body)
	return !f.usesFrame
}

// frameUsageFinder flags constructs that only make sense inside the function
// frame an IIFE unwrap would remove.
type frameUsageFinder struct {
	usesFrame bool
}

func (f *frameUsageFinder) Enter(n tjs.INode) tjs.IVisitor {
	if f.usesFrame {
		return nil
	}
	switch n := n.(type) {
	case *tjs.ReturnStmt, *tjs.NewTargetExpr:
		f.usesFrame = true
		return nil
	case *tjs.LiteralExpr:
		if n.TokenType == tjs.ThisToken {
			f.usesFrame = true
		}
		return nil
	case *tjs.Var:
		if string(n.Data) == "arguments" {
			f.usesFrame = true
		}
		return nil
	case *tjs.FuncDecl, *tjs.MethodDecl, *tjs.ClassDecl:
		// Nested full function frames own their returns/this/arguments; only
		// the IIFE's own frame matters here. Arrow functions are deliberately
		// not in this list: they inherit `this` and `arguments` from the IIFE
		// frame, so their bodies must still be scanned. A `return` inside an
		// arrow is a false positive we accept to stay conservative.
		return nil
	}
	return f
}

func (f *frameUsageFinder) Exit(tjs.INode) {}
