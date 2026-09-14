package arm64lift

import (
	"fmt"

	"github.com/destruct/destruct/internal/ir"
)

// tryStringDispatch recognizes the compiled shape of an if/else-if
// chain that dispatches on a string - a run of
//
//	if (strcmp(x, "dump-lib") == 0) { ... }
//	else if (strcmp(x, "dump-meta") == 0) { ... }
//	...
//	else { ... }
//
// (and the mirror-image orientation where the chain continues in the
// branch-taken arm: "if (strcmp(x, \"a\") != 0) ... else ...") - and
// folds it into one compact switch-style dispatch:
//
//	switch (x) {
//	    case "dump-lib": ...
//	    case "dump-meta": ...
//	    default: ...
//	}
//
// This is exactly what a parse_args-style command dispatcher looks like
// after lifting, and folding it is the difference between dozens of
// nested two-arm ifs and the handful of lines the original source
// actually had.
//
// Conservation rules: every link must test the SAME expression against
// a string literal through a strcmp-family call, all orientations must
// agree, and there must be at least two links - anything less falls
// back to the ordinary if/else rendering, never a wrong guess.
func tryStringDispatch(ifs *ir.IfStmt) (*ir.SwitchStmt, bool) {
	if ifs == nil {
		return nil, false
	}

	type entry struct {
		value string
		body  *ir.Block
	}

	var entries []entry
	var target string
	orientation := -1 // 0: then=body (== 0), 1: else=body (!= 0)
	cur := ifs
	var defaultBlock *ir.Block

	for {
		call, value, mode, ok := matchStrcmpLink(cur)
		if !ok {
			// A link that isn't a strcmp test (a plain trailing
			// condition, or the chain's final else) is the default arm:
			// keep it - and everything nested under it - whole, rather
			// than dropping it from the folded dispatch.
			defaultBlock = &ir.Block{Statements: []ir.Stmt{cur}}
			break
		}
		rendered := fmt.Sprint(call.Args[0])
		if target == "" {
			target = rendered
		} else if rendered != target {
			return nil, false
		}
		if orientation == -1 {
			orientation = mode
		} else if orientation != mode {
			return nil, false
		}

		var body, next *ir.Block
		if mode == 0 {
			body, next = cur.Then, cur.Else
		} else {
			body, next = cur.Else, cur.Then
		}
		entries = append(entries, entry{value: value, body: body})

		if next == nil || len(next.Statements) != 1 {
			defaultBlock = next
			break
		}
		inner, ok := next.Statements[0].(*ir.IfStmt)
		if !ok {
			defaultBlock = next
			break
		}
		cur = inner
	}

	if len(entries) < 2 {
		return nil, false
	}

	sw := &ir.SwitchStmt{Target: firstArg(ifs)}
	for _, e := range entries {
		body := e.body
		if body == nil {
			body = &ir.Block{}
		}
		sw.Cases = append(sw.Cases, &ir.CaseClause{
			Values: []ir.Expr{&ir.StringLit{Value: e.value}},
			Body:   &ir.Block{Statements: body.Statements},
		})
	}
	sw.Default = defaultBlock
	return sw, true
}

// firstArg extracts the tested expression from the chain's head (the
// strcmp call's first argument), since it isn't carried through the
// walk above.
func firstArg(ifs *ir.IfStmt) ir.Expr {
	if call, _, _, ok := matchStrcmpLink(ifs); ok && len(call.Args) > 0 {
		return call.Args[0]
	}
	return &ir.LocalVar{Name: "cmd"}
}

// matchStrcmpLink reports whether s is one link of a strcmp dispatch:
// a comparison of strcmp(x, "literal") against zero, in either the
// "== 0" (mode 0: the THEN arm is the case body) or "!= 0" (mode 1:
// the ELSE arm is the case body) orientation.
func matchStrcmpLink(s *ir.IfStmt) (call *ir.StaticMethodCall, value string, mode int, ok bool) {
	if s == nil || s.Cond == nil {
		return nil, "", 0, false
	}
	// "!strcmp(...)" is the cbz-lifted spelling of "== 0".
	if un, isUnary := s.Cond.(*ir.UnaryExpr); isUnary && un.Op == "!" {
		if c, isCall := un.Expr.(*ir.StaticMethodCall); isCall && isStrcmpCall(c) {
			return c, stringArg(c), 0, stringArg(c) != ""
		}
		return nil, "", 0, false
	}
	cmp, isBinary := s.Cond.(*ir.BinaryExpr)
	if !isBinary {
		return nil, "", 0, false
	}
	switch cmp.Op {
	case "==":
		mode = 0
	case "!=":
		mode = 1
	default:
		return nil, "", 0, false
	}
	call, ok = cmp.Left.(*ir.StaticMethodCall)
	if !ok || !isStrcmpCall(call) {
		return nil, "", 0, false
	}
	if zero, ok := cmp.Right.(*ir.IntLit); !ok || zero.Value != 0 {
		// Accept only a comparison against literal zero; "== 1" etc. is
		// not a dispatch on the string's content.
		return nil, "", 0, false
	}
	v := stringArg(call)
	if v == "" {
		return nil, "", 0, false
	}
	return call, v, mode, true
}

// isStrcmpCall reports whether call is a strcmp-family comparison with
// exactly two arguments (the usual "strcmp(s, literal)" shape).
func isStrcmpCall(call *ir.StaticMethodCall) bool {
	if call == nil || len(call.Args) != 2 {
		return false
	}
	switch call.Method {
	case "strcmp", "strncmp", "strcasecmp", "strncasecmp":
		return true
	}
	return false
}

// stringArg returns call's second argument when it's a string literal.
func stringArg(call *ir.StaticMethodCall) string {
	if len(call.Args) != 2 {
		return ""
	}
	if lit, ok := call.Args[1].(*ir.StringLit); ok {
		return lit.Value
	}
	return ""
}
