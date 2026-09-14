package arm64lift

import (
	"github.com/destruct/destruct/internal/ir"
)

// reconstructTryCatch folds the C++ exception-handling idioms this
// lifter leaves as flat, dead-looking call sequences into real
// TryStmt nodes. In -O0 AArch64 codegen, an exception handler's body
// is reached via the personality routine's landing pads, so by the
// time the structural lifter walks the CFG the handler looks like
// unreachable code sitting after a return:
//
//	return sp.~sentry();          // try body (ends in a terminator)
//	sp.~sentry();
//	.__cxa_begin_catch(x0);        // handler entry
//	x0.__set_badbit_and_consider_rethrow();
//	.__cxa_end_catch();            // handler end
//
// This pass splits each statement list (top-level and every nested
// block) at the first __cxa_begin_catch call: everything before it is
// the protected region, everything between it and the matching
// __cxa_end_catch is the handler, and whatever follows continues
// normally. Both sides keep rendering the same calls they did before -
// only the grouping changes, so the fold is conservative (it never
// invents control flow).
//
// It deliberately does NOT mine .eh_frame/.gcc_except_table for exact
// try ranges: landing-pad tables live outside the instruction stream
// this lifter walks, and a call-marker split is the honest, reviewable
// approximation of what the binary actually says.
func reconstructTryCatch(stmts []ir.Stmt) []ir.Stmt {
	if len(stmts) == 0 {
		return stmts
	}
	for i, s := range stmts {
		stmts[i] = rewriteTryChildren(s)
	}

	begin := -1
	for i, s := range stmts {
		if isBeginCatch(s) {
			begin = i
			break
		}
	}
	if begin <= 0 {
		// No handler, or nothing before it to protect - not a try.
		return stmts
	}
	end := -1
	for i := begin + 1; i < len(stmts); i++ {
		if isEndCatch(stmts[i]) {
			end = i
			break
		}
	}
	if end < 0 {
		// Unmatched begin marker: leave everything alone rather than
		// swallowing an open-ended handler.
		return stmts
	}

	out := make([]ir.Stmt, 0, len(stmts)+1)
	out = append(out, &ir.TryStmt{
		Body: &ir.Block{Statements: stmts[:begin]},
		Catches: []*ir.CatchClause{{
			VarName: "e",
			VarType: &ir.ClassType{Name: "Exception"},
			Body:    &ir.Block{Statements: stmts[begin+1 : end]},
		}},
	})
	out = append(out, reconstructTryCatch(stmts[end+1:])...)
	return out
}

// rewriteTryChildren applies reconstructTryCatch to every nested block
// a statement carries, so handlers inside an if/else arm or a loop
// body fold just like top-level ones.
func rewriteTryChildren(s ir.Stmt) ir.Stmt {
	switch v := s.(type) {
	case *ir.IfStmt:
		if v.Then != nil {
			v.Then.Statements = reconstructTryCatch(v.Then.Statements)
		}
		if v.Else != nil {
			v.Else.Statements = reconstructTryCatch(v.Else.Statements)
		}
	case *ir.WhileStmt:
		if v.Body != nil {
			v.Body.Statements = reconstructTryCatch(v.Body.Statements)
		}
	case *ir.DoWhileStmt:
		if v.Body != nil {
			v.Body.Statements = reconstructTryCatch(v.Body.Statements)
		}
	case *ir.SwitchStmt:
		for _, c := range v.Cases {
			if c.Body != nil {
				c.Body.Statements = reconstructTryCatch(c.Body.Statements)
			}
		}
		if v.Default != nil {
			v.Default.Statements = reconstructTryCatch(v.Default.Statements)
		}
	case *ir.TryStmt:
		if v.Body != nil {
			v.Body.Statements = reconstructTryCatch(v.Body.Statements)
		}
		for _, c := range v.Catches {
			if c.Body != nil {
				c.Body.Statements = reconstructTryCatch(c.Body.Statements)
			}
		}
		if v.Finally != nil {
			v.Finally.Statements = reconstructTryCatch(v.Finally.Statements)
		}
	case *ir.BlockStmt:
		if v.Block != nil {
			v.Block.Statements = reconstructTryCatch(v.Block.Statements)
		}
	}
	return s
}

// isBeginCatch reports whether s is a call to __cxa_begin_catch - the
// Itanium ABI entry point every C++ catch handler invokes first.
func isBeginCatch(s ir.Stmt) bool {
	if es, ok := s.(*ir.ExprStmt); ok {
		return isRuntimeCall(es.Expr, "__cxa_begin_catch")
	}
	return false
}

// isEndCatch reports whether s is a call to __cxa_end_catch - the
// Itanium ABI exit point of a catch handler's own cleanup.
func isEndCatch(s ir.Stmt) bool {
	if es, ok := s.(*ir.ExprStmt); ok {
		return isRuntimeCall(es.Expr, "__cxa_end_catch")
	}
	return false
}

// isRuntimeCall reports whether x is a call (direct or through a
// receiver) to the named C++ runtime function. The receiver-carrying
// form matters because the lifter renders an Itanium instance method
// as "obj.method(...)" (see buildCall) - a landing-pad call sequence
// at -O0 keeps the exception object in a register that reads as the
// receiver.
func isRuntimeCall(x ir.Expr, name string) bool {
	switch c := x.(type) {
	case *ir.StaticMethodCall:
		return methodNameOnly(c.Method) == name
	case *ir.MethodCall:
		return c.Name == name
	}
	return false
}
