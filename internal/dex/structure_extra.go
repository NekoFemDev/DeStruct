package dex

import (
	"fmt"
	"regexp"

	"github.com/destruct/destruct/internal/ir"
)

// finallyExceptionUse matches the synthetic catch-all's exception variable
// in rendered statements.
var finallyExceptionUse = regexp.MustCompile(`\be\b`)

// finallyFromHandler recognises the catch-all handler javac emits for a
// finally block: move-exception into a register, the finally body, then a
// rethrow of that same register. Anything that mentions the caught
// exception other than to rethrow it is left as an ordinary catch.
func finallyFromHandler(body *ir.Block) (*ir.Block, bool) {
	if body == nil || len(body.Statements) < 2 {
		return nil, false
	}
	first, ok := body.Statements[0].(*ir.AssignStmt)
	if !ok {
		return nil, false
	}
	exc, ok := first.Value.(*ir.LocalVar)
	if !ok || exc.Name != "e" {
		return nil, false
	}
	target, ok := first.Target.(*ir.LocalVar)
	if !ok {
		return nil, false
	}
	last, ok := body.Statements[len(body.Statements)-1].(*ir.ThrowStmt)
	if !ok {
		return nil, false
	}
	thrown, ok := last.Value.(*ir.LocalVar)
	if !ok || thrown.Name != target.Name {
		return nil, false
	}
	mid := body.Statements[1 : len(body.Statements)-1]
	for _, st := range mid {
		if finallyExceptionUse.MatchString(fmt.Sprint(st)) {
			return nil, false
		}
	}
	return &ir.Block{Statements: append([]ir.Stmt(nil), mid...)}, true
}

// monitorLock reports whether st is a synthetic monitorEnter/monitorExit
// call, returning the lock expression.
func monitorLock(st ir.Stmt, method string) (ir.Expr, bool) {
	es, ok := st.(*ir.ExprStmt)
	if !ok {
		return nil, false
	}
	call, ok := es.Expr.(*ir.MethodCall)
	if !ok || call.Name != method || len(call.Args) != 0 {
		return nil, false
	}
	return call.Object, true
}

// dedupeInlinedFinally removes the normal-path copy of a finally body that
// javac/d8 emit after the protected range. The handler-based reconstruction
// already produced the try/finally; leaving the inlined copy would run the
// cleanup twice.
func dedupeInlinedFinally(b *ir.Block) *ir.Block {
	if b == nil {
		return nil
	}
	for _, st := range b.Statements {
		for _, child := range childBlocks(st) {
			dedupeInlinedFinally(child)
		}
	}
	var out []ir.Stmt
	for i := 0; i < len(b.Statements); {
		st := b.Statements[i]
		if tr, ok := st.(*ir.TryStmt); ok && tr.Finally != nil && len(tr.Catches) == 0 && len(tr.Finally.Statements) > 0 {
			n := len(tr.Finally.Statements)
			if i+1+n <= len(b.Statements) && statementsEqual(b.Statements[i+1:i+1+n], tr.Finally.Statements) {
				out = append(out, tr)
				i += 1 + n
				continue
			}
		}
		out = append(out, st)
		i++
	}
	b.Statements = out
	return b
}

func statementsEqual(a, b []ir.Stmt) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if fmt.Sprint(a[i]) != fmt.Sprint(b[i]) {
			return false
		}
	}
	return true
}

// stripLockGuard removes monitorEnter/monitorExit calls for lock that are
// already implied by an enclosing synchronized block. A synthetic try/finally
// whose only job is the monitor exit collapses to its body.
func stripLockGuard(b *ir.Block, lock ir.Expr) {
	if b == nil {
		return
	}
	var out []ir.Stmt
	for _, st := range b.Statements {
		tr, ok := st.(*ir.TryStmt)
		if !ok {
			out = append(out, st)
			continue
		}
		if tr.Finally != nil {
			var kept []ir.Stmt
			for _, fst := range tr.Finally.Statements {
				if l, ok := monitorLock(fst, "monitorExit"); ok && fmt.Sprint(l) == fmt.Sprint(lock) {
					continue
				}
				kept = append(kept, fst)
			}
			tr.Finally.Statements = kept
			if len(kept) == 0 {
				tr.Finally = nil
			}
		}
		if len(tr.Catches) == 0 && tr.Finally == nil && tr.Body != nil {
			out = append(out, tr.Body.Statements...)
			continue
		}
		out = append(out, tr)
	}
	b.Statements = out
}

// reconstructSynchronized turns a matching monitorEnter/monitorExit pair at
// the same nesting level into a Java synchronized block. Nested blocks are
// processed first. Unpaired monitors are left as calls.
func reconstructSynchronized(b *ir.Block) *ir.Block {
	if b == nil {
		return nil
	}
	for _, st := range b.Statements {
		for _, child := range childBlocks(st) {
			reconstructSynchronized(child)
		}
	}
	var out []ir.Stmt
	for i := 0; i < len(b.Statements); i++ {
		st := b.Statements[i]
		lock, ok := monitorLock(st, "monitorEnter")
		if !ok {
			out = append(out, st)
			continue
		}
		depth := 0
		end := -1
		for j := i + 1; j < len(b.Statements); j++ {
			if _, ok := monitorLock(b.Statements[j], "monitorEnter"); ok {
				depth++
				continue
			}
			exitLock, ok := monitorLock(b.Statements[j], "monitorExit")
			if !ok {
				continue
			}
			if depth > 0 {
				depth--
				continue
			}
			if fmt.Sprint(exitLock) != fmt.Sprint(lock) {
				continue
			}
			end = j
			break
		}
		if end < 0 {
			out = append(out, st)
			continue
		}
		body := &ir.Block{Statements: append([]ir.Stmt(nil), b.Statements[i+1:end]...)}
		stripLockGuard(body, lock)
		out = append(out, &ir.SynchronizedStmt{Lock: lock, Body: body})
		i = end
	}
	b.Statements = out
	for _, st := range b.Statements {
		if sync, ok := st.(*ir.SynchronizedStmt); ok {
			reconstructSynchronized(sync.Body)
		}
	}
	return b
}

// childBlocks returns the statement blocks directly nested in st.
func childBlocks(st ir.Stmt) []*ir.Block {
	switch v := st.(type) {
	case *ir.IfStmt:
		return []*ir.Block{v.Then, v.Else}
	case *ir.WhileStmt:
		return []*ir.Block{v.Body}
	case *ir.DoWhileStmt:
		return []*ir.Block{v.Body}
	case *ir.ForStmt:
		return []*ir.Block{v.Body}
	case *ir.ForEachStmt:
		return []*ir.Block{v.Body}
	case *ir.SwitchStmt:
		var out []*ir.Block
		for _, c := range v.Cases {
			out = append(out, c.Body)
		}
		if v.Default != nil {
			out = append(out, v.Default)
		}
		return out
	case *ir.TryStmt:
		out := []*ir.Block{v.Body, v.Finally}
		for _, c := range v.Catches {
			out = append(out, c.Body)
		}
		return out
	case *ir.BlockStmt:
		return []*ir.Block{v.Block}
	case *ir.SynchronizedStmt:
		return []*ir.Block{v.Body}
	default:
		return nil
	}
}
