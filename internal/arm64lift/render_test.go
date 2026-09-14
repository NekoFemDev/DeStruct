package arm64lift

import (
	"bytes"
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/ir"
)

// TestRenderStmts_HoistsSharedSubexpressions covers a real pathological
// input: the lifter stores register values as a shared expression DAG,
// so a chain of instructions that feed a value back into itself (the
// classic "add x, x, x" doubling sequence, common in obfuscated/packed
// code) produces an IR tree whose naive String() rendering is
// exponential in the number of instructions. A real packed ARM64
// binary hit this and generated a single 12.9 MB source line from a
// 2 KB function, effectively hanging the decompiler. RenderStmts must
// instead give each shared node a temporary so the output stays linear.
func TestRenderStmts_HoistsSharedSubexpressions(t *testing.T) {
	shared := &ir.BinaryExpr{
		Op:    "+",
		Left:  &ir.LocalVar{Name: "a"},
		Right: &ir.LocalVar{Name: "b"},
	}
	// x = shared & (shared | shared) - shared referenced three times, so
	// expanding it once per reference is what used to blow up; repeated
	// doubling compounds the problem.
	value := &ir.BinaryExpr{Op: "&", Left: shared, Right: shared}
	for i := 0; i < 30; i++ {
		value = &ir.BinaryExpr{Op: "+", Left: value, Right: value}
	}
	stmt := &ir.AssignStmt{Target: &ir.LocalVar{Name: "x"}, Value: value}

	var buf bytes.Buffer
	RenderStmts(&buf, []ir.Stmt{stmt}, 0)
	out := buf.String()

	// Without hoisting this renders 2^30 copies of shared and never
	// finishes in practice; with it, a few temp lines and one
	// bounded-size statement.
	if len(out) > 4096 {
		t.Fatalf("rendered output unexpectedly large (%d bytes) - shared subexpressions were not hoisted", len(out))
	}
	if !strings.Contains(out, "tmp0") {
		t.Fatalf("expected a synthetic tmp0 assignment, got:\n%s", out)
	}
	if strings.Count(out, "a + b") != 1 {
		t.Fatalf("expected the shared expression to be materialized exactly once, got:\n%s", out)
	}
}

// TestRenderStmts_NoHoistForPlainTrees verifies the fast path: a
// statement whose expressions are ordinary, non-shared trees renders
// exactly as before - no spurious temporaries.
func TestRenderStmts_NoHoistForPlainTrees(t *testing.T) {
	stmt := &ir.AssignStmt{
		Target: &ir.LocalVar{Name: "x"},
		Value: &ir.BinaryExpr{
			Op:    "+",
			Left:  &ir.LocalVar{Name: "a"},
			Right: &ir.IntLit{Value: 1},
		},
	}
	var buf bytes.Buffer
	RenderStmts(&buf, []ir.Stmt{stmt}, 0)
	if got := strings.TrimSpace(buf.String()); got != "x = a + 1;" {
		t.Fatalf("expected plain rendering %q, got %q", "x = a + 1;", got)
	}
}

// TestRenderStmts_ElseIfCollapsing verifies that an if whose Else is
// exactly one more if renders as a flat "else if" chain rather than a
// nest of blocks - the shape every compiled if/else-if chain has.
func TestRenderStmts_ElseIfCollapsing(t *testing.T) {
	call := func(name string) ir.Stmt {
		return &ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: name}}
	}
	stmt := &ir.IfStmt{
		Cond: &ir.LocalVar{Name: "a"},
		Then: &ir.Block{Statements: []ir.Stmt{call("one")}},
		Else: &ir.Block{Statements: []ir.Stmt{&ir.IfStmt{
			Cond: &ir.LocalVar{Name: "b"},
			Then: &ir.Block{Statements: []ir.Stmt{call("two")}},
			Else: &ir.Block{Statements: []ir.Stmt{call("three")}},
		}}},
	}
	var buf bytes.Buffer
	RenderStmts(&buf, []ir.Stmt{stmt}, 0)
	out := buf.String()
	if !strings.Contains(out, "} else if (b) {") {
		t.Fatalf("expected a collapsed \"else if\" chain, got:\n%s", out)
	}
	// The nested-block spelling must be gone, and the whole chain must
	// stay at one indent level (not progressively deeper).
	if strings.Contains(out, " else {\n        if") {
		t.Fatalf("expected no nested else-block around the if, got:\n%s", out)
	}
	if strings.Count(out, "\nif (") != 0 {
		t.Fatalf("expected the second if to continue the chain on the same line, got:\n%s", out)
	}
}

// TestRenderStmts_StringDispatchFolding verifies that a chain of
// strcmp comparisons against string literals renders as one compact
// switch-style dispatch - the parse_args shape.
func TestRenderStmts_StringDispatchFolding(t *testing.T) {
	mkLink := func(cmd string, body string, next *ir.IfStmt) *ir.IfStmt {
		strcmp := &ir.StaticMethodCall{
			Method: "strcmp",
			Args:   []ir.Expr{&ir.LocalVar{Name: "cmd"}, &ir.StringLit{Value: cmd}},
		}
		then := &ir.Block{Statements: []ir.Stmt{&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: body}}}}
		var elseBlock *ir.Block
		if next != nil {
			elseBlock = &ir.Block{Statements: []ir.Stmt{next}}
		} else {
			elseBlock = &ir.Block{Statements: []ir.Stmt{&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "usage"}}}}
		}
		return &ir.IfStmt{
			Cond: &ir.BinaryExpr{Op: "==", Left: strcmp, Right: &ir.IntLit{Value: 0}},
			Then: then,
			Else: elseBlock,
		}
	}
	chain := mkLink("dump-lib", "dump_lib", mkLink("dump-meta", "dump_meta", nil))

	var buf bytes.Buffer
	RenderStmts(&buf, []ir.Stmt{chain}, 0)
	out := buf.String()
	for _, want := range []string{"switch (cmd) {", `case "dump-lib":`, `case "dump-meta":`, "default:", "usage();"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected folded dispatch to contain %q, got:\n%s", want, out)
		}
	}
	if strings.Count(out, "if (") != 0 {
		t.Errorf("expected no remaining if statements after folding, got:\n%s", out)
	}
}

// TestTryStringDispatch_RejectsSingleLinkAndMismatchedTargets guards
// the fold's conservative boundaries: one link alone isn't a dispatch,
// and links testing different expressions must not be merged.
func TestTryStringDispatch_RejectsSingleLinkAndMismatchedTargets(t *testing.T) {
	link := func(target, cmd string, next *ir.IfStmt) *ir.IfStmt {
		strcmp := &ir.StaticMethodCall{
			Method: "strcmp",
			Args:   []ir.Expr{&ir.LocalVar{Name: target}, &ir.StringLit{Value: cmd}},
		}
		var elseBlock *ir.Block
		if next != nil {
			elseBlock = &ir.Block{Statements: []ir.Stmt{next}}
		} else {
			elseBlock = &ir.Block{Statements: []ir.Stmt{&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "fallback"}}}}
		}
		return &ir.IfStmt{
			Cond: &ir.BinaryExpr{Op: "==", Left: strcmp, Right: &ir.IntLit{Value: 0}},
			Then: &ir.Block{Statements: []ir.Stmt{&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "one"}}}},
			Else: elseBlock,
		}
	}
	if _, ok := tryStringDispatch(link("cmd", "a", nil)); ok {
		t.Error("a single link must not fold into a dispatch")
	}
	if _, ok := tryStringDispatch(link("cmd", "a", link("other", "b", nil))); ok {
		t.Error("links testing different expressions must not fold")
	}
	if _, ok := tryStringDispatch(link("cmd", "a", link("cmd", "b", nil))); !ok {
		t.Error("two consistent links should fold")
	}
}

// TestTryStringDispatch_KeepsTrailingNonStrcmpLink guards against data
// loss at the end of the chain: a trailing link that tests something
// other than a strcmp (a plain condition, or the chain's final else)
// must be kept whole as the switch's default arm, not silently
// discarded from the folded output.
func TestTryStringDispatch_KeepsTrailingNonStrcmpLink(t *testing.T) {
	strcmp := func(cmd string) *ir.StaticMethodCall {
		return &ir.StaticMethodCall{
			Method: "strcmp",
			Args:   []ir.Expr{&ir.LocalVar{Name: "cmd"}, &ir.StringLit{Value: cmd}},
		}
	}
	call := func(name string) ir.Stmt {
		return &ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: name}}
	}
	// if (strcmp(cmd,"a")==0) one();
	// else if (strcmp(cmd,"b")==0) two();
	// else if (x == 0) three();
	// else four();
	last := &ir.IfStmt{
		Cond: &ir.BinaryExpr{Op: "==", Left: &ir.LocalVar{Name: "x"}, Right: &ir.IntLit{Value: 0}},
		Then: &ir.Block{Statements: []ir.Stmt{call("three")}},
		Else: &ir.Block{Statements: []ir.Stmt{call("four")}},
	}
	second := &ir.IfStmt{
		Cond: &ir.BinaryExpr{Op: "==", Left: strcmp("b"), Right: &ir.IntLit{Value: 0}},
		Then: &ir.Block{Statements: []ir.Stmt{call("two")}},
		Else: &ir.Block{Statements: []ir.Stmt{last}},
	}
	first := &ir.IfStmt{
		Cond: &ir.BinaryExpr{Op: "==", Left: strcmp("a"), Right: &ir.IntLit{Value: 0}},
		Then: &ir.Block{Statements: []ir.Stmt{call("one")}},
		Else: &ir.Block{Statements: []ir.Stmt{second}},
	}

	sw, ok := tryStringDispatch(first)
	if !ok {
		t.Fatalf("expected the two leading strcmp links to fold")
	}
	if sw.Default == nil {
		t.Fatalf("expected the trailing non-strcmp link to become the default arm")
	}
	if len(sw.Default.Statements) != 1 {
		t.Fatalf("expected the entire trailing link as one default statement, got %v", sw.Default.Statements)
	}
	if _, ok := sw.Default.Statements[0].(*ir.IfStmt); !ok {
		t.Fatalf("expected the trailing IfStmt preserved, got %T", sw.Default.Statements[0])
	}

	// And it must actually render.
	var buf bytes.Buffer
	RenderStmts(&buf, []ir.Stmt{first}, 0)
	out := buf.String()
	for _, want := range []string{`case "a":`, `case "b":`, "default:", "three();", "four();"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected rendered output to contain %q, got:\n%s", want, out)
		}
	}
}
