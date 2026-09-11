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
