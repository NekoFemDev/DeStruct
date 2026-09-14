package arm64lift

import (
	"bytes"
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/ir"
)

func beginCatch() ir.Stmt {
	return &ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "__cxa_begin_catch", Args: []ir.Expr{&ir.LocalVar{Name: "x0"}}}}
}

func endCatch() ir.Stmt {
	return &ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "__cxa_end_catch"}}
}

func plainCall(name string) ir.Stmt {
	return &ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: name}}
}

// TestReconstructTryCatch_FoldsBeginEndPair checks the core fold: a
// protected region, a begin marker, a handler, and an end marker become
// one TryStmt with the handler as its single catch, and code after the
// end marker continues normally.
func TestReconstructTryCatch_FoldsBeginEndPair(t *testing.T) {
	in := []ir.Stmt{plainCall("work"), beginCatch(), plainCall("handle"), endCatch(), plainCall("after")}
	out := reconstructTryCatch(in)

	if len(out) != 2 {
		t.Fatalf("expected 2 statements (try + trailing call), got %d: %v", len(out), out)
	}
	try, ok := out[0].(*ir.TryStmt)
	if !ok {
		t.Fatalf("expected the first statement to be a TryStmt, got %T: %v", out[0], out[0])
	}
	if len(try.Body.Statements) != 1 || !isCall(try.Body.Statements[0], "work") {
		t.Errorf("expected the try body to be the protected call, got %v", try.Body.Statements)
	}
	if len(try.Catches) != 1 {
		t.Fatalf("expected exactly 1 catch clause, got %d", len(try.Catches))
	}
	if len(try.Catches[0].Body.Statements) != 1 || !isCall(try.Catches[0].Body.Statements[0], "handle") {
		t.Errorf("expected the catch body to be the handler call, got %v", try.Catches[0].Body.Statements)
	}
	if !isCall(out[1], "after") {
		t.Errorf("expected the trailing call to continue after the try, got %v", out[1])
	}
}

// TestReconstructTryCatch_LeavesUnmatchedShapesAlone guards the
// conservative boundaries: a lone begin marker with no end, a begin
// with no protected code before it, or no markers at all must all pass
// through unchanged.
func TestReconstructTryCatch_LeavesUnmatchedShapesAlone(t *testing.T) {
	cases := []struct {
		name string
		in   []ir.Stmt
	}{
		{"no markers", []ir.Stmt{plainCall("a"), plainCall("b")}},
		{"begin first", []ir.Stmt{beginCatch(), plainCall("h"), endCatch(), plainCall("a")}},
		{"unmatched begin", []ir.Stmt{plainCall("a"), beginCatch(), plainCall("h")}},
		{"empty", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := reconstructTryCatch(tc.in)
			if len(out) != len(tc.in) {
				t.Fatalf("expected %d statements unchanged, got %d: %v", len(tc.in), len(out), out)
			}
			for _, s := range out {
				if _, ok := s.(*ir.TryStmt); ok {
					t.Fatalf("expected no TryStmt to be produced, got %v", out)
				}
			}
		})
	}
}

// TestReconstructTryCatch_NestedAndRenders checks the fold inside an
// if arm and that RenderStmts prints a real try statement for it,
// not the old "try { ... } catch { ... }" placeholder.
func TestReconstructTryCatch_NestedAndRenders(t *testing.T) {
	ifs := &ir.IfStmt{
		Cond: &ir.LocalVar{Name: "c"},
		Then: &ir.Block{Statements: []ir.Stmt{plainCall("work"), beginCatch(), plainCall("handle"), endCatch()}},
		Else: &ir.Block{Statements: []ir.Stmt{plainCall("other")}},
	}
	out := reconstructTryCatch([]ir.Stmt{ifs})
	if len(out) != 1 {
		t.Fatalf("expected the list length to be unchanged, got %v", out)
	}
	arm := out[0].(*ir.IfStmt).Then.Statements
	if len(arm) != 1 {
		t.Fatalf("expected the arm to hold exactly the folded TryStmt, got %v", arm)
	}
	if _, ok := arm[0].(*ir.TryStmt); !ok {
		t.Fatalf("expected a TryStmt, got %T", arm[0])
	}

	var buf bytes.Buffer
	RenderStmts(&buf, out, 0)
	rendered := buf.String()
	for _, want := range []string{"try {", "catch (Exception e) {", "work();", "handle();"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("expected rendered output to contain %q, got:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "try { ... } catch { ... }") {
		t.Errorf("the try placeholder must not appear, got:\n%s", rendered)
	}
}

func isCall(s ir.Stmt, name string) bool {
	es, ok := s.(*ir.ExprStmt)
	if !ok {
		return false
	}
	c, ok := es.Expr.(*ir.StaticMethodCall)
	return ok && c.Method == name
}
