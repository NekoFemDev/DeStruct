package dex

import (
	"os"
	"testing"

	"github.com/destruct/destruct/internal/ir"
)

func TestFinallyFromHandler(t *testing.T) {
	setup := &ir.AssignStmt{
		Target: &ir.LocalVar{Name: "v0"},
		Value:  &ir.LocalVar{Name: "e"},
	}
	cleanup := &ir.ExprStmt{Expr: &ir.MethodCall{Object: &ir.LocalVar{Name: "res"}, Name: "close"}}
	rethrow := &ir.ThrowStmt{Value: &ir.LocalVar{Name: "v0"}}
	body := &ir.Block{Statements: []ir.Stmt{setup, cleanup, rethrow}}

	finally, ok := finallyFromHandler(body)
	if !ok {
		t.Fatal("finally handler not recognised")
	}
	if len(finally.Statements) != 1 {
		t.Fatalf("finally body has %d statements, want 1", len(finally.Statements))
	}
	if _, ok := finally.Statements[0].(*ir.ExprStmt); !ok {
		t.Fatalf("finally body statement is %T, want *ir.ExprStmt", finally.Statements[0])
	}

	// A genuine catch-all that uses the exception is left alone.
	logIt := &ir.ExprStmt{Expr: &ir.MethodCall{
		Object: &ir.LocalVar{Name: "log"},
		Name:   "e",
		Args:   []ir.Expr{&ir.LocalVar{Name: "e"}},
	}}
	notFinally := &ir.Block{Statements: []ir.Stmt{setup, logIt, rethrow}}
	if _, ok := finallyFromHandler(notFinally); ok {
		t.Error("catch-all that logs the exception was mistaken for finally")
	}
}

func TestReconstructSynchronized(t *testing.T) {
	lock := &ir.LocalVar{Name: "lock"}
	enter := &ir.ExprStmt{Expr: &ir.MethodCall{Object: lock, Name: "monitorEnter"}}
	work := &ir.AssignStmt{Target: &ir.LocalVar{Name: "v0"}, Value: &ir.IntLit{Value: 1}}
	exit := &ir.ExprStmt{Expr: &ir.MethodCall{Object: lock, Name: "monitorExit"}}
	after := &ir.ReturnStmt{}

	block := reconstructSynchronized(&ir.Block{Statements: []ir.Stmt{enter, work, exit, after}})
	if len(block.Statements) != 2 {
		t.Fatalf("block has %d statements, want 2", len(block.Statements))
	}
	sync, ok := block.Statements[0].(*ir.SynchronizedStmt)
	if !ok {
		t.Fatalf("first statement is %T, want *ir.SynchronizedStmt", block.Statements[0])
	}
	if len(sync.Body.Statements) != 1 {
		t.Fatalf("synchronized body has %d statements, want 1", len(sync.Body.Statements))
	}
	if _, ok := block.Statements[1].(*ir.ReturnStmt); !ok {
		t.Fatal("statement after synchronized was not preserved")
	}
}

func TestAnnotationsZenin(t *testing.T) {
	const path = "../../test/zenin/classes.dex"
	if _, err := os.Stat(path); err != nil {
		t.Skip("zenin fixture not present")
	}
	dex, err := ParseDexFile(path)
	if err != nil {
		t.Fatalf("ParseDexFile: %v", err)
	}
	found := 0
	for _, classDef := range dex.Classes {
		dir := dex.GetAnnotations(classDef)
		if dir == nil {
			continue
		}
		for _, ann := range dir.Class {
			if ann.TypeDesc == "" {
				t.Fatalf("class annotation with empty type in %s", dex.GetClassName(classDef.ClassIdx))
			}
			found++
		}
		for _, anns := range dir.Methods {
			for _, ann := range anns {
				if ann.TypeDesc == "" {
					t.Fatal("method annotation with empty type")
				}
				found++
			}
		}
		if found > 0 {
			return
		}
	}
	t.Skip("fixture has no annotations")
}
