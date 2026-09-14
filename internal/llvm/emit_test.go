package llvm

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/ir"
)

// TestEmitFunction_SimpleIfElse checks the structural skeleton the
// exporter promises: an entry block with allocas, real basic blocks
// and branches for structured control flow, a call, and a terminator
// on every path.
func TestEmitFunction_SimpleIfElse(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.IfStmt{
			Cond: &ir.BinaryExpr{
				Op:    "==",
				Left:  &ir.LocalVar{Name: "w0"},
				Right: &ir.IntLit{Value: 0},
			},
			Then: &ir.Block{Statements: []ir.Stmt{
				&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "fail"}},
			}},
			Else: &ir.Block{Statements: []ir.Stmt{
				&ir.AssignStmt{Target: &ir.LocalVar{Name: "w1"}, Value: &ir.IntLit{Value: 7}},
			}},
		},
		&ir.ReturnStmt{Value: &ir.LocalVar{Name: "w1"}},
	}

	var buf bytes.Buffer
	EmitFunction(&buf, "test_func", stmts)
	out := buf.String()

	for _, want := range []string{
		`define i64 @"test_func"() {`,
		"entry:",
		"alloca i64",
		"icmp eq i64",
		"br i1",
		"call i64 @\"fail\"()",
		"store i64 7",
		"ret i64",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
	// Every basic block must end in a terminator before the next label:
	// the entry block needs its own br.
	if !strings.Contains(out, "br label %entry_body") {
		t.Errorf("entry block must branch into the body, got:\n%s", out)
	}
}

// TestEmitFunction_StringGlobalsAndCalls checks string literals are
// declared as module globals and referenced through gep/ptrtoint, and
// that argument lists come out as typed operands.
func TestEmitFunction_StringGlobalsAndCalls(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.ExprStmt{Expr: &ir.StaticMethodCall{
			Method: "strcmp",
			Args: []ir.Expr{
				&ir.LocalVar{Name: "cmd"},
				&ir.StringLit{Value: "--help"},
			},
		}},
	}
	var buf bytes.Buffer
	EmitFunction(&buf, "dispatcher", stmts)
	out := buf.String()

	if !strings.Contains(out, `@.str1 = private unnamed_addr constant [7 x i8] c"--help\00"`) {
		t.Errorf("expected a string global declaration, got:\n%s", out)
	}
	if !strings.Contains(out, "getelementptr inbounds") {
		t.Errorf("expected a gep for the string literal, got:\n%s", out)
	}
	if !strings.Contains(out, `call i64 @"strcmp"(i64`) {
		t.Errorf("expected a typed strcmp call, got:\n%s", out)
	}
}

// TestEmitFunction_LoopsAndLabels checks while/do-while and the merge
// LabelStmt/GotoStmt pair map onto LLVM blocks and branches.
func TestEmitFunction_LoopsAndLabels(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.WhileStmt{
			Cond: &ir.LocalVar{Name: "c"},
			Body: &ir.Block{Statements: []ir.Stmt{
				&ir.BreakStmt{},
			}},
		},
		&ir.LabelStmt{Name: "L_100"},
		&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "after"}},
		&ir.GotoStmt{Label: "L_100"},
	}
	var buf bytes.Buffer
	EmitFunction(&buf, "looper", stmts)
	out := buf.String()

	for _, want := range []string{
		"while_head",
		"while_body",
		"while_exit",
		"br label %while_head",
		"L_100:",
		"br label %L_100",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

// TestEmitFunction_UnreachableCodeGetsItsOwnBlock checks statements the
// lifter emits after a terminator (exception cleanup) don't produce
// invalid IR with two terminators in a row: they start a fresh "dead"
// block instead.
func TestEmitFunction_UnreachableCodeGetsItsOwnBlock(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.ReturnStmt{Value: &ir.IntLit{Value: 1}},
		&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "landing_pad"}},
	}
	var buf bytes.Buffer
	EmitFunction(&buf, "cleanup", stmts)
	out := buf.String()
	if !strings.Contains(out, "dead") {
		t.Errorf("expected unreachable cleanup to start a dead block, got:\n%s", out)
	}
	if strings.Contains(out, "ret i64 1\n  ret i64 0") {
		t.Errorf("two terminators must never share a block, got:\n%s", out)
	}
}

// checkBlockTerminators enforces LLVM's structural rule that every
// basic block ends in a terminator before the next label - the failure
// mode is an empty block (e.g. an if/else whose arms both jump away)
// left dangling right before a merge label.
func checkBlockTerminators(t *testing.T, out string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, ln := range lines {
		if !strings.HasSuffix(ln, ":") || strings.HasPrefix(strings.TrimSpace(ln), ";") {
			continue
		}
		j := i - 1
		for j >= 0 && strings.TrimSpace(lines[j]) == "" {
			j--
		}
		if j < 0 {
			continue
		}
		prev := strings.TrimSpace(lines[j])
		if strings.HasSuffix(prev, "{") || strings.HasPrefix(prev, ";") {
			continue
		}
		terminated := strings.HasPrefix(prev, "br ") ||
			strings.HasPrefix(prev, "ret ") ||
			prev == "unreachable" ||
			strings.HasPrefix(prev, "switch ")
		if !terminated {
			t.Errorf("block %q starts without a terminator on the previous line (%q); output:\n%s", ln, prev, out)
		}
	}
}

// TestEmitFunction_EmptyBlockBeforeMergeLabelGetsBranch covers the
// merge-point shape the lifter now emits: both arms of a conditional
// end in a goto, so the if's own end block is empty and must be closed
// with an explicit branch before the merge label - an empty unterminated
// block is exactly what llvm-as rejects.
func TestEmitFunction_EmptyBlockBeforeMergeLabelGetsBranch(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.IfStmt{
			Cond: &ir.BinaryExpr{Op: "==", Left: &ir.LocalVar{Name: "w0"}, Right: &ir.IntLit{Value: 0}},
			Then: &ir.Block{Statements: []ir.Stmt{
				&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "a"}},
				&ir.GotoStmt{Label: "L_20"},
			}},
			Else: &ir.Block{Statements: []ir.Stmt{
				&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "b"}},
				&ir.GotoStmt{Label: "L_20"},
			}},
		},
		&ir.LabelStmt{Name: "L_20"},
		&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "c"}},
		&ir.ReturnStmt{},
	}
	var buf bytes.Buffer
	EmitFunction(&buf, "merge_labels", stmts)
	out := buf.String()
	checkBlockTerminators(t, out)
	if !strings.Contains(out, "br label %L_20") {
		t.Errorf("expected a branch to the merge label, got:\n%s", out)
	}
	if !strings.Contains(out, "ret i64 0") || strings.Contains(out, "ret void") {
		t.Errorf("expected value-less return to still return i64, got:\n%s", out)
	}
}

// TestEmitFunction_StringSwitchLowersToComparisons covers the folded
// string dispatch: LLVM switch cases must be integer constants, so a
// switch whose values are StringLits has to become a strcmp equality
// chain (with the string globals actually declared) instead of an
// invalid "switch i64 %t [ i64 %ptr, ... ]".
func TestEmitFunction_StringSwitchLowersToComparisons(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.SwitchStmt{
			Target: &ir.LocalVar{Name: "cmd"},
			Cases: []*ir.CaseClause{
				{Values: []ir.Expr{&ir.StringLit{Value: "dump-lib"}}, Body: &ir.Block{Statements: []ir.Stmt{
					&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "dump_lib"}},
				}}},
				{Values: []ir.Expr{&ir.StringLit{Value: "dump-meta"}}, Body: &ir.Block{Statements: []ir.Stmt{
					&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "dump_meta"}},
				}}},
			},
			Default: &ir.Block{Statements: []ir.Stmt{&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "usage"}}}},
		},
	}
	var buf bytes.Buffer
	EmitFunction(&buf, "dispatch", stmts)
	out := buf.String()
	for _, want := range []string{
		`@.str1 = private unnamed_addr constant [9 x i8] c"dump-lib\00"`,
		`@.str2 = private unnamed_addr constant [10 x i8] c"dump-meta\00"`,
		`call i64 @"strcmp"`,
		"icmp eq i64",
		`declare i64 @"strcmp"(...)`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "switch i64") {
		t.Errorf("a string dispatch must not be emitted as an integer switch, got:\n%s", out)
	}
	checkBlockTerminators(t, out)
}

// TestModule_DeclaresExternalCalleesAndSkipsDuplicates checks the
// module-level rules: every referenced-but-undefined callee gets one
// variadic declaration, a called function the module defines does NOT,
// and a duplicate definition (two symbol aliases demangling to one
// name) is skipped rather than emitted twice.
func TestModule_DeclaresExternalCalleesAndSkipsDuplicates(t *testing.T) {
	var buf bytes.Buffer
	m := NewModule(&buf)
	m.EmitHeader("test", "input")
	m.EmitFunction("callee", []ir.Stmt{&ir.ReturnStmt{Value: &ir.IntLit{Value: 1}}})
	m.EmitFunction("callee", []ir.Stmt{&ir.ReturnStmt{Value: &ir.IntLit{Value: 2}}}) // duplicate
	m.EmitFunction("caller", []ir.Stmt{
		&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "callee"}},
		&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "external_fn"}},
	})
	m.Finish()
	out := buf.String()

	if got := strings.Count(out, `define i64 @"callee"()`); got != 1 {
		t.Errorf("expected exactly one definition of callee, got %d:\n%s", got, out)
	}
	if !strings.Contains(out, "; duplicate definition of") {
		t.Errorf("expected a duplicate-definition marker, got:\n%s", out)
	}
	if !strings.Contains(out, `declare i64 @"external_fn"(...)`) {
		t.Errorf("expected a declaration for the external callee, got:\n%s", out)
	}
	if strings.Contains(out, `declare i64 @"callee"(...)`) {
		t.Errorf("a function defined by the module must not be declared, got:\n%s", out)
	}
}

// TestModule_AssemblesWithLLVMAs is an end-to-end guard for the
// "feed this into llvm-as" promise: the emitted module is handed to a
// real llvm-as if one is installed (skipped otherwise). It exercises
// merge labels, a folded string dispatch, external calls, and a
// value-less return together.
func TestModule_AssemblesWithLLVMAs(t *testing.T) {
	asm, err := exec.LookPath("llvm-as")
	if err != nil {
		t.Skip("llvm-as not installed")
	}
	var buf bytes.Buffer
	m := NewModule(&buf)
	m.EmitHeader("test", "input")
	m.EmitFunction("dispatch", []ir.Stmt{
		&ir.IfStmt{
			Cond: &ir.BinaryExpr{Op: "==", Left: &ir.LocalVar{Name: "w0"}, Right: &ir.IntLit{Value: 0}},
			Then: &ir.Block{Statements: []ir.Stmt{&ir.GotoStmt{Label: "L_20"}}},
			Else: &ir.Block{Statements: []ir.Stmt{&ir.GotoStmt{Label: "L_20"}}},
		},
		&ir.LabelStmt{Name: "L_20"},
		&ir.SwitchStmt{
			Target: &ir.LocalVar{Name: "cmd"},
			Cases: []*ir.CaseClause{
				{Values: []ir.Expr{&ir.StringLit{Value: "dump-lib"}}, Body: &ir.Block{Statements: []ir.Stmt{
					&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "dump_lib"}},
				}}},
			},
			Default: &ir.Block{Statements: []ir.Stmt{&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "usage"}}}},
		},
		&ir.ReturnStmt{},
	})
	m.Finish()

	path := filepath.Join(t.TempDir(), "module.ll")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write module: %v", err)
	}
	cmd := exec.Command(asm, path, "-o", filepath.Join(t.TempDir(), "module.bc"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("llvm-as rejected the emitted module: %v\n%s\nmodule:\n%s", err, out, buf.String())
	}
}
