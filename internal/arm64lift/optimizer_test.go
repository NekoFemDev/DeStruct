package arm64lift

import (
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/ir"
)

func vtableCallIR() *ir.IndirectCall {
	vtable := &ir.FieldAccess{
		Object:    &ir.LocalVar{Name: "x22"},
		Name:      "field_0",
		Offset:    0,
		HasOffset: true,
		Width:     8,
	}
	slot := &ir.FieldAccess{
		Object:    vtable,
		Name:      "field_56",
		Offset:    0x38,
		HasOffset: true,
		Width:     8,
	}
	return &ir.IndirectCall{
		Callee: slot,
		Args:   []ir.Expr{&ir.LocalVar{Name: "x22"}, &ir.IntLit{Value: 45}},
	}
}

func TestOptimizeForC_VTableCall(t *testing.T) {
	stmts := []ir.Stmt{&ir.ExprStmt{Expr: vtableCallIR()}}
	got := OptimizeForC(stmts, COptimizerOptions{SimplifyVTableCalls: true})
	call, ok := got[0].(*ir.ExprStmt).Expr.(*ir.StaticMethodCall)
	if !ok || call.Method != "CALL_VTABLE" {
		t.Fatalf("expected a CALL_VTABLE static call, got %#v", got[0])
	}
	if len(call.Args) != 4 {
		t.Fatalf("expected obj/offset/two call args, got %#v", call.Args)
	}
	if lit, ok := call.Args[1].(*ir.IntLit); !ok || lit.Value != 0x38 {
		t.Fatalf("expected offset 0x38, got %#v", call.Args[1])
	}

	var b strings.Builder
	RenderCFunctionWithOptions(&b, "sub_92b374", got, CRenderOptions{SimplifyVTableCalls: false})
	out := b.String()
	if !strings.Contains(out, "CALL_VTABLE(x22, 0x38, x22, 45);") {
		t.Fatalf("expected simplified vtable call, got:\n%s", out)
	}
}

func TestRenderCFunctionWithOptions_OffsetComment(t *testing.T) {
	db, err := LoadOffsetDBFromJSON(strings.NewReader(`{
		"classes": [{
			"name": "Agones.Model.GameServerSpec",
			"td": 26572,
			"fields": [{
				"name": "_Health_k_BackingField",
				"type": "SpecHealth",
				"offset": "0x10"
			}]
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	stmts := []ir.Stmt{
		&ir.AssignStmt{
			Target: &ir.LocalVar{Name: "local_16"},
			Value: &ir.FieldAccess{
				Object:    &ir.LocalVar{Name: "x6"},
				Name:      "field_16",
				Offset:    0x10,
				HasOffset: true,
				Width:     8,
			},
		},
	}
	var b strings.Builder
	RenderCFunctionWithOptions(&b, "sub_92b374", stmts, CRenderOptions{Offsets: db, OffsetComments: true})
	want := "local_16 = *(uint64_t*)((uintptr_t)x6 + 0x10) /* Agones.Model.GameServerSpec::_Health_k_BackingField */;"
	if !strings.Contains(b.String(), want) {
		t.Fatalf("expected %q in:\n%s", want, b.String())
	}
}

func TestRenderCFunctionWithOptions_SkipsVTableSlotComment(t *testing.T) {
	db, err := LoadOffsetDBFromJSON(strings.NewReader(`{
		"classes": [{
			"name": "Agones.Model.GameServerSpec",
			"td": 26572,
			"fields": [{"name": "health", "type": "int", "offset": "0x38"}]
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	vtable := &ir.FieldAccess{Object: &ir.LocalVar{Name: "x22"}, Offset: 0, HasOffset: true, Width: 8}
	slot := &ir.FieldAccess{Object: vtable, Offset: 0x38, HasOffset: true, Width: 8}
	stmts := []ir.Stmt{&ir.ExprStmt{Expr: slot}}

	var b strings.Builder
	RenderCFunctionWithOptions(&b, "sub_slot", stmts, CRenderOptions{Offsets: db, OffsetComments: true})
	if strings.Contains(b.String(), "Agones.Model.GameServerSpec") {
		t.Fatalf("vtable method slot must not receive an object-field comment:\n%s", b.String())
	}
}

func TestReduceGotos_FallthroughIfInversion(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.IfStmt{
			Cond: &ir.LocalVar{Name: "c"},
			Then: &ir.Block{Statements: []ir.Stmt{&ir.GotoStmt{Label: "L1"}}},
			Else: &ir.Block{Statements: []ir.Stmt{&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "A"}}}},
		},
		&ir.LabelStmt{Name: "L1"},
		&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "B"}},
	}
	got := ReduceGotos(stmts)
	var b strings.Builder
	RenderCFunctionWithOptions(&b, "sub_test", got, CRenderOptions{})
	out := b.String()
	if strings.Contains(out, "goto ") || strings.Contains(out, "LABEL_") {
		t.Fatalf("expected goto/label to disappear, got:\n%s", out)
	}
	if !strings.Contains(out, "if (!c) {") || !strings.Contains(out, "A();") || !strings.Contains(out, "B();") {
		t.Fatalf("expected inverted if, got:\n%s", out)
	}
}

func TestReduceGotos_TrivialChain(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.GotoStmt{Label: "L1"},
		&ir.LabelStmt{Name: "L1"},
		&ir.GotoStmt{Label: "L2"},
		&ir.LabelStmt{Name: "L2"},
	}
	got := ReduceGotos(stmts)
	var b strings.Builder
	RenderCFunctionWithOptions(&b, "sub_chain", got, CRenderOptions{})
	out := b.String()
	if strings.Contains(out, "goto ") {
		t.Fatalf("expected the redundant chain to vanish, got:\n%s", out)
	}
}

func TestReduceGotos_WhileLoop(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.LabelStmt{Name: "START"},
		&ir.IfStmt{
			Cond: &ir.BinaryExpr{Op: "==", Left: &ir.LocalVar{Name: "c"}, Right: &ir.IntLit{Value: 0}},
			Then: &ir.Block{Statements: []ir.Stmt{&ir.GotoStmt{Label: "END"}}},
		},
		&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "body"}},
		&ir.GotoStmt{Label: "START"},
		&ir.LabelStmt{Name: "END"},
		&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "after"}},
	}
	got := ReduceGotos(stmts)
	var b strings.Builder
	RenderCFunctionWithOptions(&b, "sub_loop", got, CRenderOptions{})
	out := b.String()
	if !strings.Contains(out, "while (c != 0) {") {
		t.Fatalf("expected a while loop, got:\n%s", out)
	}
	if strings.Contains(out, "goto ") || strings.Contains(out, "LABEL_") {
		t.Fatalf("expected loop labels/gotos to disappear, got:\n%s", out)
	}
	if !strings.Contains(out, "body();") || !strings.Contains(out, "after();") {
		t.Fatalf("expected body and continuation preserved, got:\n%s", out)
	}
}

func TestRenderCFunction_CharConstants(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.IfStmt{
			Cond: &ir.BinaryExpr{Op: "==", Left: &ir.LocalVar{Name: "w1"}, Right: &ir.IntLit{Value: 45}},
			Then: &ir.Block{Statements: []ir.Stmt{&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "a"}}}},
		},
		&ir.IfStmt{
			Cond: &ir.BinaryExpr{
				Op:    "==",
				Left:  &ir.BinaryExpr{Op: "|", Left: &ir.LocalVar{Name: "w8"}, Right: &ir.IntLit{Value: 32}},
				Right: &ir.IntLit{Value: 120},
			},
			Then: &ir.Block{Statements: []ir.Stmt{&ir.ExprStmt{Expr: &ir.StaticMethodCall{Method: "b"}}}},
		},
	}
	var b strings.Builder
	RenderCFunctionWithOptions(&b, "sub_chars", stmts, CRenderOptions{CharConstants: true})
	out := b.String()
	for _, want := range []string{
		"w1 == '-' /* 0x2d */",
		"(w8 | 32) == 'x' /* 0x78 */",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "(w8 | ' '") {
		t.Errorf("arithmetic operand 32 must stay numeric:\n%s", out)
	}
}

func TestRenderCFunction_AddressComment(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.AssignStmt{
			Target: &ir.LocalVar{Name: "x0"},
			Value:  &ir.AddrLit{Value: 0xa2a408},
		},
	}
	var b strings.Builder
	RenderCFunctionWithOptions(&b, "sub_addr", stmts, CRenderOptions{AddressComments: true})
	if !strings.Contains(b.String(), "((uintptr_t)0xa2a408) /* ADDR */") {
		t.Fatalf("expected address comment, got:\n%s", b.String())
	}
}

func TestReduceGotos_PreservesConditionSideEffects(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.IfStmt{
			Cond: &ir.StaticMethodCall{Method: "check"},
			Then: &ir.Block{Statements: []ir.Stmt{&ir.GotoStmt{Label: "L"}}},
		},
		&ir.LabelStmt{Name: "L"},
	}
	got := ReduceGotos(stmts)
	var b strings.Builder
	RenderCFunctionWithOptions(&b, "sub_side", got, CRenderOptions{})
	out := b.String()
	if !strings.Contains(out, "ext_check();") {
		t.Fatalf("expected condition side effect preserved, got:\n%s", out)
	}
	if strings.Contains(out, "goto ") || strings.Contains(out, "LABEL_") {
		t.Fatalf("expected goto/label removed, got:\n%s", out)
	}
}
