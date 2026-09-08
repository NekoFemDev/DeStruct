package jvm

import (
	"testing"
	"github.com/destruct/destruct/internal/ir"
)

func TestFlattenStringBuilder(t *testing.T) {
	ne := &ir.NewExpr{Type: "java.lang.StringBuilder"}
	inner := &ir.MethodCall{Object: ne, Name: "append", Args: []ir.Expr{&ir.StringLit{Value: "hello "}}}
	outer := &ir.MethodCall{Object: inner, Name: "append", Args: []ir.Expr{&ir.LocalVar{Name: "name"}}}
	toString := &ir.MethodCall{Object: outer, Name: "toString", Args: []ir.Expr{}}
	
	result := flattenStringBuilderChain(toString)
	t.Logf("Before: %s", toString)
	t.Logf("After: %s", result)
	
	if _, ok := result.(*ir.BinaryExpr); !ok {
		t.Fatalf("Expected BinaryExpr, got %T", result)
	}
}

func TestFlattenStringBuilderNoToString(t *testing.T) {
	ne := &ir.NewExpr{Type: "java.lang.StringBuilder"}
	inner := &ir.MethodCall{Object: ne, Name: "append", Args: []ir.Expr{&ir.StringLit{Value: "hello "}}}
	outer := &ir.MethodCall{Object: inner, Name: "append", Args: []ir.Expr{&ir.LocalVar{Name: "name"}}}
	
	result := flattenStringBuilderChain(outer)
	t.Logf("Before: %s", outer)
	t.Logf("After: %s", result)
	
	if _, ok := result.(*ir.BinaryExpr); !ok {
		t.Fatalf("Expected BinaryExpr, got %T", result)
	}
}

func TestIsStringBuilderExpr(t *testing.T) {
	ne := &ir.NewExpr{Type: "java.lang.StringBuilder"}
	inner := &ir.MethodCall{Object: ne, Name: "append", Args: []ir.Expr{&ir.StringLit{Value: "x"}}}
	outer := &ir.MethodCall{Object: inner, Name: "append", Args: []ir.Expr{&ir.LocalVar{Name: "y"}}}
	
	if !isStringBuilderExpr(ne) {
		t.Fatal("NewExpr should be StringBuilder expr")
	}
	if !isStringBuilderExpr(inner) {
		t.Fatal("inner append should be StringBuilder expr")
	}
	if !isStringBuilderExpr(outer) {
		t.Fatal("outer append should be StringBuilder expr")
	}
}
