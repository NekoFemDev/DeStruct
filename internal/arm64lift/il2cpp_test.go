package arm64lift

import (
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/native"
)

// renderStmts is a small helper for the IL2CPP-mode tests: render IR to
// text the same way the pipeline does.
func renderStmts(t *testing.T, stmts []ir.Stmt) string {
	t.Helper()
	var b strings.Builder
	RenderStmts(&b, stmts, 0)
	return b.String()
}

func TestRewriteForIL2CPP_UnresolvedField(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.AssignStmt{
			Target: &ir.FieldAccess{
				Object:    &ir.LocalVar{Name: "x9"},
				Name:      "field_952",
				Offset:    0x3b8,
				HasOffset: true,
				Width:     8,
			},
			Value: &ir.IntLit{Value: 1},
		},
	}
	out := renderStmts(t, RewriteForIL2CPP(stmts))
	if want := "*(uint64_t*)(x9 + 0x3b8) = 1;"; !strings.Contains(out, want) {
		t.Errorf("expected %q in:\n%s", want, out)
	}
}

func TestRewriteForIL2CPP_ZeroOffsetUsesBarePointer(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.AssignStmt{
			Target: &ir.FieldAccess{
				Object:    &ir.LocalVar{Name: "x0"},
				Name:      "field_0",
				Offset:    0,
				HasOffset: true,
				Width:     4,
			},
			Value: &ir.IntLit{Value: 0},
		},
	}
	out := renderStmts(t, RewriteForIL2CPP(stmts))
	if want := "*(uint32_t*)x0 = 0;"; !strings.Contains(out, want) {
		t.Errorf("expected %q in:\n%s", want, out)
	}
}

func TestRewriteForIL2CPP_ResolvedField(t *testing.T) {
	stmts := []ir.Stmt{
		&ir.AssignStmt{
			Target: &ir.FieldAccess{
				Object:    &ir.LocalVar{Name: "x0"},
				Name:      "field_64",
				Offset:    0x40,
				HasOffset: true,
				Width:     4,
				FieldName: "progressTarget_",
				TypeName:  "Axlebolt.Bolt.Protobuf.PlayerAchievement",
			},
			Value: &ir.IntLit{Value: 7},
		},
	}
	out := renderStmts(t, RewriteForIL2CPP(stmts))
	want := "((Axlebolt_Bolt_Protobuf_PlayerAchievement*)x0)->progressTarget_ = 7;"
	if !strings.Contains(out, want) {
		t.Errorf("expected %q in:\n%s", want, out)
	}
}

func TestRewriteForIL2CPP_NestedFieldChain(t *testing.T) {
	inner := &ir.FieldAccess{Object: &ir.LocalVar{Name: "x0"}, Name: "field_0", Offset: 0, HasOffset: true, Width: 8}
	outer := &ir.FieldAccess{Object: inner, Name: "field_64", Offset: 0x40, HasOffset: true, Width: 8}
	stmts := []ir.Stmt{
		&ir.ExprStmt{Expr: outer},
	}
	out := renderStmts(t, RewriteForIL2CPP(stmts))
	want := "*(uint64_t*)(*(uint64_t*)x0 + 0x40);"
	if !strings.Contains(out, want) {
		t.Errorf("expected %q in:\n%s", want, out)
	}
}

func TestRewriteForIL2CPP_AddrLitHex(t *testing.T) {
	addr := &ir.AddrLit{Value: 0xA2EFA0, Label: ".data+0x0"}
	if got := addr.String(); got != ".data+0x0" {
		t.Fatalf("pseudo rendering = %q, want .data+0x0", got)
	}
	stmts := []ir.Stmt{&ir.ExprStmt{Expr: addr}}
	out := renderStmts(t, RewriteForIL2CPP(stmts))
	if !strings.Contains(out, "0xa2efa0;") {
		t.Errorf("expected hex address in:\n%s", out)
	}
}

func TestLiftFunction_AddrLitRendersHex(t *testing.T) {
	insns := []native.DetailedInstruction{
		// adrp x8, #0xa2e000
		{Address: 0x0, Size: 4, Mnemonic: "adrp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x8"},
			{Type: native.OperandImm, Imm: 0xa2e000},
		}},
		// add x8, x8, #0xfa0
		{Address: 0x4, Size: 4, Mnemonic: "add", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x8"},
			{Type: native.OperandReg, Reg: "x8"},
			{Type: native.OperandImm, Imm: 0xfa0},
		}},
		// str x8, [sp, #0x10]
		{Address: 0x8, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x8"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp", Disp: 0x10}},
		}},
	}
	out := renderStmts(t, LiftFunction(insns, nil, nil, nil))
	if !strings.Contains(out, "local_16 = 0xa2efa0;") {
		t.Errorf("expected hex address local_16 = 0xA2EFA0, got:\n%s", out)
	}
}

func TestLiftFunction_AddrLitResolvesToLabel(t *testing.T) {
	insns := []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "adrp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x8"},
			{Type: native.OperandImm, Imm: 0x900000},
		}},
		{Address: 0x4, Size: 4, Mnemonic: "add", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x8"},
			{Type: native.OperandReg, Reg: "x8"},
			{Type: native.OperandImm, Imm: 0x1fa0},
		}},
		{Address: 0x8, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x8"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp", Disp: 0x10}},
		}},
	}
	resolver := func(addr uint64) (string, bool) {
		if addr == 0x901fa0 {
			return ".rodata+0x1fa0", true
		}
		return "", false
	}
	out := renderStmts(t, LiftFunction(insns, nil, resolver, nil))
	if !strings.Contains(out, "local_16 = .rodata+0x1fa0;") {
		t.Errorf("expected section label, got:\n%s", out)
	}
}

// stubMeta is a MetadataProvider for tests: one method at RVA 0x1000 of
// a PlayerAchievement instance method with one parameter, and one field
// at offset 8.
type stubMeta struct{}

func (stubMeta) MethodAtRVA(rva uint64) (string, []string, bool, bool) {
	if rva == 0x1000 {
		return "Axlebolt.Bolt.Protobuf.PlayerAchievement", []string{"other"}, false, true
	}
	return "", nil, false, false
}

func (stubMeta) FieldAtOffset(typeName string, offset uint64) (string, string, bool) {
	if typeName == "Axlebolt.Bolt.Protobuf.PlayerAchievement" && offset == 8 {
		return "progressTarget_", "int", true
	}
	return "", "", false
}

func TestLiftFunction_MetadataFieldName(t *testing.T) {
	insns := []native.DetailedInstruction{
		// str w1, [x0, #8]   (this->progressTarget_ = other)
		{Address: 0x1000, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0", Disp: 8}},
		}},
		{Address: 0x1004, Size: 4, Mnemonic: "ret"},
	}
	stmts := LiftFunctionWithOptions(insns, nil, nil, nil, nil, LiftOptions{Metadata: stubMeta{}})
	out := renderStmts(t, stmts)
	if !strings.Contains(out, "this.progressTarget_ = other;") {
		t.Errorf("expected named field assignment, got:\n%s", out)
	}
	if got := renderStmts(t, RewriteForIL2CPP(stmts)); !strings.Contains(got, "->progressTarget_ = other;") {
		t.Errorf("expected arrow field in IL2CPP mode, got:\n%s", got)
	}
}

func TestLiftFunction_MetadataSeedsParams(t *testing.T) {
	insns := []native.DetailedInstruction{
		// ldr w0, [x0]   (load this->field_0)
		{Address: 0x1000, Size: 4, Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0", Disp: 0}},
		}},
		{Address: 0x1004, Size: 4, Mnemonic: "ret"},
	}
	stmts := LiftFunctionWithOptions(insns, nil, nil, nil, nil, LiftOptions{Metadata: stubMeta{}})
	out := renderStmts(t, stmts)
	// Field 0 isn't in the stub, so the access stays synthetic - but
	// the base must be the seeded `this` from the metadata binding.
	if !strings.Contains(out, "return this.field_0;") {
		t.Errorf("expected seeded this base, got:\n%s", out)
	}
}

func TestLiftFunction_RegsAsVars(t *testing.T) {
	insns := []native.DetailedInstruction{
		// str x9, [x0, #8]   (arg0->field_8 = var_0)
		{Address: 0x0, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x9"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0", Disp: 8}},
		}},
		// str q0, [sp, #0x20]
		{Address: 0x4, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "q0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp", Disp: 0x20}},
		}},
	}
	stmts := LiftFunctionWithOptions(insns, nil, nil, nil, nil, LiftOptions{RegsAsVars: true})
	out := renderStmts(t, stmts)
	if !strings.Contains(out, "arg0.field_8 = var_0;") {
		t.Errorf("expected arg0/var_0 naming, got:\n%s", out)
	}
	if !strings.Contains(out, "local_32 = fvar_0;") {
		t.Errorf("expected separate fvar_0 class for SIMD, got:\n%s", out)
	}
}

func TestLiftFunction_DefaultRegsUnchanged(t *testing.T) {
	insns := []native.DetailedInstruction{
		{Address: 0x0, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x9"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0", Disp: 8}},
		}},
	}
	out := renderStmts(t, LiftFunction(insns, nil, nil, nil))
	if !strings.Contains(out, "x0.field_8 = x9;") {
		t.Errorf("default rendering changed, got:\n%s", out)
	}
}

func TestGenerateIL2CPPHeader(t *testing.T) {
	db, err := LoadOffsetDBFromJSON(strings.NewReader(testOffsetsJSON))
	if err != nil {
		t.Fatal(err)
	}
	header := string(GenerateIL2CPPHeader(db))
	for _, want := range []string{
		"typedef struct Axlebolt_Bolt_Protobuf_PlayerAchievement {",
		"uint8_t _pad0[0x10];",
		"int32_t progressCurrent_; /* 0x40 int */",
		"_Static_assert(offsetof(Axlebolt_Bolt_Protobuf_PlayerAchievement, progressCurrent_) == 0x40",
		"void* _unknownFields; /* 0x10 UnknownFieldSet */",
	} {
		if !strings.Contains(header, want) {
			t.Errorf("header missing %q:\n%s", want, header)
		}
	}
}

func TestSanitizeCType(t *testing.T) {
	cases := map[string]string{
		"Axlebolt.Bolt.Protobuf.PlayerAchievement": "Axlebolt_Bolt_Protobuf_PlayerAchievement",
		"id_":           "id_",
		"<>9":           "__9",
		"2fast":         "_2fast",
		"Achievement.<>c": "Achievement___c",
	}
	for in, want := range cases {
		if got := SanitizeCType(in); got != want {
			t.Errorf("SanitizeCType(%q) = %q, want %q", in, got, want)
		}
	}
}
