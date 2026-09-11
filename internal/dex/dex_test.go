package dex

import (
	"fmt"
	"testing"
	"unicode/utf8"

	"github.com/destruct/destruct/internal/ir"
)

const testDexPath = "../../test/classes_merge.dex"

func TestParseHeader(t *testing.T) {
	dex, err := ParseDexFile(testDexPath)
	if err != nil {
		t.Fatalf("ParseDexFile: %v", err)
	}
	if got := dex.Version(); got != "035" {
		t.Errorf("version = %q, want 035", got)
	}
	if len(dex.Classes) == 0 {
		t.Fatal("no classes parsed")
	}
	if len(dex.Methods) == 0 || len(dex.Fields) == 0 || len(dex.Types) == 0 || len(dex.Strings) == 0 {
		t.Fatalf("missing tables: methods=%d fields=%d types=%d strings=%d",
			len(dex.Methods), len(dex.Fields), len(dex.Types), len(dex.Strings))
	}
}

func TestStringsAreValidUTF8(t *testing.T) {
	dex, err := ParseDexFile(testDexPath)
	if err != nil {
		t.Fatalf("ParseDexFile: %v", err)
	}
	bad := 0
	for i, s := range dex.Strings {
		if !utf8.ValidString(s) {
			bad++
			if bad <= 3 {
				t.Errorf("string %d is not valid UTF-8: %q", i, s)
			}
		}
	}
	if bad > 3 {
		t.Errorf("...and %d more invalid strings", bad-3)
	}
}

func TestFieldAndMethodIds(t *testing.T) {
	dex, err := ParseDexFile(testDexPath)
	if err != nil {
		t.Fatalf("ParseDexFile: %v", err)
	}

	for i := range dex.Fields {
		fid := dex.GetFieldId(uint32(i))
		if dex.GetTypeDesc(uint32(fid.ClassIdx)) == "" {
			t.Fatalf("field %d has empty class descriptor", i)
		}
		if dex.GetTypeDesc(uint32(fid.TypeIdx)) == "" {
			t.Fatalf("field %d has empty type descriptor", i)
		}
		if dex.GetString(fid.NameIdx) == "" {
			t.Fatalf("field %d has empty name", i)
		}
	}

	for i := range dex.Methods {
		mid := dex.GetMethodId(uint32(i))
		if dex.GetTypeDesc(uint32(mid.ClassIdx)) == "" {
			t.Fatalf("method %d has empty class descriptor", i)
		}
		if dex.GetProto(uint32(mid.ProtoIdx)) == nil {
			t.Fatalf("method %d has invalid proto index %d", i, mid.ProtoIdx)
		}
		if dex.GetString(mid.NameIdx) == "" {
			t.Fatalf("method %d has empty name", i)
		}
	}
}

func TestDecodeAllInstructions(t *testing.T) {
	dex, err := ParseDexFile(testDexPath)
	if err != nil {
		t.Fatalf("ParseDexFile: %v", err)
	}

	unknown := make(map[byte]int)
	total := 0
	for _, classDef := range dex.Classes {
		data := dex.GetClassData(classDef)
		if data == nil {
			continue
		}
		methods := append(append([]Method{}, data.DirectMethods...), data.VirtualMethods...)
		for _, m := range methods {
			if m.CodeOff == 0 {
				continue
			}
			ci := dex.GetCodeItem(m.CodeOff)
			if ci == nil {
				continue
			}
			code := dex.GetInstructions(ci)
			insns, consumed := decodeInstructionsFor(code, int(ci.RegistersSize))
			last := -1
			for _, inst := range insns {
				if inst.Offset <= last {
					t.Fatalf("method %d: non-increasing offset %d after %d", m.MethodIdx, inst.Offset, last)
				}
				last = inst.Offset
				if inst.Name == "unknown" {
					unknown[inst.Op]++
				}
			}
			if consumed*2 != len(code) {
				t.Fatalf("method %d: consumed %d bytes, code item has %d", m.MethodIdx, consumed*2, len(code))
			}
			total += len(insns)
		}
	}

	// Unknown opcodes are logged rather than failed: packed/protected
	// samples use nonstandard opcodes that we deliberately skip.
	if len(unknown) > 0 {
		t.Logf("nonstandard opcodes skipped: %v", unknown)
	}
	t.Logf("decoded %d instructions", total)
}

func TestDecodeFormats(t *testing.T) {
	u16 := func(vals ...uint16) []byte {
		out := make([]byte, 0, len(vals)*2)
		for _, v := range vals {
			out = append(out, byte(v), byte(v>>8))
		}
		return out
	}

	tests := []struct {
		name string
		code []byte
		want Instruction
	}{
		{
			name: "const/4 negative",
			code: u16(OP_CONST_4 | 10<<8 | 15<<12),
			want: Instruction{Offset: 0, Op: OP_CONST_4, A: 10, Literal: -1, Size: 1},
		},
		{
			name: "const 31i",
			code: u16(OP_CONST|3<<8, 0x5678, 0x1234),
			want: Instruction{Offset: 0, Op: OP_CONST, A: 3, Literal: 0x12345678, Size: 3},
		},
		{
			name: "const/high16",
			code: u16(OP_CONST_HIGH_16|5<<8, 0x1234),
			want: Instruction{Offset: 0, Op: OP_CONST_HIGH_16, A: 5, Literal: 0x12340000, Size: 2},
		},
		{
			name: "add-int/lit8",
			code: u16(OP_ADD_INT_LIT8|1<<8, 2|0x07<<8),
			want: Instruction{Offset: 0, Op: OP_ADD_INT_LIT8, A: 1, B: 2, Literal: 7, Size: 2},
		},
		{
			name: "rsub-int/lit8 negative",
			code: u16(OP_RSUB_INT_LIT8|1<<8, 2|0xFB<<8),
			want: Instruction{Offset: 0, Op: OP_RSUB_INT_LIT8, A: 1, B: 2, Literal: -5, Size: 2},
		},
		{
			name: "const-string",
			code: u16(OP_CONST_STRING|3<<8, 0x1234),
			want: Instruction{Offset: 0, Op: OP_CONST_STRING, A: 3, Ref: 0x1234, Size: 2},
		},
		{
			name: "invoke-virtual 35c",
			code: u16(OP_INVOKE_VIRTUAL|0<<8|2<<12, 0x0055, 1|2<<4),
			want: Instruction{Offset: 0, Op: OP_INVOKE_VIRTUAL, A: 2, Ref: 0x55, Regs: []int{1, 2}, Size: 3},
		},
		{
			name: "if-eqz target",
			code: u16(OP_IF_EQZ|4<<8, 5),
			want: Instruction{Offset: 0, Op: OP_IF_EQZ, A: 4, Target: 5, Size: 2},
		},
		{
			name: "goto/16 target",
			code: u16(OP_GOTO_16, 9),
			want: Instruction{Offset: 0, Op: OP_GOTO_16, Target: 9, Size: 2},
		},
	}

	for _, tc := range tests {
		got := DecodeInstructions(tc.code)
		if len(got) != 1 {
			t.Errorf("%s: got %d instructions, want 1", tc.name, len(got))
			continue
		}
		g := got[0]
		if g.Op != tc.want.Op || g.A != tc.want.A || g.B != tc.want.B ||
			g.Literal != tc.want.Literal || g.Ref != tc.want.Ref ||
			g.Target != tc.want.Target || g.Size != tc.want.Size {
			t.Errorf("%s: got %+v, want %+v", tc.name, g, tc.want)
		}
		if tc.want.Regs != nil {
			if len(g.Regs) != len(tc.want.Regs) {
				t.Errorf("%s: regs %v, want %v", tc.name, g.Regs, tc.want.Regs)
			} else {
				for i := range g.Regs {
					if g.Regs[i] != tc.want.Regs[i] {
						t.Errorf("%s: regs %v, want %v", tc.name, g.Regs, tc.want.Regs)
						break
					}
				}
			}
		}
	}
}

func TestDecodeSwitchPayload(t *testing.T) {
	// packed-switch v0, +3 followed by payload: size 2, first key 10,
	// targets +8 and +12 (relative to the switch instruction at offset 0).
	code := []byte{
		0x2b, 0x00, // packed-switch v0
		0x03, 0x00, 0x00, 0x00, // delta = 3
		0x00, 0x01, // payload ident 0x0100
		0x02, 0x00, // size = 2
		0x0a, 0x00, 0x00, 0x00, // first_key = 10
		0x08, 0x00, 0x00, 0x00, // target 0
		0x0c, 0x00, 0x00, 0x00, // target 1
	}

	insns := DecodeInstructions(code)
	if len(insns) != 1 {
		t.Fatalf("got %d instructions, want 1 (payload must be skipped)", len(insns))
	}
	sw := insns[0].Switch
	if sw == nil {
		t.Fatal("switch payload not attached")
	}
	if !sw.Packed || sw.FirstKey != 10 || len(sw.Targets) != 2 {
		t.Fatalf("unexpected payload: %+v", sw)
	}
	if sw.Targets[0] != 8 || sw.Targets[1] != 12 {
		t.Errorf("targets = %v, want [8 12]", sw.Targets)
	}
}

func TestDecodeFillArrayData(t *testing.T) {
	code := []byte{
		0x26, 0x00, // fill-array-data v0
		0x03, 0x00, 0x00, 0x00, // delta = 3
		0x00, 0x03, // payload ident 0x0300
		0x02, 0x00, // element width = 2
		0x04, 0x00, 0x00, 0x00, // size = 4
		0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00,
	}

	insns := DecodeInstructions(code)
	if len(insns) != 1 {
		t.Fatalf("got %d instructions, want 1", len(insns))
	}
	ad := insns[0].ArrayData
	if ad == nil {
		t.Fatal("array payload not attached")
	}
	if ad.ElementWidth != 2 || len(ad.Elements) != 4 {
		t.Fatalf("unexpected payload: %+v", ad)
	}
	for i, want := range []uint64{1, 2, 3, 4} {
		if ad.Elements[i] != want {
			t.Errorf("element %d = %d, want %d", i, ad.Elements[i], want)
		}
	}
}

func TestDecodeMUTF8(t *testing.T) {
	// 'A', encoded NUL, U+00E9, U+1F600 as a UTF-16 surrogate pair.
	raw := []byte{
		0x41,
		0xC0, 0x80,
		0xC3, 0xA9,
		0xED, 0xA0, 0xBD,
		0xED, 0xB8, 0x80,
	}
	got := decodeMUTF8(raw)
	want := "A\x00\u00e9\U0001F600"
	if got != want {
		t.Fatalf("decodeMUTF8 = %q, want %q", got, want)
	}
}

func TestTypeFromDesc(t *testing.T) {
	tests := map[string]string{
		"V":                    "void",
		"I":                    "int",
		"J":                    "long",
		"Z":                    "boolean",
		"Ljava/lang/String;":   "java.lang.String",
		"[I":                   "int[]",
		"[[Ljava/lang/Object;": "java.lang.Object[][]",
	}
	for desc, want := range tests {
		if got := fmt.Sprint(TypeFromDesc(desc)); got != want {
			t.Errorf("TypeFromDesc(%q).String() = %q, want %q", desc, got, want)
		}
	}
}

func TestMoveConstructorCallFirst(t *testing.T) {
	body := &ir.Block{Statements: []ir.Stmt{
		&ir.AssignStmt{Target: &ir.LocalVar{Name: "this.f"}, Value: &ir.IntLit{Value: 1}},
		&ir.ExprStmt{Expr: &ir.MethodCall{Name: "foo"}},
		&ir.SuperCallStmt{},
	}}
	moveConstructorCallFirst(body)
	if _, ok := body.Statements[0].(*ir.SuperCallStmt); !ok {
		t.Fatalf("super call not moved first: %T", body.Statements[0])
	}

	// Argument setup must be folded into the hoisted call.
	arg := &ir.LocalVar{Name: "v0"}
	body = &ir.Block{Statements: []ir.Stmt{
		&ir.AssignStmt{Target: &ir.LocalVar{Name: "this.f"}, Value: &ir.IntLit{Value: 1}},
		&ir.AssignStmt{Target: arg, Value: &ir.IntLit{Value: 7}},
		&ir.SuperCallStmt{Args: []ir.Expr{arg}},
	}}
	moveConstructorCallFirst(body)
	sup, ok := body.Statements[0].(*ir.SuperCallStmt)
	if !ok {
		t.Fatalf("super call not moved first: %T", body.Statements[0])
	}
	if len(sup.Args) != 1 || fmt.Sprint(sup.Args[0]) != "7" {
		t.Fatalf("super arg not substituted: %v", sup.Args)
	}
}

func TestDecompileAllClasses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full decompile in short mode")
	}

	dex, err := ParseDexFile(testDexPath)
	if err != nil {
		t.Fatalf("ParseDexFile: %v", err)
	}

	classes := 0
	methods := 0
	statements := 0
	for _, classDef := range dex.Classes {
		class := classFromDef(dex, classDef)
		if class == nil {
			continue
		}
		classes++
		for _, m := range class.Methods {
			methods++
			if m.Body != nil {
				statements += len(m.Body.Statements)
			}
		}
	}

	if classes == 0 || methods == 0 || statements == 0 {
		t.Fatalf("decompiled classes=%d methods=%d statements=%d", classes, methods, statements)
	}
	t.Logf("decompiled %d classes, %d methods, %d statements", classes, methods, statements)
}

func TestStreamingMatchesCount(t *testing.T) {
	total, err := CountDexClasses(testDexPath)
	if err != nil {
		t.Fatalf("CountDexClasses: %v", err)
	}
	streamed := 0
	err = DecompileDexStreaming(testDexPath, func(*ir.Class) {
		streamed++
	}, nil)
	if err != nil {
		t.Fatalf("DecompileDexStreaming: %v", err)
	}
	if streamed != total {
		t.Fatalf("streamed %d classes, counted %d", streamed, total)
	}
}
