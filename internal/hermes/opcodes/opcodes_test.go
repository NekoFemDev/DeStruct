package opcodes

import "testing"

// syntheticTable builds a tiny table to test NewTable's derived fields.
func syntheticTable() *Table {
	return NewTable(999, []*Opcode{
		{Name: "Unreachable"},
		{Name: "Mov", Operands: []Operand{{Type: Reg8}, {Type: Reg8}}},
		{Name: "MovLong", Operands: []Operand{{Type: Reg32}, {Type: Reg32}}},
		{Name: "Jmp", Operands: []Operand{{Type: Addr8}}},
		{Name: "JmpLong", Operands: []Operand{{Type: Addr32}}},
		{Name: "JmpTrue", Operands: []Operand{{Type: Addr8}, {Type: Reg8}}},
		{Name: "JmpTrueLong", Operands: []Operand{{Type: Addr32}, {Type: Reg8}}},
	})
}

func TestNewTableAssignsOpcodesSizesAndLookup(t *testing.T) {
	table := syntheticTable()

	if got := table.Opcode(4); got == nil || got.Name != "JmpLong" {
		t.Fatalf("Opcode(4) = %v, want JmpLong", got)
	}
	if got := table.Find("JmpTrue"); got == nil || got.Value != 5 {
		t.Fatalf("Find(JmpTrue) = %v, want value 5", got)
	}
	if table.Opcode(200) != nil {
		t.Fatal("Opcode(200) should be nil for an unused byte")
	}

	for _, tc := range []struct {
		name string
		want int
	}{
		{"Unreachable", 1},
		{"Mov", 3},
		{"MovLong", 9},
		{"Jmp", 2},
		{"JmpLong", 5},
		{"JmpTrue", 3},
	} {
		if got := table.Find(tc.name).Size; got != tc.want {
			t.Errorf("%s.Size = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestLongFormLinking(t *testing.T) {
	table := syntheticTable()

	jmp := table.Find("Jmp")
	if jmp.LongForm == nil || jmp.LongForm.Name != "JmpLong" {
		t.Fatalf("Jmp.LongForm = %v, want JmpLong", jmp.LongForm)
	}
	if jmp.LongForm.ShortForm != jmp {
		t.Fatal("JmpLong.ShortForm does not point back at Jmp")
	}
	if got := table.Find("JmpTrue").LongForm; got == nil || got.Name != "JmpTrueLong" {
		t.Fatalf("JmpTrue.LongForm = %v, want JmpTrueLong", got)
	}

	// Mov/MovLong merely share the "Long" suffix; they must not link.
	if mov := table.Find("Mov"); mov.LongForm != nil {
		t.Errorf("Mov.LongForm = %v, want nil (not a jump)", mov.LongForm)
	}
	if movLong := table.Find("MovLong"); movLong.ShortForm != nil {
		t.Errorf("MovLong.ShortForm = %v, want nil", movLong.ShortForm)
	}
}

func TestParseOperandTypeRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		want OperandType
	}{
		{"Reg8", Reg8},
		{"Reg32", Reg32},
		{"UInt8", UInt8},
		{"UInt16", UInt16},
		{"UInt32", UInt32},
		{"Addr8", Addr8},
		{"Addr32", Addr32},
		{"Imm32", Imm32},
		{"Double", Double},
	} {
		got, err := ParseOperandType(tc.name)
		if err != nil {
			t.Errorf("ParseOperandType(%q): %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseOperandType(%q) = %v, want %v", tc.name, got, tc.want)
		}
		if got.String() != tc.name {
			t.Errorf("OperandType(%v).String() = %q, want %q", got, got.String(), tc.name)
		}
		if got.Size() == 0 {
			t.Errorf("%v.Size() = 0", got)
		}
	}
	if _, err := ParseOperandType("NoSuchType"); err == nil {
		t.Error("ParseOperandType accepted a bogus type name")
	}
}
