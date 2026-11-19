package native

import (
	"context"
	"testing"
)

func TestInfoLibLun(t *testing.T) {
	p, err := NewELFParser("../../test/liblun.so")
	if err != nil {
		t.Fatalf("NewELFParser: %v", err)
	}
	info, err := p.Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if info.Class != "ELF64" {
		t.Errorf("Class = %q, want ELF64", info.Class)
	}
	if info.Machine != "AArch64" {
		t.Errorf("Machine = %q, want AArch64", info.Machine)
	}
	if info.SectionCount == 0 || len(info.Sections) != info.SectionCount {
		t.Errorf("sections = %d / %d, want matching non-zero counts", len(info.Sections), info.SectionCount)
	}
	if info.SymbolCount == 0 {
		t.Error("SymbolCount = 0, want symbols from .dynsym/.symtab")
	}
	if info.FunctionCount == 0 {
		t.Error("FunctionCount = 0, want defined function symbols")
	}
	if len(info.Imports) == 0 {
		t.Error("Imports is empty, want libc imports")
	}
	if info.SONAME != "liblun.so" {
		t.Errorf("SONAME = %q, want liblun.so", info.SONAME)
	}
	if len(info.Needed) == 0 {
		t.Error("Needed is empty, want dynamic dependencies")
	}
	if !info.Stripped {
		t.Error("Stripped = false, want true for liblun.so (no .symtab)")
	}
}
