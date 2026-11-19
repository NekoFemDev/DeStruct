package native

import (
	"errors"
	"testing"
)

func TestLoadDWARFFixture(t *testing.T) {
	info, err := LoadDWARF("testdata/dwarf-aarch64.o")
	if err != nil {
		t.Fatalf("LoadDWARF: %v", err)
	}
	if len(info.Functions) != 2 {
		t.Fatalf("functions = %d, want 2: %+v", len(info.Functions), info.Functions)
	}

	add, ok := info.FunctionAt(0)
	if !ok || add.Name != "add" {
		t.Fatalf("FunctionAt(0) = %+v, %v; want add", add, ok)
	}
	if add.LowPC != 0 || add.HighPC != 0x28 {
		t.Fatalf("add range = 0x%x..0x%x, want 0..0x28", add.LowPC, add.HighPC)
	}
	if len(add.Params) != 2 || add.Params[0].Name != "a" || add.Params[1].Name != "b" {
		t.Fatalf("add params = %+v, want a,b", add.Params)
	}
	if name, ctype, ok := add.LocalAt(4); !ok || name != "c" || ctype != "int32_t" {
		t.Fatalf("add local at +4 = (%q,%q,%v), want c/int32_t", name, ctype, ok)
	}

	if _, ok := info.FunctionAt(0x27); !ok {
		t.Fatal("FunctionAt(0x27) should still be inside add")
	}
	if fn, ok := info.FunctionAt(0x50); ok {
		t.Fatalf("FunctionAt(0x50) = %+v, want no function past the end", fn)
	}

	line, ok := info.LineAt(0)
	if !ok || line.Line != 1 {
		t.Fatalf("LineAt(0) = %+v, %v; want line 1", line, ok)
	}
	line, ok = info.LineAt(0x28)
	if !ok || line.Line != 2 {
		t.Fatalf("LineAt(0x28) = %+v, %v; want line 2", line, ok)
	}

	if _, err := LoadDWARF("../../test/liblun.so"); !errors.Is(err, ErrNoDWARF) {
		t.Fatalf("LoadDWARF(liblun) error = %v, want ErrNoDWARF", err)
	}
}
