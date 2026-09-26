package hexedit

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFunctionsIndex(t *testing.T) {
	var buf bytes.Buffer
	elfSession, err := Open(elfFixture, Options{Out: &buf})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer elfSession.Close()

	funcs, err := elfSession.functions(context.Background())
	if err != nil {
		t.Fatalf("functions: %v", err)
	}
	if len(funcs) == 0 {
		t.Fatal("fixture has no functions")
	}
	for i, f := range funcs {
		if f.Size == 0 || f.Size > maxFunctionBytes {
			t.Fatalf("function %d (%s) size = %d", i, f.Name, f.Size)
		}
		if i > 0 && funcs[i-1].Addr >= f.Addr {
			t.Fatalf("functions not sorted: %d >= %d", funcs[i-1].Addr, f.Addr)
		}
	}
	found, ok := functionContaining(funcs, funcs[0].Addr+funcs[0].Size/2)
	if !ok || found.Addr != funcs[0].Addr {
		t.Fatalf("containing lookup = %+v, %v", found, ok)
	}

	// The index is cached: repeated calls return the same slice.
	again, err := elfSession.functions(context.Background())
	if err != nil || len(again) != len(funcs) {
		t.Fatalf("cached functions: %d, %v", len(again), err)
	}
}

func TestDecompileByAddrAndName(t *testing.T) {
	var buf bytes.Buffer
	s, err := Open(elfFixture, Options{Out: &buf})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	funcs, err := s.functions(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Lift by address: try a few candidates in case the first is a
	// thunk the lifter yields nothing useful for.
	var lastErr error
	lifted := false
	for _, f := range funcs {
		if f.Size < 16 {
			continue
		}
		buf.Reset()
		if _, err := execLine(t, s, fmt.Sprintf("decompile v:0x%x", f.Addr)); err != nil {
			lastErr = err
			continue
		}
		if !strings.Contains(buf.String(), "// ") || !strings.Contains(buf.String(), "v:0x") {
			t.Fatalf("decompile header missing:\n%s", buf.String())
		}
		lifted = true
		break
	}
	if !lifted {
		t.Fatalf("no function lifted (last error: %v)", lastErr)
	}

	// Lift by name when the fixture exposes one.
	for _, f := range funcs {
		if strings.HasPrefix(f.Name, "sub_") || strings.ContainsAny(f.Name, " \t") {
			continue
		}
		buf.Reset()
		if _, err := execLine(t, s, "decompile "+f.Name); err != nil {
			t.Fatalf("decompile %q: %v", f.Name, err)
		}
		if !strings.Contains(buf.String(), f.Name) {
			t.Fatalf("decompile %q output missing name:\n%s", f.Name, buf.String())
		}
		return
	}
	t.Log("fixture exposes no named functions; name lookup not exercised")
}

func TestDecompileErrors(t *testing.T) {
	raw, _ := openBufferSession(t, make([]byte, 0x40))
	if _, err := execLine(t, raw, "decompile 0x0"); err == nil || !strings.Contains(err.Error(), "AArch64 ELF") {
		t.Fatalf("raw decompile error = %v", err)
	}
	if _, err := execLine(t, raw, "decompile"); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("missing usage error = %v", err)
	}

	var buf bytes.Buffer
	s, err := Open(elfFixture, Options{Out: &buf})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if _, err := execLine(t, s, "decompile definitely_not_a_function"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown function error = %v", err)
	}
	if _, err := execLine(t, s, "decompile f:0x0"); err == nil || !strings.Contains(err.Error(), "file-backed section") {
		t.Fatalf("unmapped address error = %v", err)
	}
}

func TestDecompileRejectsNonAArch64(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(elfFixture)
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite e_machine to EM_X86_64 (62).
	src[18], src[19] = 62, 0
	path := filepath.Join(dir, "x86.so")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	s, err := Open(path, Options{Out: &buf})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	_, err = execLine(t, s, "decompile 0x0")
	if err == nil || !strings.Contains(err.Error(), "AArch64-only") || !strings.Contains(err.Error(), "destruct elf") {
		t.Fatalf("non-AArch64 decompile error = %v", err)
	}
}
