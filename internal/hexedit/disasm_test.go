package hexedit

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/native"
)

func codeSection(t *testing.T, s *Session) native.SectionHeader {
	t.Helper()
	elf := s.Image().ELF()
	if elf == nil {
		t.Fatalf("fixture has no ELF metadata: %v", s.Image().ELFError())
	}
	for i := range elf.Sections {
		sec := &elf.Sections[i]
		if sec.Flags&native.SHF_EXECINSTR != 0 && sec.Size >= 64 {
			return *sec
		}
	}
	t.Fatal("fixture has no executable section of at least 64 bytes")
	return native.SectionHeader{}
}

func countDisasmRows(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "v:0x") {
			n++
		}
	}
	return n
}

func TestExecDisasmELF(t *testing.T) {
	var buf bytes.Buffer
	s, err := Open(elfFixture, Options{Out: &buf})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	sec := codeSection(t, s)

	if _, err := execLine(t, s, fmt.Sprintf("disasm f:0x%x 4", sec.Offset)); err != nil {
		t.Fatalf("disasm: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, fmt.Sprintf("; .text f:0x%08x v:0x%08x", sec.Offset, sec.Addr)) {
		t.Fatalf("missing section header:\n%s", out)
	}
	if got := countDisasmRows(out); got != 4 {
		t.Fatalf("rows = %d, want 4:\n%s", got, out)
	}

	// Default count walks 16 instructions from the cursor.
	buf.Reset()
	if _, err := execLine(t, s, "goto f:0x"+fmt.Sprintf("%x", sec.Offset+16)); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if _, err := execLine(t, s, "disasm"); err != nil {
		t.Fatalf("disasm default: %v", err)
	}
	if got := countDisasmRows(buf.String()); got != defaultDisasmCount {
		t.Fatalf("default rows = %d, want %d", got, defaultDisasmCount)
	}
}

func TestExecDisasmVA(t *testing.T) {
	var buf bytes.Buffer
	s, err := Open(elfFixture, Options{Out: &buf})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	sec := codeSection(t, s)

	if _, err := execLine(t, s, fmt.Sprintf("disasm v:0x%x 2", sec.Addr+8)); err != nil {
		t.Fatalf("disasm v:: %v", err)
	}
	if got := countDisasmRows(buf.String()); got != 2 {
		t.Fatalf("rows = %d, want 2:\n%s", got, buf.String())
	}
	if s.Cursor().Space != SpaceVirtual || s.Cursor().Value != sec.Addr+8 {
		t.Fatalf("cursor = %v", s.Cursor())
	}
}

func TestExecDisasmUnalignedWarns(t *testing.T) {
	var buf bytes.Buffer
	s, err := Open(elfFixture, Options{Out: &buf})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	sec := codeSection(t, s)

	if _, err := execLine(t, s, fmt.Sprintf("disasm f:0x%x 1", sec.Offset+1)); err != nil {
		t.Fatalf("unaligned disasm: %v", err)
	}
	if !strings.Contains(buf.String(), "not 4-byte aligned") {
		t.Fatalf("missing alignment warning:\n%s", buf.String())
	}
}

func TestExecDisasmErrors(t *testing.T) {
	raw, _ := openBufferSession(t, make([]byte, 0x100))
	if _, err := execLine(t, raw, "disasm 0x0 1"); err == nil || !strings.Contains(err.Error(), "ELF") {
		t.Fatalf("raw disasm error = %v", err)
	}

	var buf bytes.Buffer
	s, err := Open(elfFixture, Options{Out: &buf})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	sec := codeSection(t, s)

	if _, err := execLine(t, s, "disasm 0x0 1"); err == nil || !strings.Contains(err.Error(), "not inside an executable section") {
		t.Fatalf("non-exec disasm error = %v", err)
	}
	if _, err := execLine(t, s, fmt.Sprintf("disasm f:0x%x 0", sec.Offset)); err == nil {
		t.Fatal("zero count: expected error")
	}
	if _, err := execLine(t, s, fmt.Sprintf("disasm f:0x%x 99999", sec.Offset)); err == nil {
		t.Fatal("oversized count: expected error")
	}
	if _, err := execLine(t, s, "disasm 0 1 2"); err == nil {
		t.Fatal("extra argument: expected error")
	}
	if _, err := execLine(t, s, "disasm 0xffffff00 1"); err == nil {
		t.Fatal("out-of-range address: expected error")
	}
}
