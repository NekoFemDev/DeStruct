package hexedit

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/native"
)

func TestSessionResolveRawAddresses(t *testing.T) {
	s, err := Open(writeTemp(t, make([]byte, 0x100)), Options{Out: io.Discard})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	off, err := s.ResolveAddr(Addr{Value: 0x10, Space: SpaceFile})
	if err != nil || off != 0x10 {
		t.Fatalf("resolve file offset: off=%d err=%v", off, err)
	}

	if _, err := s.ResolveAddr(Addr{Value: 0x100, Space: SpaceFile}); err == nil {
		t.Fatal("expected out-of-range error at EOF")
	} else if !strings.Contains(err.Error(), "beyond the end") {
		t.Fatalf("unexpected EOF error: %v", err)
	}

	if _, err := s.ResolveAddr(Addr{Value: 0x10, Space: SpaceVirtual}); err == nil {
		t.Fatal("expected error resolving v: on a raw file")
	} else if !strings.Contains(err.Error(), "no ELF metadata") {
		t.Fatalf("unexpected VA error: %v", err)
	}
}

func TestSessionResolveELFAddresses(t *testing.T) {
	s, err := Open(elfFixture, Options{Out: io.Discard})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	elf := s.Image().ELF()
	if elf == nil {
		t.Fatalf("no ELF metadata: %v", s.Image().ELFError())
	}
	var sec *native.SectionHeader
	for i := range elf.Sections {
		if elf.Sections[i].Flags&native.SHF_EXECINSTR != 0 && elf.Sections[i].Size > 16 {
			sec = &elf.Sections[i]
			break
		}
	}
	if sec == nil {
		t.Fatal("no executable section in fixture")
	}

	va := sec.Addr + 8
	off, err := s.ResolveAddr(Addr{Value: va, Space: SpaceVirtual})
	if err != nil {
		t.Fatalf("resolve v:0x%x: %v", va, err)
	}
	if want := int64(sec.Offset + 8); off != want {
		t.Errorf("v:0x%x resolved to %d, want %d", va, off, want)
	}
	if off, err := s.ResolveAddr(Addr{Value: uint64(off), Space: SpaceFile}); err != nil || off != int64(sec.Offset+8) {
		t.Errorf("resolve file offset: off=%d err=%v", off, err)
	}
}

// TestSessionAddressHint exercises the did-you-mean path with a
// hand-built section table: a file offset beyond EOF that looks like a
// virtual address gets a hint, and a virtual address outside the
// section table that looks like an in-file offset gets the reverse.
func TestSessionAddressHint(t *testing.T) {
	s, err := Open(writeTemp(t, make([]byte, 0x200)), Options{Out: io.Discard})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	s.img.elf = &native.ELFParser{
		Sections: []native.SectionHeader{
			{Type: native.SHT_PROGBITS, Addr: 0x7f000000, Offset: 0x100, Size: 0x10},
		},
	}

	_, err = s.ResolveAddr(Addr{Value: 0x7f000000, Space: SpaceFile})
	if err == nil || !strings.Contains(err.Error(), "did you mean v:0x7f000000") {
		t.Fatalf("expected VA hint, got %v", err)
	}

	_, err = s.ResolveAddr(Addr{Value: 0x100, Space: SpaceVirtual})
	if err == nil || !strings.Contains(err.Error(), "did you mean f:0x100") {
		t.Fatalf("expected file-offset hint, got %v", err)
	}
}

func TestSessionRead(t *testing.T) {
	data := []byte("0123456789")
	s, err := Open(writeTemp(t, data), Options{Out: io.Discard})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	got, err := s.Read(4, 3)
	if err != nil || string(got) != "456" {
		t.Fatalf("Read(4,3) = %q, %v", got, err)
	}
	got, err = s.Read(8, 100)
	if err != nil || string(got) != "89" {
		t.Fatalf("clamped Read = %q, %v", got, err)
	}
	if _, err := s.Read(10, 1); err == nil {
		t.Fatal("expected EOF error")
	}
	if _, err := s.Read(0, -1); err == nil {
		t.Fatal("expected negative-length error")
	}

	s.SetCursor(Addr{Value: 0x4, Space: SpaceFile})
	if s.Cursor().Value != 4 {
		t.Fatalf("cursor = %v", s.Cursor())
	}
}

func TestSessionReadOnlyAndAccessors(t *testing.T) {
	s, err := Open(writeTemp(t, []byte{1}), Options{ReadOnly: true, Out: io.Discard})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if !s.ReadOnly() {
		t.Error("ReadOnly() = false")
	}
	if s.Size() != 1 {
		t.Errorf("size = %d", s.Size())
	}
	if s.Path() == "" || s.Image() == nil {
		t.Error("missing path or image")
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestSessionOpenErrors(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing.bin"), Options{}); err == nil {
		t.Fatal("expected error for missing file")
	}
}
