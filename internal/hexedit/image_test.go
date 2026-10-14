package hexedit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/destruct/destruct/internal/native"
)

// elfFixture is the NDK-built AArch64 shared object already used by
// internal/native's tests.
const elfFixture = "../../test/liblun.so"

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenImageRaw(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 'h', 'i'}
	img, err := OpenImage(writeTemp(t, data))
	if err != nil {
		t.Fatalf("OpenImage: %v", err)
	}
	defer img.Close()

	if img.Format != FormatRaw {
		t.Errorf("format = %q, want raw", img.Format)
	}
	if img.Size != int64(len(data)) {
		t.Errorf("size = %d, want %d", img.Size, len(data))
	}
	if img.ELF() != nil {
		t.Error("raw file produced ELF metadata")
	}
	if got := string(img.Bytes()); got != string(data) {
		t.Errorf("bytes = %q", got)
	}
	if _, ok := img.FileToVA(0); ok {
		t.Error("raw file advertised a VA mapping")
	}
	if _, ok := img.VAToFile(0); ok {
		t.Error("raw file advertised a VA mapping")
	}
	if err := img.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestOpenImageELF(t *testing.T) {
	img, err := OpenImage(elfFixture)
	if err != nil {
		t.Fatalf("OpenImage: %v", err)
	}
	defer img.Close()

	if img.Format != FormatELF {
		t.Fatalf("format = %q, want ELF", img.Format)
	}
	elf := img.ELF()
	if elf == nil {
		t.Fatalf("no ELF metadata (err: %v)", img.ELFError())
	}
	if img.Arch != native.ArchARM64 {
		t.Errorf("arch = %d, want ARM64", img.Arch)
	}

	// Every executable section must round-trip file offset <-> VA.
	checked := 0
	for i := range elf.Sections {
		s := &elf.Sections[i]
		if s.Flags&native.SHF_EXECINSTR == 0 || s.Size == 0 {
			continue
		}
		off := s.Offset + 16
		va, ok := img.FileToVA(off)
		if !ok {
			t.Errorf("FileToVA(0x%x) not found in executable section %s", off, s.SynthName)
			continue
		}
		if want := s.Addr + 16; va != want {
			t.Errorf("FileToVA(0x%x) = 0x%x, want 0x%x", off, va, want)
		}
		back, ok := img.VAToFile(va)
		if !ok || back != off {
			t.Errorf("VAToFile(0x%x) = 0x%x, %v; want 0x%x", va, back, ok, off)
		}
		if _, ok := img.CodeSectionAtFile(off); !ok {
			t.Errorf("CodeSectionAtFile(0x%x) not found", off)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("fixture has no executable sections")
	}
}

func TestOpenImageCorruptELF(t *testing.T) {
	data := make([]byte, 64)
	copy(data, "\x7fELF")
	path := writeTemp(t, data)
	img, err := OpenImage(path)
	if err != nil {
		t.Fatalf("OpenImage: %v", err)
	}
	defer img.Close()

	if img.Format != FormatELF {
		t.Errorf("format = %q, want ELF", img.Format)
	}
	if img.ELF() != nil || img.ELFError() == nil {
		t.Errorf("corrupt ELF: elf=%v err=%v", img.ELF(), img.ELFError())
	}
	if img.Size != 64 {
		t.Errorf("size = %d", img.Size)
	}
}

func TestOpenImageEmpty(t *testing.T) {
	img, err := OpenImage(writeTemp(t, nil))
	if err != nil {
		t.Fatalf("OpenImage: %v", err)
	}
	defer img.Close()
	if img.Size != 0 || len(img.Bytes()) != 0 {
		t.Errorf("empty file: size=%d bytes=%d", img.Size, len(img.Bytes()))
	}
}

func TestOpenImageDirectory(t *testing.T) {
	if _, err := OpenImage(t.TempDir()); err == nil {
		t.Fatal("expected error for directory")
	}
}

func TestOpenImageSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.bin")
	if err := os.WriteFile(target, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	img, err := OpenImage(link)
	if err != nil {
		t.Fatalf("OpenImage: %v", err)
	}
	defer img.Close()
	if img.Path != target {
		t.Errorf("path = %q, want resolved %q", img.Path, target)
	}
}
