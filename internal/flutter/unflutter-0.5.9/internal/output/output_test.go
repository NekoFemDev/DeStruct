package output

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/disasm"
)

// TestWriteASMSlashInSymbolName is the regression test for
// "open output/asm/Duration/dyn_-_1435fa4.txt: no such file or directory":
// a slash in a Dart symbol must be folded into the filename, and missing
// directories must be created before the write.
func TestWriteASMSlashInSymbolName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "out") // deliberately not created yet
	if err := WriteASM(root, "Duration/dyn_-_1435fa4", nil, nil); err != nil {
		t.Fatalf("WriteASM: %v", err)
	}

	want := filepath.Join(root, "asm", "Duration_dyn_-_1435fa4.txt")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected file %s: %v", want, err)
	}

	// The slash must not have been interpreted as a directory separator.
	if _, err := os.Stat(filepath.Join(root, "asm", "Duration")); !os.IsNotExist(err) {
		t.Errorf("slash in symbol name created a nested directory (stat err = %v)", err)
	}
}

func TestWriteASMContent(t *testing.T) {
	root := t.TempDir()
	insts := []disasm.Inst{{Addr: 0x1000, Raw: 0xD503201F, Size: 4, Text: "nop"}}
	if err := WriteASM(root, "Owner.Func_1000", insts, nil); err != nil {
		t.Fatalf("WriteASM: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "asm", "Owner.Func_1000.txt"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(data) == 0 {
		t.Errorf("asm file is empty")
	}
}

func TestWriteBinSanitizesAndCreatesDirs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "out")
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	if err := WriteBin(root, "Duration/dyn_-_1435fa4", payload); err != nil {
		t.Fatalf("WriteBin: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "asm", "Duration_dyn_-_1435fa4.bin"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %x, want %x", got, payload)
	}
}

func TestWriteASMSingleCreatesOutputDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "out")
	if err := WriteASMSingle(root, nil, nil); err != nil {
		t.Fatalf("WriteASMSingle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "asm.txt")); err != nil {
		t.Fatalf("expected asm.txt: %v", err)
	}
}
