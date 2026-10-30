package hermes

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/hermes/parser"
)

const sampleHBCPath = "testdata/sample.hbc"

var sampleAvailable bool

func TestMain(m *testing.M) {
	if _, err := os.Stat(sampleHBCPath); err == nil {
		sampleAvailable = true
	}
	os.Exit(m.Run())
}

func requireSampleData(t *testing.T) []byte {
	t.Helper()
	if !sampleAvailable {
		t.Skipf("%s not present; skipping fixture test", sampleHBCPath)
	}
	data, err := os.ReadFile(sampleHBCPath)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

// TestDisassembleAssembleFacade exercises the top-level one-shot API on
// the fixture: full disassembly round-trips byte-identically.
func TestDisassembleAssembleFacade(t *testing.T) {
	data := requireSampleData(t)

	text, err := Disassemble(data)
	if err != nil {
		t.Fatalf("Disassemble: %v", err)
	}
	out, err := Assemble(text, data)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(out) != len(data) {
		t.Fatalf("round trip length %d, want %d", len(out), len(data))
	}
	for i := range out {
		if out[i] != data[i] {
			t.Fatalf("round trip differs at byte %d", i)
		}
	}
}

// TestReplSession drives the interactive patcher in-memory through a
// typical edit, then verifies the saved file.
func TestReplSession(t *testing.T) {
	data := requireSampleData(t)

	var out strings.Builder
	r, err := NewRepl(data, sampleHBCPath, &out)
	if err != nil {
		t.Fatalf("NewRepl: %v", err)
	}

	exec := func(cmd string) {
		t.Helper()
		if _, err := r.Exec(cmd); err != nil {
			t.Fatalf("Exec(%q): %v\noutput so far:\n%s", cmd, err, out.String())
		}
	}

	exec("i")
	if !strings.Contains(out.String(), "bytecode version: 96") {
		t.Fatalf("info output unexpected:\n%s", out.String())
	}

	exec("sf #2")
	exec("pf")
	if got := r.Cursor; got != r.File.Functions[2].Offset {
		t.Fatalf("sf #2 cursor = 0x%x, want function offset 0x%x", got, r.File.Functions[2].Offset)
	}

	// Locate a Mov in function #2 and seek the cursor there.
	f := &r.File.Functions[2]
	movRel := uint32(0xFFFFFFFF)
	for i := range f.Instructions {
		if f.Instructions[i].Name() == "Mov" {
			movRel = f.Instructions[i].Offset
			break
		}
	}
	if movRel == 0xFFFFFFFF {
		t.Skip("fixture function #2 has no Mov")
	}
	exec(fmt.Sprintf("s 0x%x", f.Offset+movRel))
	exec("pd 2")
	if !strings.Contains(out.String(), "<Mov>") {
		t.Fatalf("pd output lacks the Mov instruction:\n%s", out.String())
	}

	exec("wi Mov Reg8: 3, Reg8: 1")
	if !r.Dirty {
		t.Fatal("session not marked dirty after wi")
	}

	// Verify the in-memory view reflects the edit.
	var got uint64 = ^uint64(0)
	for i := range r.File.Functions[2].Instructions {
		in := &r.File.Functions[2].Instructions[i]
		if in.Name() == "Mov" && in.Offset == movRel {
			got = in.Operand(0)
		}
	}
	if got != 3 {
		t.Fatalf("patched Mov operand = %d, want 3", got)
	}

	// Save and verify the file on disk parses with the edit and a valid
	// SHA1 footer.
	outPath := filepath.Join(t.TempDir(), "patched.hbc")
	quit, err := r.Exec("wq " + outPath)
	if err != nil {
		t.Fatalf("wq: %v", err)
	}
	if !quit {
		t.Fatal("wq did not end the session")
	}

	saved, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading saved file: %v", err)
	}
	m, err := parser.Parse(saved)
	if err != nil {
		t.Fatalf("saved file does not parse: %v", err)
	}
	if err := parser.Decode(m); err != nil {
		t.Fatalf("saved file does not decode: %v", err)
	}
	found := false
	for i := range m.Functions[2].Instructions {
		in := &m.Functions[2].Instructions[i]
		if in.Name() == "Mov" && in.Offset == movRel {
			if in.Operand(0) != 3 {
				t.Fatalf("saved Mov operand = %d, want 3", in.Operand(0))
			}
			found = true
		}
	}
	if !found {
		t.Fatal("Mov not found in saved file's function #2")
	}
}

// TestReplRawWrite checks wx overwrites bytes in place and the session
// reflects them after re-parsing.
func TestReplRawWrite(t *testing.T) {
	data := requireSampleData(t)

	var out strings.Builder
	r, err := NewRepl(data, sampleHBCPath, &out)
	if err != nil {
		t.Fatalf("NewRepl: %v", err)
	}

	f := &r.File.Functions[2]
	// Rewrite the first instruction's opcode byte with its own value:
	// a no-op edit that exercises the wx path and the re-parse.
	b := r.Data[f.Offset]
	if _, err := r.Exec(fmt.Sprintf("s 0x%x", f.Offset)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Exec(fmt.Sprintf("wx %02x", b)); err != nil {
		t.Fatalf("wx: %v\n%s", err, out.String())
	}
	if !r.Dirty {
		t.Fatal("session not marked dirty after wx")
	}
	if got := r.Data[f.Offset]; got != b {
		t.Fatalf("byte changed to 0x%02x, want 0x%02x", got, b)
	}
	if !strings.Contains(out.String(), "wrote 1 bytes") {
		t.Fatalf("wx output unexpected:\n%s", out.String())
	}
}
