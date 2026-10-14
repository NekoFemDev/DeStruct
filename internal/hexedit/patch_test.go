package hexedit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openInputSession(t *testing.T, path, input string, opts Options) (*Session, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	opts.Out = &buf
	if opts.In == nil {
		opts.In = strings.NewReader(input)
	}
	s, err := Open(path, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, &buf
}

func TestPatchStageDiffDropClear(t *testing.T) {
	s, buf := openBufferSession(t, make([]byte, 0x20))

	if _, err := execLine(t, s, "patch 0x4 aa bb"); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if !strings.Contains(buf.String(), "#0 f:0x00000004  00 00 -> aa bb") {
		t.Fatalf("patch output:\n%s", buf.String())
	}

	// Reads and searches see staged bytes; the row is marked staged.
	buf.Reset()
	if _, err := execLine(t, s, "read 0x4 2"); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.Contains(out, "aa bb") || !strings.Contains(out, "~f:0x00000000") {
		t.Fatalf("read after patch:\n%s", out)
	}
	buf.Reset()
	if _, err := execLine(t, s, "search aa"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "f:0x00000004") {
		t.Fatalf("search after patch:\n%s", buf.String())
	}

	buf.Reset()
	if _, err := execLine(t, s, "diff"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"; 1 staged patch(es), 2 byte(s)", "#0 f:0x00000004", "orig: 00 00", "new: aa bb"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff missing %q:\n%s", want, out)
		}
	}

	buf.Reset()
	if _, err := execLine(t, s, "drop 0"); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if !strings.Contains(buf.String(), "dropped patch #0 (0 remaining)") {
		t.Fatalf("drop output:\n%s", buf.String())
	}
	buf.Reset()
	if _, err := execLine(t, s, "read 0x4 2"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "aa bb") {
		t.Fatal("dropped patch still visible")
	}
	buf.Reset()
	if _, err := execLine(t, s, "diff"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no staged patches") {
		t.Fatalf("diff after drop:\n%s", buf.String())
	}

	if _, err := execLine(t, s, "patch 0x8 11"); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if _, err := execLine(t, s, "clear"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "cleared 1 staged patch(es)") {
		t.Fatalf("clear output:\n%s", buf.String())
	}

	ro, _ := openInputSession(t, writeTemp(t, make([]byte, 4)), "", Options{ReadOnly: true})
	if _, err := execLine(t, ro, "patch 0x0 aa"); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only patch error = %v", err)
	}
}

func TestPatchOverlapLaterWins(t *testing.T) {
	s, buf := openBufferSession(t, make([]byte, 0x10))
	if _, err := execLine(t, s, "patch 0x4 aa bb"); err != nil {
		t.Fatal(err)
	}
	if _, err := execLine(t, s, "patch 0x5 cc"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "overlaps staged patch #0") {
		t.Fatalf("missing overlap warning:\n%s", buf.String())
	}
	buf.Reset()
	if _, err := execLine(t, s, "read 0x4 2"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "aa cc") {
		t.Fatalf("later patch did not win:\n%s", buf.String())
	}
}

func TestPatchErrors(t *testing.T) {
	s, _ := openBufferSession(t, make([]byte, 0x10))
	for _, line := range []string{
		"patch",           // missing args
		"patch 0x0",       // no bytes
		"patch 0x0 a",     // odd digits
		"patch 0x0 zz",    // invalid hex
		"patch 0x10 aa",   // at EOF
		"patch 0xf aa bb", // extends past EOF
		"patch 0x1000 aa", // beyond EOF
	} {
		if _, err := execLine(t, s, line); err == nil {
			t.Errorf("%q: expected error", line)
		}
	}
}

func TestApplyDeclineThenConfirm(t *testing.T) {
	path := writeTemp(t, make([]byte, 0x20))
	s, buf := openInputSession(t, path, "n\n", Options{})

	if _, err := execLine(t, s, "patch 0x4 aa"); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if _, err := execLine(t, s, "apply"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "[y/N]") || !strings.Contains(out, "cancelled") {
		t.Fatalf("decline output:\n%s", out)
	}
	if data, _ := os.ReadFile(path); data[4] != 0 {
		t.Fatal("declined apply wrote to the file")
	}

	// Second session confirms; apply commits, clears staging and reopens.
	s2, buf2 := openInputSession(t, path, "y\n", Options{})
	if _, err := execLine(t, s2, "patch 0x4 aa"); err != nil {
		t.Fatal(err)
	}
	if _, err := execLine(t, s2, "apply"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if out := buf2.String(); !strings.Contains(out, "staged patch(es)") || !strings.Contains(out, "applied 1 patch(es)") {
		t.Fatalf("apply output:\n%s", out)
	}
	if data, _ := os.ReadFile(path); data[4] != 0xaa {
		t.Fatalf("file after apply: % x", data[:8])
	}
	buf2.Reset()
	if _, err := execLine(t, s2, "read 0x4 1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf2.String(), " aa") {
		t.Fatalf("reopened session does not show patched bytes:\n%s", buf2.String())
	}
	if s2.dirty() {
		t.Fatal("staging not cleared after apply")
	}
}

func TestApplyYesSkipsPrompt(t *testing.T) {
	path := writeTemp(t, make([]byte, 8))
	s, buf := openInputSession(t, path, "", Options{Yes: true})
	if _, err := execLine(t, s, "patch 0x0 ff"); err != nil {
		t.Fatal(err)
	}
	if _, err := execLine(t, s, "apply"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if strings.Contains(buf.String(), "[y/N]") {
		t.Fatalf("--yes still prompted:\n%s", buf.String())
	}
	if data, _ := os.ReadFile(path); data[0] != 0xff {
		t.Fatal("apply --yes did not write")
	}
}

func TestApplyConflictGuard(t *testing.T) {
	path := writeTemp(t, make([]byte, 8))
	s, _ := openInputSession(t, path, "", Options{Yes: true})
	if _, err := execLine(t, s, "patch 0x0 ff"); err != nil {
		t.Fatal(err)
	}
	// External modification (size change) must be refused.
	if err := os.WriteFile(path, make([]byte, 9), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := execLine(t, s, "apply"); err == nil || !strings.Contains(err.Error(), "changed since") {
		t.Fatalf("conflict guard error = %v", err)
	}
	if !s.dirty() {
		t.Fatal("patches dropped despite refused apply")
	}
}

func TestSaveToNewAndExistingPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "src.bin")
	if err := os.WriteFile(path, make([]byte, 0x10), 0o600); err != nil {
		t.Fatal(err)
	}

	s, buf := openInputSession(t, path, "", Options{})
	if _, err := execLine(t, s, "patch 0x2 11 22"); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "out.bin")
	if _, err := execLine(t, s, "save "+target); err != nil {
		t.Fatalf("save: %v", err)
	}
	if !strings.Contains(buf.String(), "saved 1 patch(es)") {
		t.Fatalf("save output:\n%s", buf.String())
	}
	if data, _ := os.ReadFile(target); data[2] != 0x11 || data[3] != 0x22 {
		t.Fatalf("saved file wrong: % x", data)
	}
	if data, _ := os.ReadFile(path); data[2] != 0 {
		t.Fatal("save modified the original file")
	}
	if s.dirty() {
		t.Fatal("staging not cleared after save")
	}

	// Saving over an existing file asks first; declining leaves it alone.
	s2, buf2 := openInputSession(t, path, "n\n", Options{})
	if _, err := execLine(t, s2, "patch 0x0 ee"); err != nil {
		t.Fatal(err)
	}
	if _, err := execLine(t, s2, "save "+target); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf2.String(), "cancelled") {
		t.Fatalf("overwrite decline output:\n%s", buf2.String())
	}
	if data, _ := os.ReadFile(target); data[0] == 0xee {
		t.Fatal("declined overwrite wrote")
	}
}

func TestPatchByVAOnELFCopy(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(elfFixture)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "copy.so")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	s, _ := openInputSession(t, path, "", Options{})
	sec := codeSection(t, s)
	va := sec.Addr + 8

	if _, err := execLine(t, s, fmt.Sprintf("patch v:0x%x 00000000", va)); err != nil {
		t.Fatalf("patch by VA: %v", err)
	}
	if s.patches[0].Off != int64(sec.Offset+8) {
		t.Fatalf("VA patch staged at %d, want %d", s.patches[0].Off, sec.Offset+8)
	}

	target := filepath.Join(dir, "patched.so")
	if _, err := execLine(t, s, "save "+target); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if out[sec.Offset+8+uint64(i)] != 0 {
			t.Fatalf("saved patch byte %d = %02x, want 00", i, out[sec.Offset+8+uint64(i)])
		}
	}
	if len(out) != len(src) {
		t.Fatalf("saved size %d, want %d", len(out), len(src))
	}
}

func TestQuitRefusesWhileDirty(t *testing.T) {
	s, buf := openBufferSession(t, make([]byte, 0x10))
	if _, err := execLine(t, s, "patch 0x0 aa"); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	quit, err := execLine(t, s, "q")
	if err != nil || quit {
		t.Fatalf("q with staged patches: quit=%v err=%v", quit, err)
	}
	if !strings.Contains(buf.String(), "staged patches not applied") {
		t.Fatalf("q guard output:\n%s", buf.String())
	}
	if quit, err := execLine(t, s, "q!"); err != nil || !quit {
		t.Fatalf("q!: quit=%v err=%v", quit, err)
	}
	if s.dirty() {
		t.Fatal("q! did not discard staging")
	}
}
