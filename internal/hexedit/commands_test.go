package hexedit

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func openBufferSession(t *testing.T, data []byte) (*Session, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	s, err := Open(writeTemp(t, data), Options{Out: &buf})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, &buf
}

func execLine(t *testing.T, s *Session, line string) (bool, error) {
	t.Helper()
	return s.Exec(context.Background(), line)
}

func TestExecRead(t *testing.T) {
	data := []byte("0123456789abcdefghij")
	s, buf := openBufferSession(t, data)

	if quit, err := execLine(t, s, "read 0x0 8"); err != nil || quit {
		t.Fatalf("read: quit=%v err=%v", quit, err)
	}
	out := buf.String()
	if !strings.Contains(out, "f:0x00000000") || !strings.Contains(out, "|01234567|") {
		t.Fatalf("read output unexpected:\n%s", out)
	}

	buf.Reset()
	if _, err := execLine(t, s, "goto 0x10"); err != nil {
		t.Fatalf("goto: %v", err)
	}
	buf.Reset()
	if _, err := execLine(t, s, "read"); err != nil {
		t.Fatalf("read at cursor: %v", err)
	}
	if got := buf.String(); !strings.Contains(got, "f:0x00000010") || !strings.Contains(got, "|ghij|") {
		t.Fatalf("cursor read output unexpected:\n%s", got)
	}
}

func TestExecReadErrors(t *testing.T) {
	s, _ := openBufferSession(t, make([]byte, 0x20))
	for _, line := range []string{
		"read 0x1000",     // beyond EOF
		"read 0x0 0",      // zero length
		"read 0x0 999999", // exceeds max
		"read 0x0 1 2",    // extra argument
		"read zz",         // bad address
		"read v:0x0",      // no ELF metadata
	} {
		if _, err := execLine(t, s, line); err == nil {
			t.Errorf("%q: expected error", line)
		}
	}
}

func TestExecGoto(t *testing.T) {
	s, buf := openBufferSession(t, make([]byte, 0x20))
	if _, err := execLine(t, s, "goto 0x5"); err != nil {
		t.Fatalf("goto: %v", err)
	}
	if !strings.Contains(buf.String(), "=> f:0x00000005") {
		t.Fatalf("goto output: %q", buf.String())
	}
	if s.Cursor().Value != 5 {
		t.Fatalf("cursor = %v", s.Cursor())
	}
	if _, err := execLine(t, s, "goto 0x100"); err == nil {
		t.Fatal("goto beyond EOF: expected error")
	}
	if _, err := execLine(t, s, "goto"); err == nil {
		t.Fatal("goto without argument: expected error")
	}
}

func TestExecInfoRaw(t *testing.T) {
	s, buf := openBufferSession(t, []byte{1, 2, 3, 4})
	if _, err := execLine(t, s, "info"); err != nil {
		t.Fatalf("info: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "format:    raw") {
		t.Fatalf("raw info output:\n%s", out)
	}
	if !strings.Contains(out, "size:      4 bytes (0x4)") {
		t.Fatalf("size line missing:\n%s", out)
	}
}

func TestExecInfoELF(t *testing.T) {
	var buf bytes.Buffer
	s, err := Open(elfFixture, Options{Out: &buf})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if _, err := execLine(t, s, "info"); err != nil {
		t.Fatalf("info: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"ELF 64-bit LSB", "ARM64", "sections:", ".text", "entry:"} {
		if !strings.Contains(out, want) {
			t.Errorf("info output missing %q:\n%s", want, out)
		}
	}
}

func TestExecQuitAndHelp(t *testing.T) {
	s, buf := openBufferSession(t, []byte{0})
	for _, line := range []string{"q", "quit", "exit", "q!"} {
		quit, err := execLine(t, s, line)
		if err != nil || !quit {
			t.Errorf("%q: quit=%v err=%v", line, quit, err)
		}
	}

	buf.Reset()
	if quit, err := execLine(t, s, "help"); err != nil || quit {
		t.Fatalf("help: quit=%v err=%v", quit, err)
	}
	out := buf.String()
	for _, want := range []string{"read [addr] [len]", "goto", "v:0x1234", "f:0x1234"} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %q:\n%s", want, out)
		}
	}
}

func TestExecEmptyAndUnknown(t *testing.T) {
	s, _ := openBufferSession(t, []byte{0})
	if quit, err := execLine(t, s, "   "); err != nil || quit {
		t.Fatalf("blank line: quit=%v err=%v", quit, err)
	}
	if _, err := execLine(t, s, "frobnicate"); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unknown command error = %v", err)
	}
	if _, err := execLine(t, s, "info extra"); err == nil {
		t.Fatal("info with argument: expected error")
	}
}
