package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func tempHexFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseHexFlags(t *testing.T) {
	opts, err := parseHexFlags([]string{"lib.so", "-c", "info", "--read-only", "-y", "-c", "read 0 4"})
	if err != nil {
		t.Fatalf("parseHexFlags: %v", err)
	}
	if opts.path != "lib.so" || !opts.readOnly || !opts.yes || len(opts.commands) != 2 {
		t.Fatalf("opts = %+v", opts)
	}

	if opts, err := parseHexFlags([]string{"-h"}); err != nil || !opts.help {
		t.Fatalf("help: opts=%+v err=%v", opts, err)
	}

	for _, args := range [][]string{
		{"file", "-c"},      // -c without value
		{"file", "--bogus"}, // unknown option
		{"one", "two"},      // two files
	} {
		if _, err := parseHexFlags(args); err == nil {
			t.Errorf("parseHexFlags(%v): expected error", args)
		}
	}

	// Missing file is a usage error at the command layer.
	if err := handleHex(context.Background(), []string{"-c", "info"}); !errors.Is(err, errUsage) {
		t.Fatalf("handleHex without file = %v, want errUsage", err)
	}
}

func TestRunHexBatch(t *testing.T) {
	path := tempHexFile(t, []byte("0123456789"))
	var out bytes.Buffer

	// `exit` stops the batch, so the bogus command after it never runs.
	err := runHex(context.Background(), hexOptions{
		path:     path,
		commands: []string{"info", "read 0x0 4", "exit", "frobnicate"},
	}, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("runHex: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "format:    raw") || !strings.Contains(got, "|0123|") {
		t.Fatalf("batch output:\n%s", got)
	}
}

func TestRunHexBatchFailFast(t *testing.T) {
	path := tempHexFile(t, []byte("0123456789"))
	var out bytes.Buffer
	err := runHex(context.Background(), hexOptions{
		path:     path,
		commands: []string{"read 0x1000"},
	}, strings.NewReader(""), &out)
	if err == nil || !strings.Contains(err.Error(), "read 0x1000") {
		t.Fatalf("fail-fast error = %v", err)
	}
}

func TestRunHexBatchApplyYesAndPrompt(t *testing.T) {
	// --yes skips the prompt.
	path := tempHexFile(t, make([]byte, 4))
	var out bytes.Buffer
	err := runHex(context.Background(), hexOptions{
		path:     path,
		commands: []string{"patch 0x1 aa", "apply"},
		yes:      true,
	}, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("apply --yes: %v", err)
	}
	if data, _ := os.ReadFile(path); data[1] != 0xaa {
		t.Fatalf("apply --yes did not write: % x", data)
	}

	// Without --yes the batch prompt reads stdin.
	path2 := tempHexFile(t, make([]byte, 4))
	var out2 bytes.Buffer
	err = runHex(context.Background(), hexOptions{
		path:     path2,
		commands: []string{"patch 0x1 bb", "apply"},
	}, strings.NewReader("y\n"), &out2)
	if err != nil {
		t.Fatalf("apply prompt: %v", err)
	}
	if data, _ := os.ReadFile(path2); data[1] != 0xbb {
		t.Fatalf("apply prompt did not write: % x", data)
	}
	if !strings.Contains(out2.String(), "[y/N]") {
		t.Fatalf("batch prompt missing:\n%s", out2.String())
	}
}

func TestReplInteractiveSession(t *testing.T) {
	path := tempHexFile(t, []byte("0123456789"))
	var out bytes.Buffer

	err := runHex(context.Background(), hexOptions{path: path},
		strings.NewReader("goto 0x2\nread 0x0 2\nexit\n"), &out)
	if err != nil {
		t.Fatalf("repl: %v", err)
	}
	got := out.String()
	for _, want := range []string{"DeStruct hex:", "=> f:0x00000002", "|01|", "> "} {
		if !strings.Contains(got, want) {
			t.Errorf("repl output missing %q:\n%s", want, got)
		}
	}
}

func TestReplApplyConfirmationSharesInput(t *testing.T) {
	path := tempHexFile(t, make([]byte, 4))
	var out bytes.Buffer

	err := runHex(context.Background(), hexOptions{path: path},
		strings.NewReader("patch 0x1 aa\napply\ny\nexit\n"), &out)
	if err != nil {
		t.Fatalf("repl apply: %v", err)
	}
	if data, _ := os.ReadFile(path); data[1] != 0xaa {
		t.Fatalf("repl apply did not write: % x", data)
	}
	got := out.String()
	if !strings.Contains(got, "[y/N]") || !strings.Contains(got, "applied 1 patch(es)") {
		t.Fatalf("repl apply output:\n%s", got)
	}
}

func TestReplEOFDiscardsDirtyStaging(t *testing.T) {
	path := tempHexFile(t, make([]byte, 4))
	var out bytes.Buffer

	err := runHex(context.Background(), hexOptions{path: path},
		strings.NewReader("patch 0x1 aa\n"), &out)
	if err != nil {
		t.Fatalf("repl EOF: %v", err)
	}
	if data, _ := os.ReadFile(path); data[1] != 0 {
		t.Fatal("EOF applied staged patches")
	}
	if !strings.Contains(out.String(), "staged patches discarded") {
		t.Fatalf("missing discard warning:\n%s", out.String())
	}
}

// notifyWriter closes ready on first write so a test can wait for the
// REPL's signal handler + banner without racing its output buffer.
type notifyWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	once  sync.Once
	ready chan struct{}
}

func newNotifyWriter() *notifyWriter {
	return &notifyWriter{ready: make(chan struct{})}
}

func (w *notifyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.once.Do(func() { close(w.ready) })
	return w.buf.Write(p)
}

func TestReplCtrlCAtPromptExits(t *testing.T) {
	path := tempHexFile(t, []byte("0123456789"))
	out := newNotifyWriter()

	pr, pw := io.Pipe()
	defer pw.Close()

	done := make(chan error, 1)
	go func() {
		done <- runHex(context.Background(), hexOptions{path: path}, pr, out)
	}()

	select {
	case <-out.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("REPL never started")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("REPL returned %v after SIGINT", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("REPL did not exit on SIGINT at the prompt")
	}
}
