package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func onlyRegularFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestWriteFileReplacesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteFile(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("content = %q, want %q", got, "new")
	}
	if names := onlyRegularFiles(t, dir); len(names) != 1 {
		t.Fatalf("temporary files left behind: %v", names)
	}
}

func TestAbortKeepsExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := Create(path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("partial"); err != nil {
		t.Fatal(err)
	}
	f.Abort()
	f.Abort() // second call must be a no-op

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("abort modified destination: %q", got)
	}
	if names := onlyRegularFiles(t, dir); len(names) != 1 {
		t.Fatalf("temporary files left behind: %v", names)
	}
}

func TestCommitCreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.txt")

	f, err := Create(path, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("hello"); err != nil {
		t.Fatal(err)
	}
	if err := f.Commit(); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("content = %q", got)
	}
	if names := onlyRegularFiles(t, dir); len(names) != 1 {
		t.Fatalf("temporary files left behind: %v", names)
	}
}
