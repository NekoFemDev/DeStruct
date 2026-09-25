// Package atomicfile writes files atomically: output goes to a temporary
// file in the destination directory, is synced and closed, and only then
// renamed over the final path. A crash or write error leaves the previous
// file, if any, untouched.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// File is an in-progress atomic write. Create starts it, Commit finishes it,
// and Abort discards it. Callers must call exactly one of Commit or Abort;
// Abort is a no-op after Commit, so `defer f.Abort()` is safe around a
// conditional Commit.
type File struct {
	path string
	perm os.FileMode
	tmp  *os.File
	done bool
}

// Create opens a temporary file next to path and returns a writer for it.
// The destination itself is not created or replaced until Commit.
func Create(path string, perm os.FileMode) (*File, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, err
	}
	return &File{path: path, perm: perm, tmp: tmp}, nil
}

func (f *File) Write(p []byte) (int, error)       { return f.tmp.Write(p) }
func (f *File) WriteString(s string) (int, error) { return f.tmp.WriteString(s) }

// Commit flushes the temporary file to stable storage, closes it, and
// renames it over the destination path.
func (f *File) Commit() error {
	if f.done {
		return fmt.Errorf("atomicfile: %s already finished", f.path)
	}
	f.done = true
	if err := f.tmp.Sync(); err != nil {
		f.tmp.Close()
		os.Remove(f.tmp.Name())
		return err
	}
	if err := f.tmp.Chmod(f.perm); err != nil {
		f.tmp.Close()
		os.Remove(f.tmp.Name())
		return err
	}
	if err := f.tmp.Close(); err != nil {
		os.Remove(f.tmp.Name())
		return err
	}
	if err := os.Rename(f.tmp.Name(), f.path); err != nil {
		os.Remove(f.tmp.Name())
		return err
	}
	return nil
}

// Abort closes and removes the temporary file without touching the
// destination. It is safe to call after Commit.
func (f *File) Abort() {
	if f.done {
		return
	}
	f.done = true
	f.tmp.Close()
	os.Remove(f.tmp.Name())
}

// WriteFile is the atomic equivalent of os.WriteFile.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	f, err := Create(path, perm)
	if err != nil {
		return err
	}
	defer f.Abort()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Commit()
}
