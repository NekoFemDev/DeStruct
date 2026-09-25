package archivelimits

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateLimits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []*zip.File
	}{
		{"oversized entry", []*zip.File{{FileHeader: zip.FileHeader{Name: "bad", UncompressedSize64: MaxEntrySize + 1}}}},
		{"total overflow", []*zip.File{
			{FileHeader: zip.FileHeader{UncompressedSize64: MaxEntrySize}},
			{FileHeader: zip.FileHeader{UncompressedSize64: MaxEntrySize}},
			{FileHeader: zip.FileHeader{UncompressedSize64: MaxEntrySize}},
			{FileHeader: zip.FileHeader{UncompressedSize64: MaxEntrySize}},
			{FileHeader: zip.FileHeader{UncompressedSize64: MaxEntrySize}},
			{FileHeader: zip.FileHeader{UncompressedSize64: MaxEntrySize}},
			{FileHeader: zip.FileHeader{UncompressedSize64: MaxEntrySize}},
			{FileHeader: zip.FileHeader{UncompressedSize64: MaxEntrySize}},
			{FileHeader: zip.FileHeader{UncompressedSize64: 1}},
		}},
		{"file count", make([]*zip.File, MaxFiles+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(tc.files); err == nil {
				t.Fatal("expected archive rejection")
			}
		})
	}
}

func TestOpenRejectsOversizedArchiveBeforeZIPParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(MaxArchiveSize) + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = Open(path)
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected archive size rejection, got %v", err)
	}
}

func TestReadBudgetAccumulatesActualBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "small.jar")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	entry, err := w.Create("a.class")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var budget ReadBudget
	if b, err := budget.ReadEntry(r.File[0]); err != nil || string(b) != "abc" || budget.Total != 3 {
		t.Fatalf("read result %q, total %d, error %v", b, budget.Total, err)
	}
	budget.Total = MaxTotalSize - 2
	if _, err := budget.ReadEntry(r.File[0]); err == nil {
		t.Fatal("expected actual total limit rejection")
	}
}
