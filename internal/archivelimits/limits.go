package archivelimits

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
)

// Limits are shared by JAR, APK and Flutter APK processing. Sizes are bytes.
const (
	MaxArchiveSize uint64 = 1 << 30 // 1 GiB compressed archive
	MaxEntrySize   uint64 = 256 << 20
	MaxTotalSize   uint64 = 2 << 30 // sum of uncompressed entries
	MaxFiles              = 200000
	MaxClasses            = 100000
)

// Open rejects oversized archives before zip.OpenReader parses their index.
// Validate checks the entire central directory, including entries that the
// caller does not plan to extract.
func Open(path string) (*zip.ReadCloser, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() < 0 || uint64(info.Size()) > MaxArchiveSize {
		return nil, fmt.Errorf("archive exceeds %d-byte size limit", MaxArchiveSize)
	}
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	if err := Validate(r.File); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// Validate checks declared sizes using subtraction to avoid overflow. ReadEntry
// independently enforces actual decompressed size, even for dishonest headers.
func Validate(files []*zip.File) error {
	if len(files) > MaxFiles {
		return fmt.Errorf("archive exceeds %d-file limit", MaxFiles)
	}
	var total uint64
	for _, f := range files {
		if f.UncompressedSize64 > MaxEntrySize {
			return fmt.Errorf("archive entry %q exceeds %d-byte limit", f.Name, MaxEntrySize)
		}
		if f.UncompressedSize64 > MaxTotalSize-total {
			return fmt.Errorf("archive exceeds %d-byte uncompressed limit", MaxTotalSize)
		}
		total += f.UncompressedSize64
	}
	return nil
}

// ReadEntry limits the real decompressed bytes, regardless of ZIP metadata.
func ReadEntry(f *zip.File) ([]byte, error) {
	if f.UncompressedSize64 > MaxEntrySize {
		return nil, fmt.Errorf("entry %q exceeds %d-byte limit", f.Name, MaxEntrySize)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, int64(MaxEntrySize)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) > MaxEntrySize {
		return nil, fmt.Errorf("entry %q exceeds %d-byte limit", f.Name, MaxEntrySize)
	}
	return b, nil
}

// ReadBudget counts actual decompressed bytes across entries, not just sizes
// claimed in the central directory.
type ReadBudget struct{ Total uint64 }

func (b *ReadBudget) ReadEntry(f *zip.File) ([]byte, error) {
	if b.Total > MaxTotalSize || f.UncompressedSize64 > MaxTotalSize-b.Total {
		return nil, fmt.Errorf("archive exceeds %d-byte uncompressed limit", MaxTotalSize)
	}
	data, err := ReadEntry(f)
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) > MaxTotalSize-b.Total {
		return nil, fmt.Errorf("archive exceeds %d-byte uncompressed limit", MaxTotalSize)
	}
	b.Total += uint64(len(data))
	return data, nil
}
