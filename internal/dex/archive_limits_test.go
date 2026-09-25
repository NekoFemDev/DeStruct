package dex

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestAPKArchiveLimitsApplyToCountAndStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversize.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	entry, err := w.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	central := bytes.LastIndex(data, []byte("PK\x01\x02"))
	if central < 0 {
		t.Fatal("missing zip central directory")
	}
	binary.LittleEndian.PutUint32(data[central+24:], 0xffffffff)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CountApkDexClasses(path); err == nil {
		t.Fatal("count accepted oversized entry")
	}
	if err := DecompileApkStreaming(path, nil, nil); err == nil {
		t.Fatal("stream accepted oversized entry")
	}
}
