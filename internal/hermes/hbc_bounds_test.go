package hermes

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseRejectsOversizedTables(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*Header)
	}{
		{"functions", func(h *Header) { h.FunctionCount = ^uint32(0) }},
		{"string kinds", func(h *Header) { h.StringKindCount = ^uint32(0) }},
		{"identifier hashes", func(h *Header) { h.IdentifierCount = ^uint32(0) }},
		{"small strings", func(h *Header) { h.StringCount = ^uint32(0) }},
		{"overflow strings", func(h *Header) { h.OverflowStringCount = ^uint32(0) }},
		{"string storage", func(h *Header) { h.StringStorageSize = ^uint32(0) }},
		{"literal values", func(h *Header) { h.LiteralValueBufferSize = ^uint32(0) }},
		{"object keys", func(h *Header) { h.ObjKeyBufferSize = ^uint32(0) }},
		{"shape table", func(h *Header) { h.ObjShapeTableCount = ^uint32(0) }},
		{"bigint table", func(h *Header) { h.BigIntCount = ^uint32(0) }},
		{"bigint data", func(h *Header) { h.BigIntStorageSize = ^uint32(0) }},
		{"regexp table", func(h *Header) { h.RegExpCount = ^uint32(0) }},
		{"regexp data", func(h *Header) { h.RegExpStorageSize = ^uint32(0) }},
		{"CJS modules", func(h *Header) { h.CJSModuleCount = ^uint32(0) }},
		{"function sources", func(h *Header) { h.FunctionSourceCount = ^uint32(0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &HBCFile{Header: Header{Magic: headerMagic, Version: 98}, rawData: make([]byte, 256)}
			f.Header.FileLength = uint32(len(f.rawData))
			tc.set(&f.Header)
			f.writeHeaderFields()
			hash := sha1.Sum(f.rawData[:len(f.rawData)-sha1Size])
			copy(f.rawData[len(f.rawData)-sha1Size:], hash[:])
			if _, err := Parse(bytes.NewReader(f.rawData)); err == nil {
				t.Fatal("expected bounds error")
			}
		})
	}
}

func TestFunctionMetadataBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header []byte
	}{
		{"large header pointer", func() []byte {
			b := make([]byte, 12)
			binary.LittleEndian.PutUint32(b, 0x1ffffff)
			b[11] = 0x20
			return b
		}()},
		{"exception count", func() []byte {
			b := make([]byte, 20)
			b[11] = 0x08
			binary.LittleEndian.PutUint32(b[12:], ^uint32(0))
			return b
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &HBCFile{Header: Header{Version: 98, FunctionCount: 1}}
			if err := f.readFunctions(bytes.NewReader(tc.header)); err == nil {
				t.Fatal("expected bounds error")
			}
		})
	}
}

func TestStringKindRunBounds(t *testing.T) {
	f := &HBCFile{Header: Header{Version: 98, StringCount: 1, StringKindCount: 1}}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ^uint32(0))
	if err := f.readStringKinds(bytes.NewReader(b)); err == nil || !strings.Contains(err.Error(), "string kind run") {
		t.Fatalf("expected string kind run error, got %v", err)
	}
}

func TestCodeBounds(t *testing.T) {
	f := &HBCFile{rawData: make([]byte, 8), FunctionHeaders: []SmallFunctionHeader{{Offset: ^uint32(0), BytecodeSizeInBytes: 8}}}
	if code := f.getCode(0); code != nil {
		t.Fatalf("unexpected code %v", code)
	}
	if code := f.getCode(-1); code != nil {
		t.Fatalf("unexpected code %v", code)
	}
	if err := f.SetCode(0, []byte{1}); err == nil {
		t.Fatal("expected bounds error")
	}
}
