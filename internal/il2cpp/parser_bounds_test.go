package il2cpp

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestParserRanges(t *testing.T) {
	data := make([]byte, 32)
	for _, tc := range []struct {
		off, size uint64
		valid     bool
	}{
		{28, 4, true}, {32, 0, true}, {33, 0, false},
		{31, 2, false}, {math.MaxUint64, 2, false}, {16, math.MaxUint64, false},
	} {
		_, _, ok := byteRange(data, tc.off, tc.size)
		if ok != tc.valid {
			t.Errorf("byteRange(%d,%d): %v", tc.off, tc.size, ok)
		}
	}
	if _, _, ok := recordRange(data, 0, math.MaxUint64, 8); ok {
		t.Fatal("record multiplication overflow accepted")
	}
	if _, _, ok := recordRange(data, 0, 4, 8); !ok {
		t.Fatal("valid record range rejected")
	}
}

func TestMetadataTableBounds(t *testing.T) {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[8:], 42)
	l := &structLayout{fields: []structField{p("value", 4)}}
	if got := records(data, 8, 4, l, 31); len(got) != 1 || got[0].u32("value") != 42 {
		t.Fatalf("valid record: %v", got)
	}
	for _, tc := range []struct {
		off  uint32
		size int32
	}{
		{math.MaxUint32, 4}, {28, 8}, {8, 5},
	} {
		if got := records(data, tc.off, tc.size, l, 31); got != nil {
			t.Errorf("accepted record table %+v", tc)
		}
		if got := readInt32Array(data, tc.off, tc.size); got != nil {
			t.Errorf("accepted int array %+v", tc)
		}
		if got := readUint32Array(data, tc.off, tc.size); got != nil {
			t.Errorf("accepted uint array %+v", tc)
		}
	}
	m := &Metadata{Data: data, Header: MetadataHeader{Raw: map[string]int64{"stringOffset": int64(math.MaxUint32), "stringLiteralDataOffset": int64(math.MaxUint32)}}, stringCache: make(map[uint32]string), stringLiterals: []record{{b: []byte{8, 0, 0, 0, 8, 0, 0, 0}, l: &layoutStringLiteral}}}
	if got := m.GetStringFromIndex(math.MaxUint32); got != "" {
		t.Fatalf("invalid string: %q", got)
	}
	if got := m.GetStringLiteralFromIndex(0); got != "" {
		t.Fatalf("invalid literal: %q", got)
	}
}

func TestELFUntrustedRanges(t *testing.T) {
	data := make([]byte, 128)
	e := &elfFile{data: data, order: binary.LittleEndian, is64: true, phdrs: []elfPhdr{{typ: ptLoad, off: 64, vaddr: 0x1000, filesz: 64, memsz: 64}}}
	ic := &IL2CPP{ELF: e, Version: 31}
	if got := ic.readU64s(0x1038, 2); got != nil {
		t.Fatalf("truncated array allocated: %v", got)
	}
	if got, ok := ic.readU64sStrict(0x1038, 2); ok || got != nil {
		t.Fatal("strict array accepted truncation")
	}
	if got := ic.readU32s(0x103c, 2); got != nil {
		t.Fatalf("truncated uint array: %v", got)
	}
	if got := recordsRaw(ic, 0x1038, 2, &layoutMethodSpec); got != nil {
		t.Fatalf("truncated records: %v", got)
	}
	if got := ic.readU64s(0x1000, math.MaxInt64); got != nil {
		t.Fatal("huge count accepted")
	}
	if got := e.readBytes(math.MaxInt, 10); got != nil {
		t.Fatal("overflowed slice accepted")
	}
	if got := e.readCString(math.MaxUint64); got != "" {
		t.Fatal("overflowed string address accepted")
	}
	e.phdrs[0].vaddr = math.MaxUint64 - 4
	if _, ok := e.mapVATR(3); ok {
		t.Fatal("wrapped virtual range accepted")
	}
	e.phdrs[0].vaddr = 0x1000
	e.phdrs[0].filesz = math.MaxUint64
	if len(e.dataSections()) != 0 {
		t.Fatal("wrapped segment size accepted")
	}
}

func TestELFHeaderAndDynamicOverflow(t *testing.T) {
	data := make([]byte, 128)
	copy(data, "\x7fELF")
	data[4], data[5] = 2, 1
	binary.LittleEndian.PutUint64(data[0x20:], math.MaxUint64-4)
	binary.LittleEndian.PutUint16(data[0x36:], 56)
	binary.LittleEndian.PutUint16(data[0x38:], 2)
	if _, err := newELF(data); err == nil {
		t.Fatal("overflowed program header table accepted")
	}
	e := &elfFile{data: data, order: binary.LittleEndian, is64: true, phdrs: []elfPhdr{{typ: ptDynamic, off: math.MaxUint64 - 4, filesz: 32}}}
	e.parseDynamic()
	if len(e.dyn) != 0 {
		t.Fatal("overflowed dynamic range accepted")
	}
	e.phdrs = []elfPhdr{{typ: ptLoad, off: 64, vaddr: 0x1000, filesz: 64, memsz: 64}}
	e.dyn = map[int64]uint64{dtSymtab: 0x1000, dtSyment: math.MaxUint64, dtHash: 0x1000, dtGnuHash: 0x1000}
	e.parseSymbols()
	if len(e.symbols) != 0 {
		t.Fatal("oversize symbol stride accepted")
	}
}
