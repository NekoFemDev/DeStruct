package il2cpp

import (
	"bufio"
	"bytes"
	"errors"
	"testing"
)

func TestMetadataReaderMalformedInputReturnsError(t *testing.T) {
	r := &metadataReader{data: []byte{0x80}}
	if got := r.compressedUInt32(); got != 0 {
		t.Fatalf("malformed compressed value = %d", got)
	}
	if r.err == nil {
		t.Fatal("expected malformed compressed integer error")
	}
	var refErr *ReferenceError
	if !errors.As(r.err, &refErr) || refErr.Table != "metadataBlob" {
		t.Fatalf("unexpected error: %v", r.err)
	}
}

func TestDumpTypeReportsMalformedReference(t *testing.T) {
	m := &Metadata{Version: 31, typeDefs: []record{{b: make([]byte, layoutTypeDefinition.size(31)), l: &layoutTypeDefinition, ver: 31}}}
	// TypeDefinition.parentIndex = 2, outside the empty type table.
	parent := layoutTypeDefinition.offset(31, "parentIndex")
	m.typeDefs[0].b[parent] = 2
	e := &Executor{Metadata: m, IL2CPP: &IL2CPP{}}
	var out bytes.Buffer
	e.dumpType(bufio.NewWriter(&out), 0, "image", 0, DefaultDumpOptions())
	var refErr *ReferenceError
	if !errors.As(e.Err(), &refErr) || refErr.Table != "types" || refErr.Index != 2 {
		t.Fatalf("expected types[2] error, got %v", e.Err())
	}
}

func TestDefaultValueTruncatedBlobReturnsTypedError(t *testing.T) {
	m := &Metadata{Data: []byte{0xab}, Header: MetadataHeader{Raw: map[string]int64{
		"fieldAndParameterDefaultValueDataOffset": 0,
		"fieldAndParameterDefaultValueDataSize":   1,
	}}}
	e := &Executor{Metadata: m, IL2CPP: &IL2CPP{Types: []*Il2CppType{{TypeEnum: typeU8}}}}
	if _, ok := e.TryGetDefaultValue(0, 0); ok {
		t.Fatal("accepted truncated uint64 default")
	}
	var refErr *ReferenceError
	if !errors.As(e.Err(), &refErr) || refErr.Table != "metadataBlob" {
		t.Fatalf("expected typed blob error, got %v", e.Err())
	}
}

func TestExecutorInvalidTypeRecordsError(t *testing.T) {
	e := &Executor{Metadata: &Metadata{}, IL2CPP: &IL2CPP{Types: []*Il2CppType{nil}}}
	if got := e.GetTypeName(&Il2CppType{TypeEnum: 0xfe}, false, false); got != "<?>" {
		t.Fatalf("invalid type rendered as %q", got)
	}
	if e.Err() == nil {
		t.Fatal("expected invalid type error")
	}
	var refErr *ReferenceError
	if !errors.As(e.Err(), &refErr) || refErr.Table != "types" {
		t.Fatalf("unexpected error: %v", e.Err())
	}
}

func TestExecutorTypeIndexDoesNotPanic(t *testing.T) {
	e := &Executor{IL2CPP: &IL2CPP{Types: []*Il2CppType{}}}
	if got := e.typeAt(42); got != nil {
		t.Fatalf("out-of-range type = %#v", got)
	}
	if e.Err() == nil {
		t.Fatal("expected type index error")
	}
}
