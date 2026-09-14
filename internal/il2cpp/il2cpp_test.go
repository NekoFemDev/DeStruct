package il2cpp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLayoutSizes(t *testing.T) {
	cases := []struct {
		name string
		l    *structLayout
		ver  float64
		want int
	}{
		{"Il2CppType", &layoutIl2CppType, 31, 12},
		{"MetadataRegistration", &layoutMetadataRegistration, 31, 128},
		{"CodeRegistration", &layoutCodeRegistration, 31, 136},
		{"CodeRegistration v29", &layoutCodeRegistration, 29, 120},
		{"CodeGenModule", &layoutCodeGenModule, 31, 136},
		{"TypeDefinition", &layoutTypeDefinition, 31, 88},
		{"MethodDefinition", &layoutMethodDefinition, 31, 36},
		{"MethodDefinition v27", &layoutMethodDefinition, 27, 32},
		{"ImageDefinition", &layoutImageDefinition, 31, 40},
		{"GenericParameter", &layoutGenericParameter, 31, 16},
	}
	for _, tc := range cases {
		if got := tc.l.size(tc.ver); got != tc.want {
			t.Errorf("%s size at v%.1f = %d, want %d", tc.name, tc.ver, got, tc.want)
		}
	}
}

func TestLayoutOffsets(t *testing.T) {
	if got := layoutMethodDefinition.offset(31, "token"); got != 0x18 {
		t.Errorf("v31 method token offset = 0x%X, want 0x18", got)
	}
	if got := layoutMethodDefinition.offset(31, "parameterStart"); got != 0x10 {
		t.Errorf("v31 method parameterStart offset = 0x%X, want 0x10", got)
	}
	if got := layoutMethodDefinition.offset(27, "parameterStart"); got != 0xC {
		t.Errorf("v27 method parameterStart offset = 0x%X, want 0xC", got)
	}
	if got := layoutTypeDefinition.offset(31, "token"); got != 0x54 {
		t.Errorf("v31 typeDef token offset = 0x%X, want 0x54", got)
	}
	if got := layoutCodeRegistration.offset(31, "codeGenModules"); got != 0x80 {
		t.Errorf("v31 codeGenModules offset = 0x%X, want 0x80", got)
	}
}

func TestCompressedIntegers(t *testing.T) {
	r := &metadataReader{data: []byte{0x7F}}
	if got := r.compressedUInt32(); got != 127 {
		t.Errorf("1-byte compressed = %d, want 127", got)
	}
	r = &metadataReader{data: []byte{0x97, 0x3E}}
	if got := r.compressedUInt32(); got != 0x173E {
		t.Errorf("2-byte compressed = %#x, want 0x173E", got)
	}
	r = &metadataReader{data: []byte{0xC0, 0x00, 0xC9, 0x6A}}
	if got := r.compressedUInt32(); got != 0xC96A {
		t.Errorf("4-byte compressed = %#x, want 0xC96A", got)
	}
	r = &metadataReader{data: []byte{0x22}}
	if got := r.compressedInt32(); got != 17 {
		t.Errorf("compressed int32 0x22 = %d, want 17", got)
	}
	r = &metadataReader{data: []byte{0x03}}
	if got := r.compressedInt32(); got != -2 {
		t.Errorf("compressed int32 0x03 = %d, want -2", got)
	}
}

func TestEscapeString(t *testing.T) {
	got := escapeString("a\"b\\c\nd\t")
	want := `a\"b\\c\nd\t`
	if got != want {
		t.Errorf("escapeString = %q, want %q", got, want)
	}
}

// TestFormatMethodLocation locks in the reference dumper's location
// comment format: interface/abstract methods (and any method whose
// native pointer wasn't resolved) must still get a full RVA line, with
// -1 placeholders rather than the line being dropped, and a vtable slot
// must be appended to that same line.
func TestFormatMethodLocation(t *testing.T) {
	cases := []struct {
		name          string
		isAbstract    bool
		methodPointer uint64
		rva, fileOff  uint64
		slot          uint16
		haveSlot      bool
		want          string
	}{
		{
			name:          "concrete method with RVA and slot",
			isAbstract:    false,
			methodPointer: 0x23DB3C0,
			rva:           0x23DB3C0,
			fileOff:       0x23D73C0,
			slot:          3,
			haveSlot:      true,
			want:          "\t// RVA: 0x23DB3C0 Offset: 0x23D73C0 VA: 0x23DB3C0 Slot: 3\n",
		},
		{
			name:          "concrete method with RVA, no slot",
			isAbstract:    false,
			methodPointer: 0x1000,
			rva:           0x1000,
			fileOff:       0x400,
			want:          "\t// RVA: 0x1000 Offset: 0x400 VA: 0x1000\n",
		},
		{
			name:       "interface method keeps RVA -1 line and slot",
			isAbstract: true,
			slot:       0,
			haveSlot:   true,
			want:       "\t// RVA: -1 Offset: -1 Slot: 0\n",
		},
		{
			name:       "unresolved pointer keeps RVA -1 line",
			isAbstract: false,
			want:       "\t// RVA: -1 Offset: -1\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatMethodLocation(tc.isAbstract, tc.methodPointer, tc.rva, tc.fileOff, tc.slot, tc.haveSlot); got != tc.want {
				t.Errorf("formatMethodLocation() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRenderDefaultValue(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, "null"},
		{"hi", `"hi"`},
		{float32(0.48999998), "0.49"},
		{float64(2958466.0), "2.95847e+06"},
		{int32(16777728), "16777728"},
		{charValue(10), "10"},
		{true, "true"},
	}
	for _, tc := range cases {
		if got := renderDefaultValue(tc.in); got != tc.want {
			t.Errorf("renderDefaultValue(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDumpMatchesReference runs the full dumper against the real Unity
// fixtures when they are present next to the repository root and
// compares the output byte-for-byte with the reference dump.cs.
func TestDumpMatchesReference(t *testing.T) {
	lib := "../../libil2cpp.so"
	meta := "../../global-metadata.dat"
	reference := "../../dump.cs"
	for _, p := range []string{lib, meta, reference} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("fixture %s not present", p)
		}
	}

	out := t.TempDir()
	result, err := Run(Options{
		LibPath:      lib,
		MetadataPath: meta,
		OutputDir:    out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.MetadataVersion != 31 {
		t.Fatalf("metadata version = %v, want 31", result.MetadataVersion)
	}
	if result.TypeDefCount != 10688 || result.ImageCount != 83 {
		t.Fatalf("unexpected counts: typedefs=%d images=%d", result.TypeDefCount, result.ImageCount)
	}

	got, err := os.ReadFile(filepath.Join(out, "dump.cs"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(reference)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		line := firstDiffLine(got, want)
		t.Fatalf("dump.cs differs from reference at line %d", line)
	}
}

func firstDiffLine(a, b []byte) int {
	al := bytes.Split(a, []byte("\n"))
	bl := bytes.Split(b, []byte("\n"))
	n := len(al)
	if len(bl) < n {
		n = len(bl)
	}
	for i := 0; i < n; i++ {
		if !bytes.Equal(al[i], bl[i]) {
			return i + 1
		}
	}
	return n + 1
}
