package dex

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

const (
	dexMagic = "dex\n"

	endianConstant = 0x12345678
	reverseEndian  = 0x78563412

	// Access flags
	ACC_PUBLIC                = 0x0001
	ACC_PRIVATE               = 0x0002
	ACC_PROTECTED             = 0x0004
	ACC_STATIC                = 0x0008
	ACC_FINAL                 = 0x0010
	ACC_SYNCHRONIZED          = 0x0020
	ACC_BRIDGE                = 0x0040
	ACC_VARARGS               = 0x0080
	ACC_NATIVE                = 0x0100
	ACC_INTERFACE             = 0x0200
	ACC_ABSTRACT              = 0x0400
	ACC_STRICT                = 0x0800
	ACC_SYNTHETIC             = 0x1000
	ACC_ANNOTATION            = 0x2000
	ACC_ENUM                  = 0x4000
	ACC_CONSTRUCTOR           = 0x00010000
	ACC_DECLARED_SYNCHRONIZED = 0x00020000
)

// Header represents the DEX file header
type Header struct {
	Magic          [8]byte
	Checksum       uint32
	Signature      [20]byte
	FileSize       uint32
	HeaderSize     uint32
	EndianTag      uint32
	LinkSize       uint32
	LinkOff        uint32
	MapOff         uint32
	StringIdsSize  uint32
	StringIdsOff   uint32
	TypeIdsSize    uint32
	TypeIdsOff     uint32
	ProtoIdsSize   uint32
	ProtoIdsOff    uint32
	FieldIdsSize   uint32
	FieldIdsOff    uint32
	MethodIdsSize  uint32
	MethodIdsOff   uint32
	ClassDefsSize  uint32
	ClassDefsOff   uint32
	DataSourceSize uint32
	DataSourceOff  uint32
}

// TypeId represents a type identifier
type TypeId struct {
	DescriptorIdx uint32
}

// ProtoId represents a method prototype identifier
type ProtoId struct {
	ShortyIdx     uint32
	ReturnTypeIdx uint32
	ParametersOff uint32
}

// FieldId represents a field identifier
type FieldId struct {
	ClassIdx uint16
	TypeIdx  uint16
	NameIdx  uint32
}

// MethodId represents a method identifier
type MethodId struct {
	ClassIdx uint16
	ProtoIdx uint16
	NameIdx  uint32
}

// ClassDef represents a class definition
type ClassDef struct {
	ClassIdx        uint32
	AccessFlags     uint32
	SuperclassIdx   uint32
	InterfacesOff   uint32
	SourceFileIdx   uint32
	AnnotationsOff  uint32
	ClassDataOff    uint32
	StaticValuesOff uint32
}

// ClassData represents class data (fields and methods)
type ClassData struct {
	StaticFieldsSize   uint32
	InstanceFieldsSize uint32
	DirectMethodsSize  uint32
	VirtualMethodsSize uint32
	StaticFields       []Field
	InstanceFields     []Field
	DirectMethods      []Method
	VirtualMethods     []Method
}

// Field represents a field
type Field struct {
	FieldIdx    uint32
	AccessFlags uint32
}

// Method represents a method
type Method struct {
	MethodIdx   uint32
	AccessFlags uint32
	CodeOff     uint32
}

// CodeItem represents method code
type CodeItem struct {
	RegistersSize uint16
	InsSize       uint16
	OutsSize      uint16
	TriesSize     uint16
	DebugInfoOff  uint32
	InsnsSize     uint32
	InsnsOff      uint32
	HandlersOff   uint32
}

// TryItem represents a try block
type TryItem struct {
	StartAddr  uint32
	InsCount   uint16
	HandlerOff uint16
}

// DexFile represents a complete DEX file
type DexFile struct {
	Header       Header
	Strings      []string
	Types        []TypeId
	TypeDescs    []string
	Protos       []ProtoId
	Fields       []FieldId
	Methods      []MethodId
	Classes      []ClassDef
	ClassDataMap map[uint32]*ClassData
	CodeItems    map[uint32]*CodeItem
	paramCache   map[uint32][]uint32
	version      string
	data         []byte
}

// ParseDexFile parses a DEX file from a file path
func ParseDexFile(path string) (*DexFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening dex file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading dex file: %w", err)
	}

	return ParseDexBytes(data)
}

// ParseDexBytes parses a DEX file from bytes
func ParseDexBytes(data []byte) (*DexFile, error) {
	if len(data) < 112 {
		return nil, fmt.Errorf("dex file too small: %d bytes", len(data))
	}

	dex := &DexFile{
		data:         data,
		ClassDataMap: make(map[uint32]*ClassData),
		CodeItems:    make(map[uint32]*CodeItem),
		paramCache:   make(map[uint32][]uint32),
	}

	// Parse header
	if err := dex.parseHeader(); err != nil {
		return nil, fmt.Errorf("parsing header: %w", err)
	}

	// Parse string IDs
	if err := dex.parseStringIds(); err != nil {
		return nil, fmt.Errorf("parsing string ids: %w", err)
	}

	// Parse type IDs
	if err := dex.parseTypeIds(); err != nil {
		return nil, fmt.Errorf("parsing type ids: %w", err)
	}

	// Parse proto IDs
	if err := dex.parseProtoIds(); err != nil {
		return nil, fmt.Errorf("parsing proto ids: %w", err)
	}

	// Parse field IDs
	if err := dex.parseFieldIds(); err != nil {
		return nil, fmt.Errorf("parsing field ids: %w", err)
	}

	// Parse method IDs
	if err := dex.parseMethodIds(); err != nil {
		return nil, fmt.Errorf("parsing method ids: %w", err)
	}

	// Parse class definitions
	if err := dex.parseClassDefs(); err != nil {
		return nil, fmt.Errorf("parsing class defs: %w", err)
	}

	return dex, nil
}

// Version returns the DEX format version (e.g. "035").
func (dex *DexFile) Version() string { return dex.version }

func (dex *DexFile) parseHeader() error {
	h := &dex.Header

	// Magic is "dex\n" + 3 version digits + NUL.
	copy(h.Magic[:], dex.data[0:8])
	if string(h.Magic[:4]) != dexMagic {
		return fmt.Errorf("invalid dex magic: %q", string(h.Magic[:4]))
	}
	version := string(h.Magic[4:7])
	for _, c := range version {
		if c < '0' || c > '9' {
			return fmt.Errorf("invalid dex version: %q", version)
		}
	}
	dex.version = version

	// Checksum
	h.Checksum = binary.LittleEndian.Uint32(dex.data[8:12])

	// Signature
	copy(h.Signature[:], dex.data[12:32])

	// File size
	h.FileSize = binary.LittleEndian.Uint32(dex.data[32:36])
	if uint64(h.FileSize) > uint64(len(dex.data)) || h.FileSize < h.HeaderSize {
		return fmt.Errorf("dex file size %d exceeds data size %d", h.FileSize, len(dex.data))
	}

	// Header size
	h.HeaderSize = binary.LittleEndian.Uint32(dex.data[36:40])
	if h.HeaderSize != 0x70 {
		return fmt.Errorf("unexpected header size: %d", h.HeaderSize)
	}

	// Endian tag
	h.EndianTag = binary.LittleEndian.Uint32(dex.data[40:44])
	if h.EndianTag != endianConstant {
		return fmt.Errorf("unexpected endian tag: 0x%08x", h.EndianTag)
	}

	// Link size and offset
	h.LinkSize = binary.LittleEndian.Uint32(dex.data[44:48])
	h.LinkOff = binary.LittleEndian.Uint32(dex.data[48:52])

	// Map offset
	h.MapOff = binary.LittleEndian.Uint32(dex.data[52:56])

	// String IDs
	h.StringIdsSize = binary.LittleEndian.Uint32(dex.data[56:60])
	h.StringIdsOff = binary.LittleEndian.Uint32(dex.data[60:64])

	// Type IDs
	h.TypeIdsSize = binary.LittleEndian.Uint32(dex.data[64:68])
	h.TypeIdsOff = binary.LittleEndian.Uint32(dex.data[68:72])

	// Proto IDs
	h.ProtoIdsSize = binary.LittleEndian.Uint32(dex.data[72:76])
	h.ProtoIdsOff = binary.LittleEndian.Uint32(dex.data[76:80])

	// Field IDs
	h.FieldIdsSize = binary.LittleEndian.Uint32(dex.data[80:84])
	h.FieldIdsOff = binary.LittleEndian.Uint32(dex.data[84:88])

	// Method IDs
	h.MethodIdsSize = binary.LittleEndian.Uint32(dex.data[88:92])
	h.MethodIdsOff = binary.LittleEndian.Uint32(dex.data[92:96])

	// Class defs
	h.ClassDefsSize = binary.LittleEndian.Uint32(dex.data[96:100])
	h.ClassDefsOff = binary.LittleEndian.Uint32(dex.data[100:104])

	// Data source
	h.DataSourceSize = binary.LittleEndian.Uint32(dex.data[104:108])
	h.DataSourceOff = binary.LittleEndian.Uint32(dex.data[108:112])

	return nil
}

func (dex *DexFile) parseStringIds() error {
	h := &dex.Header
	if err := dex.checkRange(h.StringIdsOff, h.StringIdsSize, 4, "string ids"); err != nil {
		return err
	}

	dex.Strings = make([]string, h.StringIdsSize)
	for i := uint32(0); i < h.StringIdsSize; i++ {
		off := h.StringIdsOff + i*4
		strOff := binary.LittleEndian.Uint32(dex.data[off : off+4])
		s, err := dex.readString(strOff)
		if err != nil {
			// Keep going: one bad string shouldn't kill the whole file.
			s = ""
		}
		dex.Strings[i] = s
	}

	return nil
}

// readString decodes a DEX string_data_item: uleb128 UTF-16 length followed
// by NUL-terminated MUTF-8 bytes.
func (dex *DexFile) readString(offset uint32) (string, error) {
	if int(offset) >= len(dex.data) {
		return "", fmt.Errorf("string offset 0x%x out of range", offset)
	}

	// Skip the uleb128 utf16_size prefix.
	_, pos, err := dex.readULEB128(offset)
	if err != nil {
		return "", err
	}

	end := int(pos)
	for end < len(dex.data) && dex.data[end] != 0 {
		end++
	}
	if end >= len(dex.data) {
		return "", fmt.Errorf("unterminated string at 0x%x", offset)
	}

	return decodeMUTF8(dex.data[pos:end]), nil
}

// decodeMUTF8 decodes a modified UTF-8 byte sequence. MUTF-8 encodes U+0000
// as 0xC0 0x80 and supplementary characters as UTF-16 surrogate pairs, each
// written as its own 3-byte sequence.
func decodeMUTF8(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == 0:
			// Shouldn't happen (NUL terminates the data), but be safe.
			i++
		case c < 0x80:
			sb.WriteByte(c)
			i++
		case c&0xe0 == 0xc0:
			if i+1 >= len(b) {
				i = len(b)
				continue
			}
			sb.WriteRune(rune(c&0x1f)<<6 | rune(b[i+1]&0x3f))
			i += 2
		case c&0xf0 == 0xe0:
			if i+2 >= len(b) {
				i = len(b)
				continue
			}
			r := rune(c&0x0f)<<12 | rune(b[i+1]&0x3f)<<6 | rune(b[i+2]&0x3f)
			if r >= 0xd800 && r <= 0xdbff && i+5 < len(b) &&
				b[i+3]&0xf0 == 0xe0 {
				r2 := rune(b[i+3]&0x0f)<<12 | rune(b[i+4]&0x3f)<<6 | rune(b[i+5]&0x3f)
				if r2 >= 0xdc00 && r2 <= 0xdfff {
					sb.WriteRune(0x10000 + (r-0xd800)<<10 + (r2 - 0xdc00))
					i += 6
					continue
				}
			}
			sb.WriteRune(r)
			i += 3
		default:
			i++
		}
	}
	return sb.String()
}

func (dex *DexFile) parseTypeIds() error {
	h := &dex.Header
	if err := dex.checkRange(h.TypeIdsOff, h.TypeIdsSize, 4, "type ids"); err != nil {
		return err
	}

	dex.Types = make([]TypeId, h.TypeIdsSize)
	dex.TypeDescs = make([]string, h.TypeIdsSize)
	for i := uint32(0); i < h.TypeIdsSize; i++ {
		off := h.TypeIdsOff + i*4
		descIdx := binary.LittleEndian.Uint32(dex.data[off : off+4])
		dex.Types[i] = TypeId{DescriptorIdx: descIdx}
		dex.TypeDescs[i] = dex.getString(descIdx)
	}

	return nil
}

func (dex *DexFile) parseProtoIds() error {
	h := &dex.Header
	if err := dex.checkRange(h.ProtoIdsOff, h.ProtoIdsSize, 12, "proto ids"); err != nil {
		return err
	}

	dex.Protos = make([]ProtoId, h.ProtoIdsSize)
	for i := uint32(0); i < h.ProtoIdsSize; i++ {
		off := h.ProtoIdsOff + i*12
		dex.Protos[i] = ProtoId{
			ShortyIdx:     binary.LittleEndian.Uint32(dex.data[off : off+4]),
			ReturnTypeIdx: binary.LittleEndian.Uint32(dex.data[off+4 : off+8]),
			ParametersOff: binary.LittleEndian.Uint32(dex.data[off+8 : off+12]),
		}
	}

	return nil
}

func (dex *DexFile) parseFieldIds() error {
	h := &dex.Header
	if err := dex.checkRange(h.FieldIdsOff, h.FieldIdsSize, 8, "field ids"); err != nil {
		return err
	}

	dex.Fields = make([]FieldId, h.FieldIdsSize)
	for i := uint32(0); i < h.FieldIdsSize; i++ {
		off := h.FieldIdsOff + i*8
		dex.Fields[i] = FieldId{
			ClassIdx: binary.LittleEndian.Uint16(dex.data[off : off+2]),
			TypeIdx:  binary.LittleEndian.Uint16(dex.data[off+2 : off+4]),
			NameIdx:  binary.LittleEndian.Uint32(dex.data[off+4 : off+8]),
		}
	}

	return nil
}

func (dex *DexFile) parseMethodIds() error {
	h := &dex.Header
	if err := dex.checkRange(h.MethodIdsOff, h.MethodIdsSize, 8, "method ids"); err != nil {
		return err
	}

	dex.Methods = make([]MethodId, h.MethodIdsSize)
	for i := uint32(0); i < h.MethodIdsSize; i++ {
		off := h.MethodIdsOff + i*8
		dex.Methods[i] = MethodId{
			ClassIdx: binary.LittleEndian.Uint16(dex.data[off : off+2]),
			ProtoIdx: binary.LittleEndian.Uint16(dex.data[off+2 : off+4]),
			NameIdx:  binary.LittleEndian.Uint32(dex.data[off+4 : off+8]),
		}
	}

	return nil
}

func (dex *DexFile) parseClassDefs() error {
	h := &dex.Header
	if err := dex.checkRange(h.ClassDefsOff, h.ClassDefsSize, 32, "class defs"); err != nil {
		return err
	}

	dex.Classes = make([]ClassDef, h.ClassDefsSize)
	for i := uint32(0); i < h.ClassDefsSize; i++ {
		off := h.ClassDefsOff + i*32
		dex.Classes[i] = ClassDef{
			ClassIdx:        binary.LittleEndian.Uint32(dex.data[off : off+4]),
			AccessFlags:     binary.LittleEndian.Uint32(dex.data[off+4 : off+8]),
			SuperclassIdx:   binary.LittleEndian.Uint32(dex.data[off+8 : off+12]),
			InterfacesOff:   binary.LittleEndian.Uint32(dex.data[off+12 : off+16]),
			SourceFileIdx:   binary.LittleEndian.Uint32(dex.data[off+16 : off+20]),
			AnnotationsOff:  binary.LittleEndian.Uint32(dex.data[off+20 : off+24]),
			ClassDataOff:    binary.LittleEndian.Uint32(dex.data[off+24 : off+28]),
			StaticValuesOff: binary.LittleEndian.Uint32(dex.data[off+28 : off+32]),
		}
	}

	return nil
}

// GetClassName returns the type descriptor of a class by its index
// (e.g. "Lcom/example/Foo;").
func (dex *DexFile) GetClassName(idx uint32) string {
	return dex.GetTypeDesc(idx)
}

// GetTypeDesc returns the type descriptor at idx (e.g. "I", "[I",
// "Ljava/lang/String;").
func (dex *DexFile) GetTypeDesc(idx uint32) string {
	if int(idx) < len(dex.TypeDescs) {
		return dex.TypeDescs[idx]
	}
	return ""
}

// GetTypeName is a compatibility alias for GetTypeDesc.
func (dex *DexFile) GetTypeName(idx uint32) string {
	return dex.GetTypeDesc(idx)
}

// GetMethodName returns the name of a method by its index.
func (dex *DexFile) GetMethodName(idx uint32) string {
	if int(idx) < len(dex.Methods) {
		return dex.getString(dex.Methods[idx].NameIdx)
	}
	return ""
}

// GetFieldName returns the name of a field by its index.
func (dex *DexFile) GetFieldName(idx uint32) string {
	if int(idx) < len(dex.Fields) {
		return dex.getString(dex.Fields[idx].NameIdx)
	}
	return ""
}

// GetString returns the string at idx.
func (dex *DexFile) GetString(idx uint32) string {
	return dex.getString(idx)
}

func (dex *DexFile) getString(idx uint32) string {
	if int(idx) < len(dex.Strings) {
		return dex.Strings[idx]
	}
	return ""
}

// GetMethodId returns the method id at idx, or nil.
func (dex *DexFile) GetMethodId(idx uint32) *MethodId {
	if int(idx) < len(dex.Methods) {
		return &dex.Methods[idx]
	}
	return nil
}

// GetFieldId returns the field id at idx, or nil.
func (dex *DexFile) GetFieldId(idx uint32) *FieldId {
	if int(idx) < len(dex.Fields) {
		return &dex.Fields[idx]
	}
	return nil
}

// GetProto returns the prototype at idx, or nil.
func (dex *DexFile) GetProto(idx uint32) *ProtoId {
	if int(idx) < len(dex.Protos) {
		return &dex.Protos[idx]
	}
	return nil
}

// GetParameters returns the list of parameter type indices for a prototype,
// decoding (and caching) the type_list at proto.ParametersOff.
func (dex *DexFile) GetParameters(proto ProtoId) []uint32 {
	if proto.ParametersOff == 0 {
		return nil
	}
	if cached, ok := dex.paramCache[proto.ParametersOff]; ok {
		return cached
	}

	off := proto.ParametersOff
	if err := dex.checkRange(off, 1, 4, "parameters size"); err != nil {
		return nil
	}
	size := binary.LittleEndian.Uint32(dex.data[off : off+4])
	if err := dex.checkRange64(uint64(off)+4, uint64(size), 2, "parameters"); err != nil {
		return nil
	}

	params := make([]uint32, size)
	for i := uint32(0); i < size; i++ {
		p := off + 4 + i*2
		params[i] = uint32(binary.LittleEndian.Uint16(dex.data[p : p+2]))
	}
	dex.paramCache[proto.ParametersOff] = params
	return params
}

// GetInterfaces returns the raw type indices in the class's interface list.
func (dex *DexFile) GetInterfaces(cd ClassDef) []uint32 {
	if cd.InterfacesOff == 0 {
		return nil
	}
	off := cd.InterfacesOff
	if err := dex.checkRange(off, 1, 4, "interfaces size"); err != nil {
		return nil
	}
	size := binary.LittleEndian.Uint32(dex.data[off : off+4])
	if err := dex.checkRange64(uint64(off)+4, uint64(size), 2, "interfaces"); err != nil {
		return nil
	}
	out := make([]uint32, size)
	for i := uint32(0); i < size; i++ {
		p := off + 4 + i*2
		out[i] = uint32(binary.LittleEndian.Uint16(dex.data[p : p+2]))
	}
	return out
}

// GetClassData returns the class data for a class definition
func (dex *DexFile) GetClassData(cd ClassDef) *ClassData {
	if cd.ClassDataOff == 0 {
		return nil
	}

	if cached, ok := dex.ClassDataMap[cd.ClassDataOff]; ok {
		return cached
	}

	data := dex.parseClassData(cd.ClassDataOff)
	dex.ClassDataMap[cd.ClassDataOff] = data
	return data
}

func (dex *DexFile) parseClassData(offset uint32) *ClassData {
	if uint64(offset) >= uint64(len(dex.data)) {
		return nil
	}
	cd := &ClassData{}
	pos := offset

	// Read sizes
	var err error
	if cd.StaticFieldsSize, pos, err = dex.readULEB128(pos); err != nil {
		return nil
	}
	if cd.InstanceFieldsSize, pos, err = dex.readULEB128(pos); err != nil {
		return nil
	}
	if cd.DirectMethodsSize, pos, err = dex.readULEB128(pos); err != nil {
		return nil
	}
	if cd.VirtualMethodsSize, pos, err = dex.readULEB128(pos); err != nil {
		return nil
	}
	remaining := uint64(len(dex.data)) - uint64(pos)
	fieldCount := uint64(cd.StaticFieldsSize) + uint64(cd.InstanceFieldsSize)
	methodCount := uint64(cd.DirectMethodsSize) + uint64(cd.VirtualMethodsSize)
	if fieldCount*2+methodCount*3 > remaining ||
		!dex.canAllocate(fieldCount, 8) || !dex.canAllocate(methodCount, 12) {
		return nil
	}

	// Read static fields
	cd.StaticFields = make([]Field, cd.StaticFieldsSize)
	fieldIdx := uint32(0)
	for i := uint32(0); i < cd.StaticFieldsSize; i++ {
		if uint64(pos) >= uint64(len(dex.data)) {
			return nil
		}
		fieldIdxDelta, p, err := dex.readULEB128(pos)
		if err != nil {
			return nil
		}
		fieldIdx += fieldIdxDelta
		accessFlags, p2, err := dex.readULEB128(p)
		if err != nil {
			return nil
		}
		cd.StaticFields[i] = Field{FieldIdx: fieldIdx, AccessFlags: accessFlags}
		pos = p2
	}

	// Read instance fields
	cd.InstanceFields = make([]Field, cd.InstanceFieldsSize)
	fieldIdx = 0
	for i := uint32(0); i < cd.InstanceFieldsSize; i++ {
		if uint64(pos) >= uint64(len(dex.data)) {
			return nil
		}
		fieldIdxDelta, p, err := dex.readULEB128(pos)
		if err != nil {
			return nil
		}
		fieldIdx += fieldIdxDelta
		accessFlags, p2, err := dex.readULEB128(p)
		if err != nil {
			return nil
		}
		cd.InstanceFields[i] = Field{FieldIdx: fieldIdx, AccessFlags: accessFlags}
		pos = p2
	}

	// Read direct methods
	cd.DirectMethods = make([]Method, cd.DirectMethodsSize)
	methodIdx := uint32(0)
	for i := uint32(0); i < cd.DirectMethodsSize; i++ {
		if uint64(pos) >= uint64(len(dex.data)) {
			return nil
		}
		methodIdxDelta, p, err := dex.readULEB128(pos)
		if err != nil {
			return nil
		}
		methodIdx += methodIdxDelta
		accessFlags, p2, err := dex.readULEB128(p)
		if err != nil {
			return nil
		}
		codeOff, p3, err := dex.readULEB128(p2)
		if err != nil {
			return nil
		}
		cd.DirectMethods[i] = Method{MethodIdx: methodIdx, AccessFlags: accessFlags, CodeOff: codeOff}
		pos = p3
	}

	// Read virtual methods
	cd.VirtualMethods = make([]Method, cd.VirtualMethodsSize)
	methodIdx = 0
	for i := uint32(0); i < cd.VirtualMethodsSize; i++ {
		if uint64(pos) >= uint64(len(dex.data)) {
			return nil
		}
		methodIdxDelta, p, err := dex.readULEB128(pos)
		if err != nil {
			return nil
		}
		methodIdx += methodIdxDelta
		accessFlags, p2, err := dex.readULEB128(p)
		if err != nil {
			return nil
		}
		codeOff, p3, err := dex.readULEB128(p2)
		if err != nil {
			return nil
		}
		cd.VirtualMethods[i] = Method{MethodIdx: methodIdx, AccessFlags: accessFlags, CodeOff: codeOff}
		pos = p3
	}

	return cd
}

// GetCodeItem returns the code item for a method
func (dex *DexFile) GetCodeItem(offset uint32) *CodeItem {
	if offset == 0 {
		return nil
	}

	if cached, ok := dex.CodeItems[offset]; ok {
		return cached
	}

	if err := dex.checkRange(offset, 1, 16, "code item"); err != nil {
		return nil
	}

	ci := &CodeItem{
		RegistersSize: binary.LittleEndian.Uint16(dex.data[offset : offset+2]),
		InsSize:       binary.LittleEndian.Uint16(dex.data[offset+2 : offset+4]),
		OutsSize:      binary.LittleEndian.Uint16(dex.data[offset+4 : offset+6]),
		TriesSize:     binary.LittleEndian.Uint16(dex.data[offset+6 : offset+8]),
		DebugInfoOff:  binary.LittleEndian.Uint32(dex.data[offset+8 : offset+12]),
		InsnsSize:     binary.LittleEndian.Uint32(dex.data[offset+12 : offset+16]),
		InsnsOff:      offset + 16,
	}

	if ci.TriesSize > 0 {
		// tries start after insns (insns are 2 bytes each), padded to 4 bytes
		triesOff64 := uint64(offset) + 16 + uint64(ci.InsnsSize)*2
		if ci.InsnsSize%2 != 0 {
			triesOff64 += 2
		}
		handlersOff64 := triesOff64 + uint64(ci.TriesSize)*8
		if handlersOff64 <= uint64(math.MaxUint32) && dex.checkRange(uint32(handlersOff64), 1, 4, "code handlers") == nil {
			handlersOff := uint32(handlersOff64)
			ci.HandlersOff = binary.LittleEndian.Uint32(dex.data[handlersOff : handlersOff+4])
		}
	}

	dex.CodeItems[offset] = ci
	return ci
}

// GetInstructions returns the raw bytecode bytes for a code item, limited to
// the declared insns_size.
func (dex *DexFile) GetInstructions(ci *CodeItem) []byte {
	if ci == nil || ci.InsnsOff == 0 {
		return nil
	}
	if dex.checkRange(ci.InsnsOff, ci.InsnsSize, 2, "instructions") != nil {
		return nil
	}
	start := int(ci.InsnsOff)
	end := start + int(ci.InsnsSize)*2
	return dex.data[start:end]
}

// readULB128 reads an unsigned LEB128 value, returning the value and the
// next offset. Malformed/truncated input yields a zero value.
func (dex *DexFile) readULB128(offset uint32) (uint32, uint32) {
	var result uint32
	var shift uint32
	pos := offset

	for {
		if int(pos) >= len(dex.data) || shift >= 32 {
			return result, pos
		}
		b := dex.data[pos]
		pos++
		result |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}

	return result, pos
}

// readULEB128 is like readULB128 but reports truncation.
func (dex *DexFile) readULEB128(offset uint32) (uint32, uint32, error) {
	var result uint32
	var shift uint32
	pos := offset

	for {
		if int(pos) >= len(dex.data) {
			return 0, pos, fmt.Errorf("truncated uleb128 at 0x%x", offset)
		}
		b := dex.data[pos]
		pos++
		result |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, pos, nil
		}
		shift += 7
		if shift >= 35 {
			return result, pos, fmt.Errorf("uleb128 too long at 0x%x", offset)
		}
	}
}

// checkRange verifies that count entries of entrySize bytes at off fit in data.
func (dex *DexFile) checkRange(off, count, entrySize uint32, what string) error {
	return dex.checkRange64(uint64(off), uint64(count), uint64(entrySize), what)
}

func (dex *DexFile) checkRange64(off, count, entrySize uint64, what string) error {
	if count == 0 {
		return nil
	}
	if entrySize != 0 && count > math.MaxUint64/entrySize {
		return fmt.Errorf("%s range overflows: off=0x%x count=%d size=%d", what, off, count, entrySize)
	}
	end := off + count*entrySize
	if end < off {
		return fmt.Errorf("%s range overflows: off=0x%x count=%d size=%d", what, off, count, entrySize)
	}
	if end > uint64(len(dex.data)) {
		return fmt.Errorf("%s out of range: off=0x%x count=%d size=%d (file %d bytes)",
			what, off, count, entrySize, len(dex.data))
	}
	return nil
}

func (dex *DexFile) canAllocate(count, itemSize uint64) bool {
	return count <= uint64(math.MaxInt) && itemSize <= uint64(math.MaxInt) &&
		(count == 0 || itemSize <= uint64(math.MaxInt)/count) &&
		(count == 0 || itemSize <= uint64(len(dex.data))/count)
}
