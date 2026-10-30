// Package ir defines DeStruct's intermediate representation for Hermes
// bytecode (.hbc) files.
//
// The IR is deliberately decoupled from the raw file bytes: the parser
// produces an *ir.Module by decoding the container (header, function
// headers, string and literal tables) and, on request, the instruction
// stream; the disassembler and assembler consume that structure without
// re-deriving offsets by hand.
//
// The only external dependency is the opcodes package, and only for the
// pure-data Opcode/Operand type declarations referenced by Instruction.
// Nothing here imports the parser, the disassembler or the assembler.
package ir

import "github.com/destruct/destruct/internal/hermes/opcodes"

// Magic is the little-endian file signature every Hermes bytecode file
// starts with ("Ἑρμῆ" encoded UTF-16BE, per BytecodeFileFormat.h).
const Magic uint64 = 0x1F1903C103BC1FC6

// Header mirrors BytecodeFileHeader. Field presence varies with the
// bytecode version; fields that do not exist for a given version are left
// at their zero value and documented below.
type Header struct {
	Magic      uint64
	Version    uint32
	SourceHash [20]byte

	FileLength      uint32 // Through the end of the SHA1 footer; the physical file may be longer (epilogue).
	GlobalCodeIndex uint32
	FunctionCount   uint32
	StringKindCount uint32
	IdentifierCount uint32
	StringCount     uint32

	// OverflowStringCount is the number of entries in the overflow string
	// table (strings whose length or offset does not fit in a small entry).
	OverflowStringCount uint32
	StringStorageSize   uint32

	// v87+.
	BigIntCount       uint32
	BigIntStorageSize uint32

	RegExpCount       uint32
	RegExpStorageSize uint32

	// v<97 layout uses ArrayBuffer/ObjValue; v97+ replaced them with a
	// single literal value buffer plus an object shape table.
	ArrayBufferSize        uint32 // v<97
	LiteralValueBufferSize uint32 // v97+
	ObjKeyBufferSize       uint32 // all versions
	ObjValueBufferSize     uint32 // v<97
	ObjShapeTableCount     uint32 // v97+

	// v98+.
	NumStringSwitchImms uint32

	// v<78 named cjsModuleOffset, v78+ segmentID.
	SegmentID      uint32
	CJSModuleCount uint32

	// v84+.
	FunctionSourceCount uint32

	DebugInfoOffset uint32

	// Flags byte (v<87: 1 bit; later versions use more).
	StaticBuiltins               bool
	CJSModulesStaticallyResolved bool
	HasAsync                     bool
}

// StringKind classifies a string table entry. The kind is stored as a
// run-length encoded table in the file; Module.StringKinds holds the
// expanded per-string kinds.
type StringKind uint8

const (
	StringKindString StringKind = iota
	StringKindIdentifier
	StringKindPredefined
)

func (k StringKind) String() string {
	switch k {
	case StringKindString:
		return "String"
	case StringKindIdentifier:
		return "Identifier"
	case StringKindPredefined:
		return "Predefined"
	default:
		return "Unknown"
	}
}

// StringKindRun is one run-length encoded entry of the StringKind section:
// Count consecutive strings all have kind Kind.
type StringKindRun struct {
	Count uint32
	Kind  StringKind
}

// FunctionKind is the FuncKind enum stored in a function header's flags.
type FunctionKind uint8

const (
	FunctionKindNormal FunctionKind = iota
	FunctionKindGenerator
	FunctionKindAsync
)

func (k FunctionKind) String() string {
	switch k {
	case FunctionKindNormal:
		return "Function"
	case FunctionKindGenerator:
		return "Generator function"
	case FunctionKindAsync:
		return "Async function"
	default:
		return "Unknown function"
	}
}

// ExceptionHandler is one HBCExceptionHandlerInfo entry. Start/End/Target
// are function-relative bytecode offsets.
type ExceptionHandler struct {
	Start  uint32
	End    uint32
	Target uint32
}

// DebugOffsets mirrors the per-function DebugOffsets structure read after
// the exception handler table. TextifiedCallees only exists for v91+.
type DebugOffsets struct {
	SourceLocations  uint32
	ScopeDescData    uint32
	TextifiedCallees uint32
}

// BigInt is one entry of the BigInt table plus a decoded decimal value.
type BigInt struct {
	Offset uint32
	Length uint32
	// Value is the decimal rendering of the little-endian magnitude.
	Value string
}

// RegExpRef is one RegExpTableEntry mapping into Module.RegExpStorage.
type RegExpRef struct {
	Offset uint32
	Length uint32
}

// ShapeTableEntry is one v97+ object shape table entry. NumProps keys for
// the shape start at KeyBufferOffset within Module.ObjectKeyBuffer.
type ShapeTableEntry struct {
	KeyBufferOffset uint32
	NumProps        uint32
}

// CJSModule is one (symbolID, fileOffset) pair of the CJS module table,
// or the raw value when the table stores plain integers (v<77 with static
// resolution).
type CJSModule struct {
	SymbolID uint32
	Offset   uint32
	// Raw is set instead of the pair fields when the table physically
	// stores a single uint32 per module.
	Raw   uint32
	IsRaw bool
}

// FunctionSource is one (functionID, stringID) function source entry (v84+).
type FunctionSource struct {
	FunctionID uint32
	StringID   uint32
}

// Instruction is one decoded instruction. Operands holds the raw
// little-endian bit patterns exactly as they appear on disk (two's
// complement for signed operand types, IEEE-754 bits for Double); the
// operand layout and semantics live in Op.
type Instruction struct {
	// Op is nil only when the decoder met an opcode byte that does not
	// exist in this version's table ("<Unknown>").
	Op     *opcodes.Opcode
	RawOp  byte
	Offset uint32 // byte offset from the start of the function's bytecode

	// Operands[i] is the raw bit pattern of Op.Operands[i].
	Operands []uint64

	// JumpTable holds the decoded entries of a SwitchImm/UIntSwitchImm
	// jump table: function-relative target offsets, one per case in the
	// instruction's inclusive [lo, hi] range. Nil for every other
	// instruction (and for StringSwitchImm, whose table is a different
	// format this decoder does not read).
	JumpTable []uint32
}

// Size returns the encoded size of the instruction (opcode byte plus all
// operand bytes). Jump tables are not counted; they are placed separately
// by the function encoder.
func (in *Instruction) Size() int {
	if in.Op == nil {
		return 1
	}
	return in.Op.Size
}

// Name returns the instruction mnemonic, or "<Unknown>" for raw opcodes.
func (in *Instruction) Name() string {
	if in.Op == nil {
		return "<Unknown>"
	}
	return in.Op.Name
}

// NextOffset is the offset of the instruction following this one in a
// well-formed stream (jump tables excluded).
func (in *Instruction) NextOffset() uint32 {
	return in.Offset + uint32(in.Size())
}

// Operand returns the raw bit pattern of operand i, or 0 when i is out of
// range.
func (in *Instruction) Operand(i int) uint64 {
	if i < 0 || i >= len(in.Operands) {
		return 0
	}
	return in.Operands[i]
}

// Function is one decoded function header plus (after decoding) its
// instruction stream.
type Function struct {
	Index uint32

	// Name is the resolved function name string; NameID is its string
	// table index.
	Name   string
	NameID uint32

	// Offset is the absolute file offset of this function's bytecode.
	Offset uint32
	// BytecodeSizeInBytes includes any jump/string switch tables appended
	// to the instruction stream.
	BytecodeSizeInBytes uint32
	// Bytecode aliases Module.Raw; nil when the declared range is out of
	// bounds.
	Bytecode []byte

	ParamCount uint32
	LoopDepth  uint32 // v98+

	FrameSize            uint32
	EnvironmentSize      uint32 // v<97
	NumberRegCount       uint32
	NonPtrRegCount       uint32
	ReadCacheSize        uint8
	WriteCacheSize       uint8
	PrivateNameCacheSize uint8
	// HighestReadCacheIndex/HighestWriteCacheIndex are the v<98 names of
	// the same bytes modelled as ReadCacheSize/WriteCacheSize in v98+.
	HighestReadCacheIndex  uint8
	HighestWriteCacheIndex uint8

	InfoOffset uint32 // v<97: file offset of the function info block

	ProhibitInvoke      uint8
	Kind                FunctionKind
	StrictMode          bool
	HasExceptionHandler bool
	HasDebugInfo        bool
	Overflowed          bool

	ExceptionHandlers []ExceptionHandler
	DebugOffsets      *DebugOffsets

	// SmallHeaderOffset is the absolute file offset of this function's
	// 12/16-byte entry in the function header table.
	SmallHeaderOffset int64
	// LargeHeaderOffset is the absolute file offset of the separately
	// stored FunctionHeader; meaningful only when Overflowed.
	LargeHeaderOffset int64

	// Instructions is populated by parser.Decode while iterating the
	// bytecode, and left nil by container-only parsing.
	Instructions []Instruction
}

// Module is a fully parsed Hermes bytecode file.
type Module struct {
	Header  Header
	Version uint32

	StringKindRuns []StringKindRun
	// StringKinds is the expanded run-length encoding, one entry per
	// string in Strings.
	StringKinds []StringKind

	IdentifierHashes []uint32

	Strings []string

	// LiteralValueBuffer holds v97+ array/object literal values (SLP).
	LiteralValueBuffer []byte
	// ArrayBuffer holds the v<97 equivalent.
	ArrayBuffer     []byte
	ObjectKeyBuffer []byte
	// ObjectValueBuffer holds v<97 object literal values (SLP).
	ObjectValueBuffer []byte
	// ObjectShapeTable is the v97+ shape table. Shape keys are decoded
	// on demand from ObjectKeyBuffer by consumers that render them.
	ObjectShapeTable []ShapeTableEntry

	BigInts       []BigInt
	BigIntData    []byte
	RegExpTable   []RegExpRef
	RegExpStorage []byte

	CJSModules      []CJSModule
	FunctionSources []FunctionSource

	Functions []Function

	// Raw is the full file contents. Functions' Bytecode fields and the
	// buffers above are sub-slices of it.
	Raw []byte
}

// StringAt resolves a string table index, reporting whether it is in range.
func (m *Module) StringAt(id uint32) (string, bool) {
	if id >= uint32(len(m.Strings)) {
		return "", false
	}
	return m.Strings[id], true
}

// FunctionByName returns the first function whose resolved name matches.
func (m *Module) FunctionByName(name string) (int, bool) {
	for i := range m.Functions {
		if m.Functions[i].Name == name {
			return i, true
		}
	}
	return 0, false
}
