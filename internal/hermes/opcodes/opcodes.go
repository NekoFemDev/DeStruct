// Package opcodes holds DeStruct's Hermes bytecode instruction metadata:
// the operand type model, the Table/Opcode structures every disassembler
// and assembler pass reads from, and the version registry that maps a
// file's bytecode version to its table.
//
// The actual per-version tables live in the version sub-packages
// (opcodes/hbc59 ... opcodes/hbc99) as generated, pure data. Nothing in
// this package knows how to read a file; see package parser for that.
//
//go:generate go run ./gen
package opcodes

import "fmt"

// OperandType is the storage class of one instruction operand. Sizes and
// signedness mirror the DEFINE_OPERAND_TYPE declarations in Hermes's
// BytecodeList.def.
type OperandType uint8

const (
	InvalidOperand OperandType = iota

	Reg8
	Reg32
	UInt8
	UInt16
	UInt32
	Addr8
	Addr32
	Imm32
	Double
)

func (t OperandType) String() string {
	switch t {
	case Reg8:
		return "Reg8"
	case Reg32:
		return "Reg32"
	case UInt8:
		return "UInt8"
	case UInt16:
		return "UInt16"
	case UInt32:
		return "UInt32"
	case Addr8:
		return "Addr8"
	case Addr32:
		return "Addr32"
	case Imm32:
		return "Imm32"
	case Double:
		return "Double"
	default:
		return "Invalid"
	}
}

// ParseOperandType maps a data-file operand type name back to its enum
// value. It is used by the opcode-table generator and by tests.
func ParseOperandType(s string) (OperandType, error) {
	switch s {
	case "Reg8":
		return Reg8, nil
	case "Reg32":
		return Reg32, nil
	case "UInt8":
		return UInt8, nil
	case "UInt16":
		return UInt16, nil
	case "UInt32":
		return UInt32, nil
	case "Addr8":
		return Addr8, nil
	case "Addr32":
		return Addr32, nil
	case "Imm32":
		return Imm32, nil
	case "Double":
		return Double, nil
	default:
		return InvalidOperand, fmt.Errorf("unknown operand type %q", s)
	}
}

// Size returns the operand's size in bytes on disk.
func (t OperandType) Size() int {
	switch t {
	case Reg8, UInt8, Addr8:
		return 1
	case UInt16:
		return 2
	case Reg32, UInt32, Addr32, Imm32:
		return 4
	case Double:
		return 8
	default:
		return 0
	}
}

// IsSigned reports whether the operand is sign-extended on decode and
// range-checked as signed on encode (Addr8/Addr32 are signed relative
// jump displacements; Imm32 is a signed integer literal).
func (t OperandType) IsSigned() bool {
	switch t {
	case Addr8, Addr32, Imm32:
		return true
	default:
		return false
	}
}

// IsAddr reports whether the operand is a code address (a signed offset
// relative to the instruction's own offset).
func (t OperandType) IsAddr() bool {
	return t == Addr8 || t == Addr32
}

// IsRegister reports whether the operand names a register.
func (t OperandType) IsRegister() bool {
	return t == Reg8 || t == Reg32
}

// Meaning annotates an operand that is an index into one of the file's
// side tables. It changes how the value is rendered (a string reference
// gets its string printed next to it) but not how it is decoded.
type Meaning uint8

const (
	MeaningNone Meaning = iota
	MeaningStringID
	MeaningFunctionID
	MeaningBigIntID
)

func (m Meaning) String() string {
	switch m {
	case MeaningNone:
		return ""
	case MeaningStringID:
		return "string_id"
	case MeaningFunctionID:
		return "function_id"
	case MeaningBigIntID:
		return "bigint_id"
	default:
		return "unknown"
	}
}

// Operand is the static description of one instruction operand.
type Operand struct {
	Type    OperandType
	Meaning Meaning
}

// Opcode is the static description of one instruction. Values are filled
// in from the version sub-package tables; the derived fields (Size,
// LongForm) are computed by NewTable.
type Opcode struct {
	Name     string
	Value    byte
	Operands []Operand
	// HasRetTarget mirrors DEFINE_RET_TARGET in BytecodeList.def: the
	// instruction may be the target of a Ret.
	HasRetTarget bool

	// Size is the full encoded size: opcode byte plus operand bytes.
	Size int
	// LongForm points at the Addr32 form of this instruction when one
	// exists (Jmp -> JmpLong), and is used by the assembler's jump
	// relaxation pass. Nil when the instruction has no long form.
	LongForm *Opcode
	// ShortForm is the reverse pointer of LongForm.
	ShortForm *Opcode
}

// Table is the opcode table for one bytecode version.
type Table struct {
	Version uint32

	// ByValue indexes instructions by their opcode byte.
	ByValue [256]*Opcode
	// ByName indexes instructions by mnemonic.
	ByName map[string]*Opcode
	// Ordered lists every instruction in opcode order.
	Ordered []*Opcode
}

// NewTable builds a table from instructions declared in opcode order,
// assigns each instruction its opcode byte from its position, computes
// encoded sizes, and links Addr8 instructions to their Addr32 long form.
// It panics on malformed generator output (duplicate names, > 256
// opcodes), because tables are compile-time constants generated from
// vendored data.
func NewTable(version uint32, instructions []*Opcode) *Table {
	if len(instructions) > 256 {
		panic(fmt.Sprintf("opcodes: version %d declares %d instructions (max 256)", version, len(instructions)))
	}
	t := &Table{
		Version: version,
		ByName:  make(map[string]*Opcode, len(instructions)),
		Ordered: instructions,
	}
	for i, op := range instructions {
		if op == nil {
			panic(fmt.Sprintf("opcodes: version %d has nil instruction at index %d", version, i))
		}
		if _, dup := t.ByName[op.Name]; dup {
			panic(fmt.Sprintf("opcodes: version %d declares %q twice", version, op.Name))
		}
		op.Value = byte(i)
		size := 1
		for _, operand := range op.Operands {
			size += operand.Type.Size()
		}
		op.Size = size
		t.ByValue[byte(i)] = op
		t.ByName[op.Name] = op
	}

	// Link short/long jump forms. Every Addr8 jump in the Hermes
	// instruction set has an Addr32 counterpart whose only layout
	// difference is that operand; requiring exactly that keep this from
	// mis-linking unrelated pairs that merely share the "Long" suffix
	// (Mov/MovLong).
	for _, op := range instructions {
		if !hasAddr8(op) {
			continue
		}
		long := t.ByName[op.Name+"Long"]
		if long == nil {
			continue
		}
		if !isLongFormOf(op, long) {
			continue
		}
		op.LongForm = long
		long.ShortForm = op
	}
	return t
}

func hasAddr8(op *Opcode) bool {
	for _, operand := range op.Operands {
		if operand.Type == Addr8 {
			return true
		}
	}
	return false
}

// isLongFormOf reports whether long is short's Addr32 counterpart: same
// operand count, and for every operand either identical types, or the one
// position where short has Addr8 and long has Addr32.
func isLongFormOf(short, long *Opcode) bool {
	if len(short.Operands) != len(long.Operands) {
		return false
	}
	addrDifferences := 0
	for i := range short.Operands {
		so, lo := short.Operands[i], long.Operands[i]
		if so.Type == lo.Type && so.Meaning == lo.Meaning {
			continue
		}
		if so.Type == Addr8 && lo.Type == Addr32 {
			addrDifferences++
			continue
		}
		return false
	}
	return addrDifferences == 1
}

// Opcode returns the instruction for a raw opcode byte, or nil when the
// byte is not a valid opcode in this version.
func (t *Table) Opcode(value byte) *Opcode {
	return t.ByValue[value]
}

// Find returns the instruction with the given mnemonic, or nil.
func (t *Table) Find(name string) *Opcode {
	return t.ByName[name]
}
