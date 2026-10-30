package parser

import (
	"encoding/binary"
	"fmt"

	"github.com/destruct/destruct/internal/hermes/ir"
	"github.com/destruct/destruct/internal/hermes/opcodes"
	"github.com/destruct/destruct/internal/hermes/opcodes/registry"
)

// maxJumpTableEntries bounds the number of switch jump table entries the
// decoder will ever read. lo/hi come straight from instruction operands;
// with a mismatched table or malformed bytecode hi-lo can approach 2^32,
// and without a cap that would drive a multi-gigabyte allocation. No real
// switch comes close to this many cases.
const maxJumpTableEntries = 1 << 20

// Decode decodes the instruction stream of every function in a module
// produced by Parse. It is idempotent: functions that already carry
// decoded instructions are skipped.
func Decode(m *ir.Module) error {
	table, err := registry.Lookup(m.Version)
	if err != nil {
		return err
	}
	for i := range m.Functions {
		f := &m.Functions[i]
		if f.Instructions != nil {
			continue
		}
		if err := decodeFunction(m, table, f); err != nil {
			return fmt.Errorf("function #%d %q: %w", i, f.Name, err)
		}
	}
	return nil
}

// DecodeFunction decodes the instruction stream of a single function.
func DecodeFunction(m *ir.Module, index int) error {
	if index < 0 || index >= len(m.Functions) {
		return fmt.Errorf("function index %d out of range (module has %d functions)", index, len(m.Functions))
	}
	table, err := registry.Lookup(m.Version)
	if err != nil {
		return err
	}
	return decodeFunction(m, table, &m.Functions[index])
}

func decodeFunction(m *ir.Module, table *opcodes.Table, f *ir.Function) error {
	code := f.Bytecode
	if code == nil {
		// The declared bytecode range was out of bounds; the function is
		// empty as far as decoding is concerned.
		f.Instructions = []ir.Instruction{}
		return nil
	}

	instrs := make([]ir.Instruction, 0, len(code)/2+1)
	for off := 0; off < len(code); {
		instr, size, err := decodeInstruction(m, table, f, code, off)
		if err != nil {
			return err
		}
		instrs = append(instrs, instr)
		if size <= 0 {
			return fmt.Errorf("instruction at offset %d does not advance", off)
		}
		off += size
	}
	f.Instructions = instrs
	return nil
}

func decodeInstruction(m *ir.Module, table *opcodes.Table, f *ir.Function, code []byte, off int) (ir.Instruction, int, error) {
	rawOp := code[off]
	op := table.Opcode(rawOp)
	if op == nil {
		return ir.Instruction{}, 0, fmt.Errorf("unknown opcode 0x%02x at offset %d (version %d table)", rawOp, off, m.Version)
	}

	in := ir.Instruction{
		Op:       op,
		RawOp:    rawOp,
		Offset:   uint32(off),
		Operands: make([]uint64, len(op.Operands)),
	}

	pos := off + 1
	for i, operand := range op.Operands {
		size := operand.Type.Size()
		if pos+size > len(code) {
			return ir.Instruction{}, 0, fmt.Errorf("operand %d of %s at offset %d runs past the end of the function", i, op.Name, off)
		}
		in.Operands[i] = decodeOperand(operand.Type, code[pos:pos+size])
		pos += size
	}

	switch op.Name {
	case "SwitchImm", "UIntSwitchImm":
		in.JumpTable = decodeSwitchTable(m, f, &in)
	}

	return in, op.Size, nil
}

// decodeOperand interprets operand bytes as the operand type. Signed
// types are sign-extended into the returned uint64 so that callers can
// use int64(value) directly; Double returns the IEEE-754 bit pattern.
func decodeOperand(t opcodes.OperandType, b []byte) uint64 {
	switch t {
	case opcodes.Reg8, opcodes.UInt8:
		return uint64(b[0])
	case opcodes.Addr8:
		return uint64(int64(int8(b[0])))
	case opcodes.UInt16:
		return uint64(binary.LittleEndian.Uint16(b))
	case opcodes.Reg32, opcodes.UInt32:
		return uint64(binary.LittleEndian.Uint32(b))
	case opcodes.Addr32, opcodes.Imm32:
		return uint64(int64(int32(binary.LittleEndian.Uint32(b))))
	case opcodes.Double:
		return binary.LittleEndian.Uint64(b)
	default:
		return 0
	}
}

// decodeSwitchTable reads the jump table appended to a SwitchImm /
// UIntSwitchImm. Layout (BytecodeList.def): operand 1 is the byte offset
// of the table relative to the instruction (unaligned; the table itself
// is 4-byte aligned in the file), operands 3 and 4 are the inclusive
// [lo, hi] value range, and the table holds one uint32 target per case,
// each a delta relative to the instruction. Targets are stored in the
// returned slice as function-relative byte offsets.
func decodeSwitchTable(m *ir.Module, f *ir.Function, in *ir.Instruction) []uint32 {
	if len(in.Operands) < 5 {
		return nil
	}

	lo, hi := in.Operands[3], in.Operands[4]
	if hi < lo {
		return nil
	}
	count := hi - lo + 1
	if count > maxJumpTableEntries {
		count = maxJumpTableEntries
	}

	// The table lives in file space; it can extend past the function's
	// declared bytecode, so read from the whole file.
	tableAbs := int64(f.Offset) + int64(in.Offset) + int64(int32(in.Operands[1]))
	if mod := tableAbs % 4; mod != 0 {
		tableAbs += 4 - mod
	}
	if tableAbs < 0 || tableAbs > int64(len(m.Raw)) {
		return nil
	}
	if avail := uint64(int64(len(m.Raw))-tableAbs) / 4; count > avail {
		count = avail
	}

	targets := make([]uint32, 0, count)
	pos := tableAbs
	for c := uint64(0); c < count; c++ {
		if pos+4 > int64(len(m.Raw)) {
			break
		}
		delta := binary.LittleEndian.Uint32(m.Raw[pos:])
		targets = append(targets, in.Offset+delta)
		pos += 4
	}
	return targets
}
