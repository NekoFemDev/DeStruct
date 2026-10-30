package asm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"

	"github.com/destruct/destruct/internal/hermes/ir"
	"github.com/destruct/destruct/internal/hermes/opcodes"
)

// This file assembles one function's edited instruction list back into
// bytecode, with iterative fixed-point address recalculation.
//
// The key invariant: an Addr operand's numeric value in the text is only
// meaningful relative to the layout the text was disassembled from. After
// LCS-aligning the edited instruction list against the function's current
// decoded instructions, every surviving branch is mapped to the
// instruction INDEX it targets in the edited list, and displacements are
// always recomputed from current offsets - never copied from the text.
// When a recomputed Addr8 displacement no longer fits a signed byte, the
// instruction is promoted to its Addr32 long form (Jmp -> JmpLong), which
// grows the layout; promotion is monotone and therefore terminates.

// maxRelaxPasses bounds the address relaxation loop. Each pass either
// promotes at least one instruction or stops, so the loop can never
// exceed the number of Addr8 instructions; the cap catches logic bugs.
const maxRelaxPasses = 128

// maxLCSCells bounds the LCS DP table size used during alignment; beyond
// this the middle region stays unresolved (see alignInstructions).
const maxLCSCells = 50_000_000

// asmLink is one instruction being assembled: its resolved opcode, raw
// operand values (Addr operands hold the original text's signed
// displacement until recomputed), and its settled offset within the
// function.
type asmLink struct {
	op     *opcodes.Opcode
	values []uint64
	offset uint32
	lineNo int
}

// switchTableToPlace describes a switch jump table that must be placed
// physically after the function's instruction stream, once the function's
// final absolute file offset is known.
type switchTableToPlace struct {
	// Arg2Offset is the offset within the function's encoded bytecode of
	// the 4-byte arg2 field (the table's relative offset), which is
	// patched after placement.
	Arg2Offset int
	// InstFuncOffset is the switch instruction's own offset within the
	// function's encoded bytecode.
	InstFuncOffset int
	// TableBytes is the encoded table (4 bytes per case, each a delta
	// relative to the instruction).
	TableBytes []byte
}

// assembleFunctionBytecode turns one parsed function's instructions into
// final bytecode, resolving addresses against the function's current
// decoded instructions and promoting Addr8 branches as needed.
func (a *assembler) assembleFunctionBytecode(funcIdx int, hf hasmFunction) ([]byte, []switchTableToPlace, error) {
	links := make([]asmLink, len(hf.Instructions))
	for i, hi := range hf.Instructions {
		op := a.table.Find(hi.Name)
		if op == nil {
			return nil, nil, fmt.Errorf("line %d: unknown instruction %q for this file's bytecode version", hi.LineNo, hi.Name)
		}
		if op.Name == "StringSwitchImm" {
			return nil, nil, fmt.Errorf("line %d: %s is not supported by the assembler (its jump table format is not reassembled)", hi.LineNo, op.Name)
		}
		if len(hi.Operands) != len(op.Operands) {
			return nil, nil, fmt.Errorf("line %d: %s expects %d operands, got %d", hi.LineNo, hi.Name, len(op.Operands), len(hi.Operands))
		}

		values := make([]uint64, len(op.Operands))
		for j, operand := range op.Operands {
			text := hi.Operands[j].Value
			if operand.Type.IsAddr() {
				v, err := strconv.ParseInt(text, 10, 64)
				if err != nil {
					return nil, nil, fmt.Errorf("line %d: invalid address operand %q: %w", hi.LineNo, text, err)
				}
				values[j] = uint64(v)
				continue
			}
			v, err := parseOperandValue(text, operand)
			if err != nil {
				return nil, nil, fmt.Errorf("line %d: operand %d of %s: %w", hi.LineNo, j+1, hi.Name, err)
			}
			values[j] = v
		}
		links[i] = asmLink{op: op, values: values, lineNo: hi.LineNo}
	}

	current := a.m.Functions[funcIdx].Instructions
	if current == nil {
		return nil, nil, fmt.Errorf("function #%d has not been decoded; call parser.Decode on the module first", funcIdx)
	}
	currentOffsets := make([]uint32, len(current))
	for i := range current {
		currentOffsets[i] = current[i].Offset
	}

	// Align the edited list against the current (pre-edit) instructions,
	// so every branch's target instruction can be identified by identity
	// rather than by arithmetic on stale offsets.
	alignment := a.alignInstructions(current, hf.Instructions) // alignment[editedIdx] = currentIdx or -1
	editedIdxOfCurrent := make(map[int]int, len(current))
	for editedIdx, curIdx := range alignment {
		if curIdx >= 0 {
			editedIdxOfCurrent[curIdx] = editedIdx
		}
	}

	// Resolve every Addr operand to the edited instruction index it
	// targets.
	targetIdx := make([][]int, len(links))
	for i := range links {
		targetIdx[i] = make([]int, len(links[i].values))
		for j, operand := range links[i].op.Operands {
			if !operand.Type.IsAddr() {
				targetIdx[i][j] = -1
				continue
			}
			curIdx := alignment[i]
			if curIdx < 0 {
				return nil, nil, fmt.Errorf("line %d: this %s was inserted or changed, so its address operand can't be resolved against the file's current layout - address operands can only be edited by changing the VALUE on an unchanged instruction, not by introducing a new branch instruction with a hand-written address", links[i].lineNo, links[i].op.Name)
			}
			relOffset := int64(links[i].values[j])
			targetByteOffset := int64(currentOffsets[curIdx]) + relOffset
			curTargetIdx := findInstructionIndexAtOffset(currentOffsets, targetByteOffset)
			if curTargetIdx < 0 {
				return nil, nil, fmt.Errorf("line %d: address operand targets byte offset %d in the current file, which is not the start of any instruction in this function", links[i].lineNo, targetByteOffset)
			}
			editedTargetIdx, ok := editedIdxOfCurrent[curTargetIdx]
			if !ok {
				return nil, nil, fmt.Errorf("line %d: this %s's target instruction was removed by this edit; a branch's target must still exist somewhere in the edited function", links[i].lineNo, links[i].op.Name)
			}
			targetIdx[i][j] = editedTargetIdx
		}
	}

	// Resolve switch jump table cases the same way: case targets are
	// function-relative byte offsets in the current file's layout. With
	// no case lines in the text, fall back to the switch's existing table
	// when it survived the edit.
	switchTargetIdx := make([][]int, len(links))
	for i := range links {
		if links[i].op.Name != "SwitchImm" && links[i].op.Name != "UIntSwitchImm" {
			continue
		}
		cases := hf.Instructions[i].SwitchCases
		curIdx := alignment[i]

		if len(cases) == 0 {
			if curIdx < 0 {
				return nil, nil, fmt.Errorf("line %d: this %s is new or was changed by this edit, so it needs explicit \"    case N: XXXXXXXX\" lines for its jump table - it has no existing table to fall back to", links[i].lineNo, links[i].op.Name)
			}
			existing := current[curIdx].JumpTable
			if len(existing) == 0 {
				continue
			}
			resolved := make([]int, len(existing))
			for k, target := range existing {
				curTargetIdx := findInstructionIndexAtOffset(currentOffsets, int64(target))
				if curTargetIdx < 0 {
					return nil, nil, fmt.Errorf("line %d: this %s's existing case %d target %08x is not the start of any instruction in the current file (please report this as a bug)", links[i].lineNo, links[i].op.Name, k, target)
				}
				editedTargetIdx, ok := editedIdxOfCurrent[curTargetIdx]
				if !ok {
					return nil, nil, fmt.Errorf("line %d: this %s's existing case %d target instruction was removed by this edit; either restore it, or provide explicit \"    case N: XXXXXXXX\" lines retargeting this switch", links[i].lineNo, links[i].op.Name, k)
				}
				resolved[k] = editedTargetIdx
			}
			switchTargetIdx[i] = resolved
			continue
		}

		if curIdx < 0 {
			return nil, nil, fmt.Errorf("line %d: this %s was inserted or changed, so its jump table's case targets can't be resolved against the file's current layout", links[i].lineNo, links[i].op.Name)
		}
		resolved := make([]int, len(cases))
		for k, c := range cases {
			targetOffset, err := strconv.ParseUint(c.TargetHex, 16, 32)
			if err != nil {
				return nil, nil, fmt.Errorf("line %d: invalid case target %q: %w", c.LineNo, c.TargetHex, err)
			}
			curTargetIdx := findInstructionIndexAtOffset(currentOffsets, int64(targetOffset))
			if curTargetIdx < 0 {
				return nil, nil, fmt.Errorf("line %d: case target %s is not the start of any instruction in this function's current bytecode", c.LineNo, c.TargetHex)
			}
			editedTargetIdx, ok := editedIdxOfCurrent[curTargetIdx]
			if !ok {
				return nil, nil, fmt.Errorf("line %d: this case's target instruction was removed by this edit; a switch case's target must still exist somewhere in the edited function", c.LineNo)
			}
			resolved[k] = editedTargetIdx
		}
		switchTargetIdx[i] = resolved
	}

	// Fixed-point layout: recompute offsets, promote any Addr8 whose
	// displacement no longer fits into its long form, repeat until stable.
	for pass := 0; ; pass++ {
		if pass >= maxRelaxPasses {
			return nil, nil, fmt.Errorf("address layout did not converge after %d passes (please report this as a bug)", maxRelaxPasses)
		}

		off := uint32(0)
		for i := range links {
			links[i].offset = off
			off += uint32(links[i].op.Size)
		}

		changed := false
		for i := range links {
			for j, operand := range links[i].op.Operands {
				if operand.Type != opcodes.Addr8 {
					continue
				}
				tIdx := targetIdx[i][j]
				rel := int64(links[tIdx].offset) - int64(links[i].offset)
				if rel < math.MinInt8 || rel > math.MaxInt8 {
					long := links[i].op.LongForm
					if long == nil {
						return nil, nil, fmt.Errorf("line %d: %s's address no longer fits in a byte after this edit, and it has no *Long form to fall back to", links[i].lineNo, links[i].op.Name)
					}
					links[i].op = long
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	// Final encode.
	var buf bytes.Buffer
	var tablesToPlace []switchTableToPlace

	for i := range links {
		instFuncOffset := buf.Len()
		buf.WriteByte(links[i].op.Value)

		isSwitch := (links[i].op.Name == "SwitchImm" || links[i].op.Name == "UIntSwitchImm") && switchTargetIdx[i] != nil
		var arg2Offset int

		for j, operand := range links[i].op.Operands {
			if isSwitch && j == 1 {
				// arg2 (table offset) depends on where the table is
				// physically placed, which isn't known until this
				// function's final file offset settles; write a
				// placeholder and patch it later.
				arg2Offset = buf.Len()
				encodeOperand(&buf, operand, 0)
				continue
			}
			v := links[i].values[j]
			if operand.Type.IsAddr() {
				tIdx := targetIdx[i][j]
				v = uint64(int64(links[tIdx].offset) - int64(links[i].offset))
			}
			encodeOperand(&buf, operand, v)
		}

		if isSwitch {
			var tableBuf bytes.Buffer
			for _, tIdx := range switchTargetIdx[i] {
				rel := int64(links[tIdx].offset) - int64(links[i].offset)
				var b [4]byte
				binary.LittleEndian.PutUint32(b[:], uint32(rel))
				tableBuf.Write(b[:])
			}
			tablesToPlace = append(tablesToPlace, switchTableToPlace{
				Arg2Offset:     arg2Offset,
				InstFuncOffset: instFuncOffset,
				TableBytes:     tableBuf.Bytes(),
			})
		}
	}

	return buf.Bytes(), tablesToPlace, nil
}

// operandMask returns the low-bits mask covering an operand's storage
// size. The decoder sign-extends signed operands to 64 bits while the
// text parser truncates to the operand's size, so value comparisons must
// mask off anything above the operand width.
func operandMask(t opcodes.OperandType) uint64 {
	size := t.Size()
	if size >= 8 {
		return ^uint64(0)
	}
	return uint64(1)<<(uint(size)*8) - 1
}

// parseOperandValue parses one operand's text value into the raw bit
// pattern decode would have produced: IEEE-754 bits for Double, the
// two's-complement bit pattern truncated to the operand's size for signed
// integer types, the value itself for unsigned types.
func parseOperandValue(text string, operand opcodes.Operand) (uint64, error) {
	switch operand.Type {
	case opcodes.Double:
		f, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid Double value %q: %w", text, err)
		}
		return math.Float64bits(f), nil
	case opcodes.Addr8, opcodes.Addr32, opcodes.Imm32:
		v, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid signed value %q: %w", text, err)
		}
		switch operand.Type.Size() {
		case 1:
			if v < math.MinInt8 || v > math.MaxInt8 {
				return 0, fmt.Errorf("value %d out of range for %s (int8)", v, operand.Type)
			}
			return uint64(uint8(int8(v))), nil
		case 2:
			if v < math.MinInt16 || v > math.MaxInt16 {
				return 0, fmt.Errorf("value %d out of range for %s (int16)", v, operand.Type)
			}
			return uint64(uint16(int16(v))), nil
		case 4:
			if v < math.MinInt32 || v > math.MaxInt32 {
				return 0, fmt.Errorf("value %d out of range for %s (int32)", v, operand.Type)
			}
			return uint64(uint32(int32(v))), nil
		default:
			return uint64(v), nil
		}
	default:
		v, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid unsigned value %q: %w", text, err)
		}
		size := operand.Type.Size()
		maxVal := uint64(math.MaxUint64)
		if size < 8 {
			maxVal = uint64(1)<<(uint(size)*8) - 1
		}
		if v > maxVal {
			return 0, fmt.Errorf("value %d out of range for %s (%d bytes)", v, operand.Type, size)
		}
		return v, nil
	}
}

// encodeOperand appends the little-endian encoding of value for the given
// operand type.
func encodeOperand(buf *bytes.Buffer, operand opcodes.Operand, value uint64) {
	switch operand.Type.Size() {
	case 1:
		buf.WriteByte(byte(value))
	case 2:
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(value))
		buf.Write(b[:])
	case 4:
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(value))
		buf.Write(b[:])
	case 8:
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], value)
		buf.Write(b[:])
	}
}

// findInstructionIndexAtOffset returns the index whose offset equals
// target, or -1.
func findInstructionIndexAtOffset(offsets []uint32, target int64) int {
	if target < 0 {
		return -1
	}
	for i, off := range offsets {
		if int64(off) == target {
			return i
		}
	}
	return -1
}

// alignInstructions computes, for each instruction in edited, the index
// of the same instruction in current (or -1 when new/changed), using the
// standard LCS algorithm after stripping the common prefix and suffix so
// only the actually-edited middle region pays for the O(n*m) DP.
func (a *assembler) alignInstructions(current []ir.Instruction, edited []hasmInstruction) []int {
	n, m := len(current), len(edited)
	result := make([]int, m)
	for j := range result {
		result[j] = -1
	}

	prefix := 0
	for prefix < n && prefix < m && a.oneInstructionEqual(&current[prefix], &edited[prefix]) {
		result[prefix] = prefix
		prefix++
	}

	suffix := 0
	for suffix < n-prefix && suffix < m-prefix &&
		a.oneInstructionEqual(&current[n-1-suffix], &edited[m-1-suffix]) {
		result[m-1-suffix] = n - 1 - suffix
		suffix++
	}

	curMid := current[prefix : n-suffix]
	editMid := edited[prefix : m-suffix]

	if int64(len(curMid)+1)*int64(len(editMid)+1) > maxLCSCells {
		return result
	}

	midResult := a.lcsAlign(curMid, editMid)
	for j, idx := range midResult {
		if idx >= 0 {
			result[prefix+j] = prefix + idx
		}
	}
	return result
}

func (a *assembler) lcsAlign(current []ir.Instruction, edited []hasmInstruction) []int {
	n, m := len(current), len(edited)

	dp := make([][]int32, n+1)
	for i := range dp {
		dp[i] = make([]int32, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a.oneInstructionEqual(&current[i-1], &edited[j-1]) {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}

	result := make([]int, m)
	for j := range result {
		result[j] = -1
	}
	i, j := n, m
	for i > 0 && j > 0 {
		if a.oneInstructionEqual(&current[i-1], &edited[j-1]) {
			result[j-1] = i - 1
			i--
			j--
			continue
		}
		if dp[i-1][j] >= dp[i][j-1] {
			i--
		} else {
			j--
		}
	}
	return result
}

// oneInstructionEqual compares a current instruction with an edited one
// for LCS alignment: same name and same NON-ADDRESS operand values.
// Address operands are excluded so that retargeting a branch by editing
// only its displacement still aligns as "the same instruction".
func (a *assembler) oneInstructionEqual(current *ir.Instruction, edited *hasmInstruction) bool {
	if current.Op == nil || current.Op.Name != edited.Name {
		return false
	}
	if len(current.Operands) != len(edited.Operands) {
		return false
	}
	for j, operand := range current.Op.Operands {
		if operand.Type.IsAddr() {
			continue
		}
		v, err := parseOperandValue(edited.Operands[j].Value, operand)
		if err != nil {
			return false
		}
		if v&operandMask(operand.Type) != current.Operand(j)&operandMask(operand.Type) {
			return false
		}
	}
	return true
}

// instructionsEqual reports whether the current decoded instructions
// match the edited text exactly (name, all operand values including
// address displacements, and — only when the text carries case lines —
// switch jump table targets).
func (a *assembler) instructionsEqual(current []ir.Instruction, edited []hasmInstruction) bool {
	if len(current) != len(edited) {
		return false
	}
	for i := range current {
		cur := &current[i]
		ed := &edited[i]
		if cur.Op == nil || cur.Op.Name != ed.Name {
			return false
		}
		if len(cur.Operands) != len(ed.Operands) {
			return false
		}
		for j, operand := range cur.Op.Operands {
			var v uint64
			var err error
			if operand.Type.IsAddr() {
				var parsed int64
				parsed, err = strconv.ParseInt(ed.Operands[j].Value, 10, 64)
				v = uint64(parsed)
			} else {
				v, err = parseOperandValue(ed.Operands[j].Value, operand)
			}
			if err != nil || v&operandMask(operand.Type) != cur.Operand(j)&operandMask(operand.Type) {
				return false
			}
		}
		if len(ed.SwitchCases) == 0 {
			continue
		}
		if len(cur.JumpTable) != len(ed.SwitchCases) {
			return false
		}
		for j, c := range ed.SwitchCases {
			target, err := strconv.ParseUint(c.TargetHex, 16, 32)
			if err != nil || target != uint64(cur.JumpTable[j]) {
				return false
			}
		}
	}
	return true
}
