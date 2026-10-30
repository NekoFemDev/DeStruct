// Package disasm renders a parsed ir.Module back into text.
//
// The output is the canonical hermes-dec exact format (the dialect hermes-dec's
// ParsedInstruction.__repr__ and disassemble_function() produce):
//
//	=> [Function #0 "global" of 118943 bytes]: 1 params, frame size=21, strict=0, exc handler=1, debug info=0  @ offset 0x0035ab04
//	  [Exception handlers: [start=0xdb, end=0x128, target=0x12a] ]
//
//	Bytecode listing:
//
//	==> 00000000: <Jmp>: <Addr8: 87>  # Address: 00000057
//	...
//
//	===============
//
// The asm package consumes this same text, so disassembly -> edit ->
// assembly round-trips through one dialect.
package disasm

import (
	"context"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/destruct/destruct/internal/hermes/ir"
	"github.com/destruct/destruct/internal/hermes/opcodes"
	"github.com/destruct/destruct/internal/hermes/opcodes/registry"
	"github.com/destruct/destruct/internal/hermes/parser"
)

// Options controls rendering.
type Options struct {
	// Editable appends one "    case N: XXXXXXXX" line after every
	// switch instruction's jump table so cases can be retargeted through
	// the text. This is a deliberate extension over the reference
	// hermes-dec format (which never prints case lines); the default
	// output stays byte-identical to hermes-dec.
	Editable bool
}

// Disassemble renders every function of m into a string.
func Disassemble(m *ir.Module) (string, error) {
	var b strings.Builder
	b.Grow(estimateSize(m))
	if err := Write(&b, m, Options{}); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Write renders every function of m into w. It decodes any function that
// has not been decoded yet.
func Write(w io.Writer, m *ir.Module, opts Options) error {
	return WriteContext(context.Background(), w, m, opts)
}

// WriteContext is Write with cancellation: ctx is checked per function
// and per instruction.
func WriteContext(ctx context.Context, w io.Writer, m *ir.Module, opts Options) error {
	if m.Version == 0 {
		return fmt.Errorf("module has no version")
	}
	table, err := registry.Lookup(m.Version)
	if err != nil {
		return err
	}
	if err := parser.Decode(m); err != nil {
		return err
	}

	r := &renderer{
		m:         m,
		table:     table,
		builtins:  registry.Builtins(m.Version),
		shapeKeys: make(map[uint32][]string),
	}
	for i := range m.Functions {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.writeFunction(ctx, w, i, opts); err != nil {
			return err
		}
	}
	return nil
}

// Function renders one function's section into a string.
func Function(m *ir.Module, index int) (string, error) {
	var b strings.Builder
	if err := WriteFunction(&b, m, index, Options{}); err != nil {
		return "", err
	}
	return b.String(), nil
}

// FormatInstruction renders one decoded instruction exactly as it appears
// after the "==> " prefix of a disassembly line. It exists for tools
// (such as the interactive patcher) that present individual instructions
// without writing a whole function section.
func FormatInstruction(m *ir.Module, in *ir.Instruction) (string, error) {
	table, err := registry.Lookup(m.Version)
	if err != nil {
		return "", err
	}
	r := &renderer{
		m:         m,
		table:     table,
		builtins:  registry.Builtins(m.Version),
		shapeKeys: make(map[uint32][]string),
	}
	return r.instruction(in), nil
}

// WriteFunction renders one function's section into w.
func WriteFunction(w io.Writer, m *ir.Module, index int, opts Options) error {
	return WriteFunctionContext(context.Background(), w, m, index, opts)
}

// WriteFunctionContext is WriteFunction with cancellation.
func WriteFunctionContext(ctx context.Context, w io.Writer, m *ir.Module, index int, opts Options) error {
	table, err := registry.Lookup(m.Version)
	if err != nil {
		return err
	}
	if err := parser.Decode(m); err != nil {
		return err
	}
	if index < 0 || index >= len(m.Functions) {
		return fmt.Errorf("function index %d out of range (module has %d functions)", index, len(m.Functions))
	}
	r := &renderer{
		m:         m,
		table:     table,
		builtins:  registry.Builtins(m.Version),
		shapeKeys: make(map[uint32][]string),
	}
	return r.writeFunction(ctx, w, index, opts)
}

// estimateSize guesses an initial builder capacity so the whole-file
// disassembly does not repeatedly grow and copy.
func estimateSize(m *ir.Module) int {
	total := 0
	for i := range m.Functions {
		total += 80 + len(m.Functions[i].Bytecode)*3
	}
	return total
}

type renderer struct {
	m        *ir.Module
	table    *opcodes.Table
	builtins []string
	// shapeKeys caches decoded v97+ object shape key lists by shape id.
	shapeKeys map[uint32][]string
}

// functionKindNames mirrors hermes-dec's FunctionKind enum names.
func functionKindName(kind ir.FunctionKind) string {
	switch kind {
	case ir.FunctionKindGenerator:
		return "Generator function"
	case ir.FunctionKindAsync:
		return "Async function"
	default:
		return "Function"
	}
}

func (r *renderer) writeFunction(ctx context.Context, w io.Writer, index int, opts Options) error {
	f := &r.m.Functions[index]

	var exceptionInfo strings.Builder
	if f.HasExceptionHandler {
		exceptionInfo.WriteString("\n  [Exception handlers:")
		for _, h := range f.ExceptionHandlers {
			fmt.Fprintf(&exceptionInfo, " [start=0x%x, end=0x%x, target=0x%x]", h.Start, h.End, h.Target)
		}
		exceptionInfo.WriteString(" ]")
	}

	var debugInfo strings.Builder
	if f.HasDebugInfo && f.DebugOffsets != nil {
		fmt.Fprintf(&debugInfo, "\n  [Debug offsets: source_locs=0x%x, scope_desc_data=0x%x]",
			f.DebugOffsets.SourceLocations, f.DebugOffsets.ScopeDescData)
	}

	if _, err := fmt.Fprintf(w,
		"=> [%s #%d \"%s\" of %d bytes]: %d params, frame size=%d, strict=%s, exc handler=%s, debug info=%s  @ offset 0x%08x%s%s\n",
		functionKindName(f.Kind), index, f.Name, f.BytecodeSizeInBytes,
		f.ParamCount, f.FrameSize,
		pyBit(f.StrictMode), pyBit(f.HasExceptionHandler), pyBit(f.HasDebugInfo),
		f.Offset, exceptionInfo.String(), debugInfo.String()); err != nil {
		return err
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Bytecode listing:")
	fmt.Fprintln(w)

	for i := range f.Instructions {
		if err := ctx.Err(); err != nil {
			return err
		}
		in := &f.Instructions[i]
		if _, err := fmt.Fprintf(w, "==> %s\n", r.instruction(in)); err != nil {
			return err
		}
		if opts.Editable && len(in.JumpTable) > 0 {
			switch in.Name() {
			case "SwitchImm", "UIntSwitchImm":
				for caseIndex, target := range in.JumpTable {
					if _, err := fmt.Fprintf(w, "    case %d: %08x\n", caseIndex, target); err != nil {
						return err
					}
				}
			}
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.Repeat("=", 15))
	fmt.Fprintln(w)
	return nil
}

// instruction renders one "==> ..." line body, matching
// ParsedInstruction.__repr__.
func (r *renderer) instruction(in *ir.Instruction) string {
	if in.Op == nil {
		return fmt.Sprintf("%08x: <<Unknown 0x%02x>>: <>", in.Offset, in.RawOp)
	}

	parts := make([]string, len(in.Op.Operands))
	for i, operand := range in.Op.Operands {
		parts[i] = fmt.Sprintf("%s: %s", operandTypeName(operand), operandValueString(in, i))
	}

	return fmt.Sprintf("%08x: <%s>: <%s>%s", in.Offset, in.Op.Name, strings.Join(parts, ", "), r.buildComment(in))
}

// operandTypeName returns the label before ": value" for one operand: the
// meaning name when the operand references a side table, the storage type
// otherwise.
func operandTypeName(operand opcodes.Operand) string {
	if name := operand.Meaning.String(); name != "" {
		return name
	}
	return operand.Type.String()
}

// operandValueString renders the operand value the way Python's %r does:
// plain integers for integer storage (sign-extended for signed types),
// Python str() of the float for Double
func operandValueString(in *ir.Instruction, index int) string {
	if index >= len(in.Op.Operands) {
		return "0"
	}
	operand := in.Op.Operands[index]
	raw := in.Operand(index)

	switch operand.Type {
	case opcodes.Double:
		return formatPyFloat(math.Float64frombits(raw))
	case opcodes.Addr8:
		return fmt.Sprintf("%d", int8(raw))
	case opcodes.Addr32, opcodes.Imm32:
		return fmt.Sprintf("%d", int32(raw))
	default:
		return fmt.Sprintf("%d", raw)
	}
}

// buildComment reproduces the comment section of __repr__: one fragment
// per operand meaning (string_id / bigint_id / function_id) interleaved
// with jump target fragments for Addr operands, then the special
// array/object/builtin/jump-table fragments.
func (r *renderer) buildComment(in *ir.Instruction) string {
	var comment strings.Builder

	for i, operand := range in.Op.Operands {
		switch operand.Meaning {
		case opcodes.MeaningStringID:
			id := int(in.Operand(i))
			if id >= 0 && id < len(r.m.Strings) {
				fmt.Fprintf(&comment, "  # String: %s (%s)", pyRepr(r.m.Strings[id]), r.stringKindName(id))
			} else {
				fmt.Fprintf(&comment, "  # String: <bad_string_id:%d>", id)
			}
		case opcodes.MeaningBigIntID:
			id := int(in.Operand(i))
			if id >= 0 && id < len(r.m.BigInts) {
				fmt.Fprintf(&comment, "  # BigInt: %s", r.m.BigInts[id].Value)
			} else {
				fmt.Fprintf(&comment, "  # BigInt: <bad_bigint_id:%d>", id)
			}
		case opcodes.MeaningFunctionID:
			id := int(in.Operand(i))
			r.appendFunctionComment(&comment, id)
		default:
			if operand.Type.IsAddr() {
				target := in.Offset + uint32(int32(in.Operand(i)))
				fmt.Fprintf(&comment, "  # Address: %08x", target)
			}
		}
	}

	switch in.Name() {
	case "NewArrayWithBuffer", "NewArrayWithBufferLong":
		r.appendArrayComment(&comment, in)
	case "NewObjectWithBuffer", "NewObjectWithBufferLong":
		r.appendObjectComment(&comment, in)
	case "CallBuiltin", "CallBuiltinLong", "GetBuiltinClosure":
		r.appendBuiltinComment(&comment, in)
	case "SwitchImm":
		// The reference tool prints the jump table comment only for
		// instructions named "SwitchImm" (the pre-v98 spelling), never
		// for "UIntSwitchImm"; reproduced here for byte-exactness.
		targets := make([]string, len(in.JumpTable))
		for i, target := range in.JumpTable {
			targets[i] = fmt.Sprintf("%08x", target)
		}
		fmt.Fprintf(&comment, "  # Jump table: [%s]", strings.Join(targets, ", "))
	}

	return comment.String()
}

func (r *renderer) stringKindName(id int) string {
	if id < 0 || id >= len(r.m.StringKinds) {
		return "String"
	}
	return r.m.StringKinds[id].String()
}

func (r *renderer) appendFunctionComment(comment *strings.Builder, id int) {
	if id < 0 || id >= len(r.m.Functions) {
		fmt.Fprintf(comment, "  # Function: <bad_function_id:%d>", id)
		return
	}
	f := &r.m.Functions[id]
	// f.Name may legitimately be empty (an empty name string); the
	// reference tool prints it as-is.
	fmt.Fprintf(comment, "  # Function: [#%d %s of %d bytes]: %d params @ offset 0x%08x",
		id, f.Name, f.BytecodeSizeInBytes, f.ParamCount, f.Offset)
}

// appendArrayComment reproduces "# Array: [...]" for
// NewArrayWithBuffer / NewArrayWithBufferLong. Operand layout:
// arg1=dst, arg2=numElements, arg3=numLiterals, arg4=bufferIndex.
func (r *renderer) appendArrayComment(comment *strings.Builder, in *ir.Instruction) {
	if len(in.Operands) < 4 {
		return
	}
	numLiterals := int(in.Operand(2))
	bufferIndex := int(in.Operand(3))

	buf := r.m.LiteralValueBuffer
	if r.m.Version < 97 {
		buf = r.m.ArrayBuffer
	}
	if bufferIndex < 0 {
		bufferIndex = 0
	}
	if bufferIndex > len(buf) {
		bufferIndex = len(buf)
	}

	items := unpackSLPArray(buf[bufferIndex:], numLiterals, r.m.Version).toStrings(r.m.Strings)
	fmt.Fprintf(comment, "  # Array: [%s]", strings.Join(items, ", "))
}

// appendObjectComment reproduces "# Object: {...}" for
// NewObjectWithBuffer / NewObjectWithBufferLong, using the pre-v97
// key/value buffers or the v97+ shape table depending on the version.
func (r *renderer) appendObjectComment(comment *strings.Builder, in *ir.Instruction) {
	if r.m.Version < 97 {
		if len(in.Operands) < 5 {
			return
		}
		numLiterals := int(in.Operand(2))
		keyIndex := clampIndex(int(in.Operand(3)), len(r.m.ObjectKeyBuffer))
		valIndex := clampIndex(int(in.Operand(4)), len(r.m.ObjectValueBuffer))

		keys := unpackSLPArray(r.m.ObjectKeyBuffer[keyIndex:], numLiterals, r.m.Version).toStrings(r.m.Strings)
		vals := unpackSLPArray(r.m.ObjectValueBuffer[valIndex:], numLiterals, r.m.Version).toStrings(r.m.Strings)
		r.appendKeyValuePairs(comment, keys, vals)
		return
	}

	if len(in.Operands) < 3 {
		return
	}
	shapeID := in.Operand(1)
	valIndex := clampIndex(int(in.Operand(2)), len(r.m.LiteralValueBuffer))

	keys, ok := r.objectShapeKeys(shapeID)
	if !ok {
		fmt.Fprintf(comment, "  # Object: <bad_shape_id:%d>", shapeID)
		return
	}

	vals := unpackSLPArray(r.m.LiteralValueBuffer[valIndex:], len(keys), r.m.Version).toStrings(r.m.Strings)
	r.appendKeyValuePairs(comment, keys, vals)
}

func (r *renderer) appendKeyValuePairs(comment *strings.Builder, keys, vals []string) {
	n := len(keys)
	if len(vals) < n {
		n = len(vals)
	}
	pairs := make([]string, n)
	for i := 0; i < n; i++ {
		pairs[i] = fmt.Sprintf("%s: %s", keys[i], vals[i])
	}
	fmt.Fprintf(comment, "  # Object: {%s}", strings.Join(pairs, ", "))
}

// objectShapeKeys returns the decoded key list for a v97+ shape table
// entry, caching the decode per shape id.
func (r *renderer) objectShapeKeys(shapeID uint64) ([]string, bool) {
	if shapeID >= uint64(len(r.m.ObjectShapeTable)) {
		return nil, false
	}
	if keys, ok := r.shapeKeys[uint32(shapeID)]; ok {
		return keys, true
	}
	entry := r.m.ObjectShapeTable[shapeID]
	offset := clampIndex(int(entry.KeyBufferOffset), len(r.m.ObjectKeyBuffer))
	keys := unpackSLPArray(r.m.ObjectKeyBuffer[offset:], int(entry.NumProps), r.m.Version).toStrings(r.m.Strings)
	r.shapeKeys[uint32(shapeID)] = keys
	return keys, true
}

// appendBuiltinComment reproduces "# Built-in function: [#N name]" for
// CallBuiltin / CallBuiltinLong / GetBuiltinClosure; operand 2 is the
// builtin number.
func (r *renderer) appendBuiltinComment(comment *strings.Builder, in *ir.Instruction) {
	if len(in.Operands) < 2 {
		return
	}
	builtinNumber := int(in.Operand(1))
	name := "<unknown>"
	if builtinNumber >= 0 && builtinNumber < len(r.builtins) {
		name = r.builtins[builtinNumber]
	}
	fmt.Fprintf(comment, "  # Built-in function: [#%d %s]", builtinNumber, name)
}

func clampIndex(index, length int) int {
	if index < 0 {
		return 0
	}
	if index > length {
		return length
	}
	return index
}
