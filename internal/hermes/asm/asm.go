// Package asm assembles edited hermes-dec exact text back into a Hermes
// bytecode file.
//
// Assembly is always a patch against an existing, parsed module: the
// text references string/function/bigint ids that live in the original
// file's tables, so it can change what bytecode a function contains but
// not introduce new strings or functions. Only functions whose text
// differs from the current disassembly are reassembled, which keeps a
// one-line edit in a 40,000-function bundle a one-function operation.
//
// Every function's bytecode is packed contiguously in the file. Changing
// one function's size shifts every function physically after it, so all
// affected header offsets, the debug-info offset, the file length, and
// the SHA1 footer are rewritten. Switch jump tables are re-placed at the
// end of the bytecode segment (4-byte aligned), matching where Hermes
// itself puts them.
package asm

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/destruct/destruct/internal/hermes/ir"
	"github.com/destruct/destruct/internal/hermes/opcodes"
	"github.com/destruct/destruct/internal/hermes/opcodes/registry"
	"github.com/destruct/destruct/internal/hermes/parser"
)

// Result is the outcome of an assembly run.
type Result struct {
	// Data is the complete new .hbc file, including a recomputed SHA1
	// footer.
	Data []byte
	// ChangedFunctions lists the indices of functions whose bytecode was
	// actually replaced, in ascending text order.
	ChangedFunctions []uint32
	// SizeDelta is the net bytecode-segment size change in bytes.
	SizeDelta int
}

// Assemble applies the edits in hasm to the module m (which must have
// been produced by parser.Parse of the file the text was disassembled
// from) and returns the complete new file. Functions absent from the
// text, or whose text is identical to the current disassembly, are left
// byte-for-byte untouched.
func Assemble(m *ir.Module, hasm string) (*Result, error) {
	table, err := registry.Lookup(m.Version)
	if err != nil {
		return nil, err
	}
	// Instruction decoding is required for the edit-alignment pass.
	if err := parser.Decode(m); err != nil {
		return nil, err
	}

	funcs, err := parseHASM(hasm)
	if err != nil {
		return nil, err
	}

	a := &assembler{m: m, table: table}
	changedIdx, err := a.changedFunctions(funcs)
	if err != nil {
		return nil, err
	}
	if len(changedIdx) == 0 {
		out := append([]byte(nil), m.Raw...)
		return &Result{Data: out}, nil
	}

	hasmByIndex := make(map[uint32]hasmFunction, len(funcs))
	for _, hf := range funcs {
		hasmByIndex[uint32(hf.Index)] = hf
	}

	// Assemble every changed function against the CURRENT layout first;
	// patching happens afterwards, in physical order.
	newCode := make(map[uint32][]byte, len(changedIdx))
	newTables := make(map[uint32][]switchTableToPlace, len(changedIdx))
	for _, idx := range changedIdx {
		code, tables, err := a.assembleFunctionBytecode(int(idx), hasmByIndex[idx])
		if err != nil {
			return nil, fmt.Errorf("function #%d: %w", idx, err)
		}
		newCode[idx] = code
		newTables[idx] = tables
	}

	s := &fileState{
		m:      m,
		data:   append([]byte(nil), m.Raw...),
		fns:    append([]ir.Function(nil), m.Functions...),
		header: m.Header,
	}

	// Apply patches in ascending physical offset order so each patch's
	// downstream shift is folded into the next.
	order := make([]uint32, len(changedIdx))
	copy(order, changedIdx)
	sort.Slice(order, func(i, j int) bool { return s.fns[order[i]].Offset < s.fns[order[j]].Offset })

	changedSet := make(map[uint32]bool, len(changedIdx))
	for _, idx := range changedIdx {
		changedSet[idx] = true
	}

	totalDelta := 0
	for _, idx := range order {
		delta, err := s.patchOneFunction(idx, newCode[idx], newTables[idx], changedSet)
		if err != nil {
			return nil, fmt.Errorf("function #%d: %w", idx, err)
		}
		totalDelta += delta
	}

	if err := s.finalize(); err != nil {
		return nil, err
	}

	return &Result{Data: s.data, ChangedFunctions: changedIdx, SizeDelta: totalDelta}, nil
}

// assembler holds the read-only side of an assembly run.
type assembler struct {
	m     *ir.Module
	table *opcodes.Table
}

// changedFunctions finds every function whose edited text differs from
// the file's current disassembly.
func (a *assembler) changedFunctions(funcs []hasmFunction) ([]uint32, error) {
	var changed []uint32
	for _, hf := range funcs {
		if hf.Index < 0 || hf.Index >= len(a.m.Functions) {
			return nil, fmt.Errorf("function #%d in HASM does not exist in this file (file has %d functions)", hf.Index, len(a.m.Functions))
		}
		current := a.m.Functions[hf.Index].Instructions
		if !a.instructionsEqual(current, hf.Instructions) {
			changed = append(changed, uint32(hf.Index))
		}
	}
	return changed, nil
}

// fileState is the mutable working copy used while patching.
type fileState struct {
	m      *ir.Module
	data   []byte
	fns    []ir.Function
	header ir.Header
}

// writeHeaderFields re-serializes the file-level header into s.data,
// mirroring the exact field order and version conditionals the parser
// reads (see parser/header.go). Only call after mutating s.header fields
// that must persist (FileLength, DebugInfoOffset).
func (s *fileState) writeHeaderFields() {
	var buf bytes.Buffer
	le := binary.LittleEndian
	w32 := func(v uint32) { _ = binary.Write(&buf, le, v) }

	_ = binary.Write(&buf, le, s.header.Magic)
	w32(s.header.Version)
	buf.Write(s.header.SourceHash[:])
	w32(s.header.FileLength)
	w32(s.header.GlobalCodeIndex)
	w32(s.header.FunctionCount)
	w32(s.header.StringKindCount)
	w32(s.header.IdentifierCount)
	w32(s.header.StringCount)
	w32(s.header.OverflowStringCount)
	w32(s.header.StringStorageSize)

	if s.header.Version >= 87 {
		w32(s.header.BigIntCount)
		w32(s.header.BigIntStorageSize)
	}
	w32(s.header.RegExpCount)
	w32(s.header.RegExpStorageSize)

	if s.header.Version < 97 {
		w32(s.header.ArrayBufferSize)
		w32(s.header.ObjKeyBufferSize)
		w32(s.header.ObjValueBufferSize)
	} else {
		w32(s.header.LiteralValueBufferSize)
		w32(s.header.ObjKeyBufferSize)
		w32(s.header.ObjShapeTableCount)
		if s.header.Version >= 98 {
			w32(s.header.NumStringSwitchImms)
		}
	}

	w32(s.header.SegmentID)
	w32(s.header.CJSModuleCount)
	if s.header.Version >= 84 {
		w32(s.header.FunctionSourceCount)
	}
	w32(s.header.DebugInfoOffset)

	var flags byte
	if s.header.StaticBuiltins {
		flags |= 1
	}
	if s.header.CJSModulesStaticallyResolved {
		flags |= 2
	}
	if s.header.HasAsync {
		flags |= 4
	}
	buf.WriteByte(flags)

	copy(s.data, buf.Bytes())
}

// writeFunctionHeaderOffsetAndSize re-serializes one function's Offset
// and BytecodeSizeInBytes into whichever location holds them: the packed
// small header fields, or the separately stored large header (plus the
// overflow pointer in the small header) when Overflowed.
func (s *fileState) writeFunctionHeaderOffsetAndSize(idx uint32) error {
	f := &s.fns[idx]

	if f.Overflowed {
		off := f.LargeHeaderOffset
		if off < 0 || off+int64(largeHeaderSize(s.header.Version)) > int64(len(s.data)) {
			return fmt.Errorf("large header file offset %d out of bounds", off)
		}
		var sizeFieldOff int64
		if s.header.Version >= 98 {
			sizeFieldOff = off + 12 // offset(4) paramCount(4) loopDepth(4) bytecodeSizeInBytes(4)
		} else {
			sizeFieldOff = off + 8 // offset(4) paramCount(4) bytecodeSizeInBytes(4)
		}
		binary.LittleEndian.PutUint32(s.data[off:], f.Offset)
		binary.LittleEndian.PutUint32(s.data[sizeFieldOff:], f.BytecodeSizeInBytes)
		return s.writeOverflowPointer(f)
	}

	off := f.SmallHeaderOffset
	rawSize := int64(12)
	if s.header.Version < 97 {
		rawSize = 16
	}
	if off < 0 || off+rawSize > int64(len(s.data)) {
		return fmt.Errorf("small header file offset %d out of bounds", off)
	}
	raw := s.data[off : off+rawSize]

	if f.Offset > 0x1FFFFFF {
		return fmt.Errorf("function offset 0x%x no longer fits in the small header's 25-bit field", f.Offset)
	}

	var sizeMask uint32 = 0x3FFF // v>=98: 14 bits
	if s.header.Version < 98 {
		sizeMask = 0x7FFF // v97/v<97: 15 bits
	}
	if f.BytecodeSizeInBytes > sizeMask {
		return fmt.Errorf("function #%d's new bytecode size (%d bytes) no longer fits in the small header's size field (max %d); promoting a function to a large header is not supported by this assembler", idx, f.BytecodeSizeInBytes, sizeMask)
	}

	w1 := binary.LittleEndian.Uint32(raw[0:4])
	w1 = (w1 &^ 0x1FFFFFF) | (f.Offset & 0x1FFFFFF)
	binary.LittleEndian.PutUint32(raw[0:4], w1)

	w2 := binary.LittleEndian.Uint32(raw[4:8])
	w2 = (w2 &^ sizeMask) | (f.BytecodeSizeInBytes & sizeMask)
	binary.LittleEndian.PutUint32(raw[4:8], w2)

	if s.header.Version < 97 {
		// The pre-v97 small header's third word also carries the
		// infoOffset, which shifts whenever the bytecode segment grows.
		if f.InfoOffset > 0x1FFFFFF {
			return fmt.Errorf("function info offset 0x%x no longer fits in the small header's 25-bit field", f.InfoOffset)
		}
		w3 := binary.LittleEndian.Uint32(raw[8:12])
		w3 = (w3 &^ 0x1FFFFFF) | (f.InfoOffset & 0x1FFFFFF)
		binary.LittleEndian.PutUint32(raw[8:12], w3)
	}

	return nil
}

// writeOverflowPointer rewrites the small header fields that hold an
// overflowed function's large-header pointer, inverting the decode in
// parser/functions.go.
func (s *fileState) writeOverflowPointer(f *ir.Function) error {
	off := f.SmallHeaderOffset
	if off < 0 || off+12 > int64(len(s.data)) {
		return fmt.Errorf("small header file offset %d out of bounds", off)
	}
	raw := s.data[off : off+12]

	ptr := f.LargeHeaderOffset
	if ptr < 0 || ptr > (int64(1)<<40) {
		return fmt.Errorf("large header pointer %d is not representable", ptr)
	}
	ptrOffsetBits := uint32(ptr & 0x1FFFFFF)
	ptrHighBits := uint32(uint64(ptr) >> 16)
	if s.header.Version >= 98 {
		ptrHighBits = uint32(uint64(ptr) >> 24)
	}

	w1 := binary.LittleEndian.Uint32(raw[0:4])
	w1 = (w1 &^ 0x1FFFFFF) | (ptrOffsetBits & 0x1FFFFFF)
	binary.LittleEndian.PutUint32(raw[0:4], w1)

	w2 := binary.LittleEndian.Uint32(raw[4:8])
	switch {
	case s.header.Version >= 98:
		if ptrHighBits > 0xFF {
			return fmt.Errorf("large header pointer's high bits no longer fit in the small header's 8-bit functionName field")
		}
		w2 = (w2 &^ (0xFF << 14)) | ((ptrHighBits & 0xFF) << 14)
	case s.header.Version >= 97:
		if ptrHighBits > 0x1FFFF {
			return fmt.Errorf("large header pointer's high bits no longer fit in the small header's 17-bit functionName field")
		}
		w2 = (w2 &^ (0x1FFFF << 15)) | ((ptrHighBits & 0x1FFFF) << 15)
	}
	binary.LittleEndian.PutUint32(raw[4:8], w2)

	if s.header.Version < 97 {
		if ptrHighBits > 0x1FFFFFF {
			return fmt.Errorf("large header pointer's high bits no longer fit in the small header's 25-bit infoOffset field")
		}
		w3 := binary.LittleEndian.Uint32(raw[8:12])
		w3 = (w3 &^ 0x1FFFFFF) | (ptrHighBits & 0x1FFFFFF)
		binary.LittleEndian.PutUint32(raw[8:12], w3)
	}
	return nil
}

// largeHeaderSize mirrors the parser's layout table.
func largeHeaderSize(version uint32) int {
	switch {
	case version >= 98:
		return 36
	case version >= 97:
		return 23
	default:
		return 31
	}
}

// tailStart returns the absolute offset of the first structure that lives
// after the whole bytecode segment (large function headers, pre-v97
// function info blocks, debug info), or -1 when there is none. This is
// where out-of-line switch tables are inserted: it is 4-byte aligned, so
// inserting a multiple-of-4 table there keeps every following structure
// aligned.
func (s *fileState) tailStart() int64 {
	start := int64(-1)
	consider := func(p int64) {
		if p > 0 && (start < 0 || p < start) {
			start = p
		}
	}
	for i := range s.fns {
		f := &s.fns[i]
		if f.Overflowed {
			consider(f.LargeHeaderOffset)
		} else if s.header.Version < 97 && f.InfoOffset > 0 {
			consider(int64(f.InfoOffset))
		}
	}
	if s.header.DebugInfoOffset > 0 {
		consider(int64(s.header.DebugInfoOffset))
	}
	return start
}

// bytecodeSegmentEnd returns the first safe insertion point after every
// function's bytecode: the maximum end of all declared bytecode ranges.
// The large/overflow headers and the pre-v97 function info blocks all sit
// at or after this point (they always follow the whole bytecode segment),
// so inserting here only shifts pointers that the caller then updates.
//
// Note that a file may declare DebugInfoOffset == 0 (no debug section),
// so that field cannot be used as the segment boundary.
func (s *fileState) bytecodeSegmentEnd() int64 {
	end := int64(0)
	for i := range s.fns {
		f := &s.fns[i]
		if e := int64(f.Offset) + int64(f.BytecodeSizeInBytes); e > end {
			end = e
		}
	}
	return end
}

// insertBytesAt inserts bytes at an absolute offset and shifts every
// function offset and file-level offset at or past it, then re-serializes
// the affected headers.
func (s *fileState) insertBytesAt(at int64, newBytes []byte) error {
	if at < 0 || at > int64(len(s.data)) {
		return fmt.Errorf("insertion point %d is out of bounds for a %d-byte file", at, len(s.data))
	}

	newData := make([]byte, int64(len(s.data))+int64(len(newBytes)))
	copy(newData, s.data[:at])
	copy(newData[at:], newBytes)
	copy(newData[at+int64(len(newBytes)):], s.data[at:])
	s.data = newData

	delta := int64(len(newBytes))
	for i := range s.fns {
		f := &s.fns[i]
		if int64(f.Offset) >= at {
			f.Offset = uint32(int64(f.Offset) + delta)
		}
		if f.Overflowed && f.LargeHeaderOffset >= at {
			f.LargeHeaderOffset += delta
		}
		if !f.Overflowed && s.header.Version < 97 && int64(f.InfoOffset) >= at {
			f.InfoOffset = uint32(int64(f.InfoOffset) + delta)
		}
		if f.SmallHeaderOffset >= at {
			f.SmallHeaderOffset += delta
		}
	}

	s.header.DebugInfoOffset = uint32(int64(s.header.DebugInfoOffset) + delta)
	s.header.FileLength = uint32(int64(s.header.FileLength) + delta)
	s.writeHeaderFields()

	for i := range s.fns {
		if err := s.writeFunctionHeaderOffsetAndSize(uint32(i)); err != nil {
			return fmt.Errorf("writing shifted header for function #%d: %w", i, err)
		}
	}
	return nil
}

// deduplicateAliasedFunctions gives every OTHER function sharing funcIdx's
// bytecode offset its own copy at the end of the bytecode segment, so the
// upcoming splice cannot corrupt a function that aliased the bytes.
func (s *fileState) deduplicateAliasedFunctions(funcIdx uint32, skip map[uint32]bool) error {
	hdr := s.fns[funcIdx]

	var aliases []uint32
	for i := range s.fns {
		if uint32(i) == funcIdx || skip[uint32(i)] {
			continue
		}
		if s.fns[i].Offset == hdr.Offset {
			aliases = append(aliases, uint32(i))
		}
	}
	if len(aliases) == 0 {
		return nil
	}

	for _, i := range aliases {
		aliasHdr := &s.fns[i]
		size := int(aliasHdr.BytecodeSizeInBytes)
		offset := int(aliasHdr.Offset)
		if offset < 0 || offset+size > len(s.data) {
			return fmt.Errorf("function #%d's bytecode range [%d, %d) is out of bounds for a %d-byte file", i, offset, offset+size, len(s.data))
		}
		copyOfBytes := make([]byte, size+((4-size%4)%4))
		copy(copyOfBytes, s.data[offset:offset+size])

		insertAt := s.bytecodeSegmentEnd()
		if err := s.insertBytesAt(insertAt, copyOfBytes); err != nil {
			return fmt.Errorf("de-duplicating function #%d (shares bytecode with function #%d): %w", i, funcIdx, err)
		}
		// insertBytesAt shifted aliasHdr's Offset along with everything
		// else at or past insertAt; repoint it at the inserted copy.
		aliasHdr.Offset = uint32(insertAt)
		if err := s.writeFunctionHeaderOffsetAndSize(i); err != nil {
			return fmt.Errorf("writing de-duplicated header for function #%d: %w", i, err)
		}
	}
	return nil
}

// patchOneFunction replaces one function's bytecode, shifts everything
// after it, places its switch jump tables, and rewrites affected headers.
func (s *fileState) patchOneFunction(funcIdx uint32, code []byte, tables []switchTableToPlace, skip map[uint32]bool) (int, error) {
	if funcIdx >= uint32(len(s.fns)) {
		return 0, fmt.Errorf("function index %d out of range", funcIdx)
	}
	if err := s.deduplicateAliasedFunctions(funcIdx, skip); err != nil {
		return 0, err
	}

	hdr := &s.fns[funcIdx]
	offset := int(hdr.Offset)
	oldSize := int(hdr.BytecodeSizeInBytes)
	if offset < 0 || offset+oldSize > len(s.data) {
		return 0, fmt.Errorf("function's current bytecode range [%d, %d) is out of bounds for a %d-byte file", offset, offset+oldSize, len(s.data))
	}

	splicePoint := int64(offset + oldSize)

	// Pad the spliced chunk so the bytecode segment's total size stays a
	// multiple of BYTECODE_ALIGNMENT (4): everything after the splice
	// shifts by the inserted length, and the aligned large-header/info/
	// debug sections after the segment must remain 4-byte aligned. The
	// padding is dead space between this function and the next, exactly
	// like Hermes's own alignment gaps, and is NOT counted in
	// BytecodeSizeInBytes.
	pad := (4 - ((len(code) - oldSize) % 4)) % 4
	chunk := code
	if pad != 0 {
		chunk = make([]byte, len(code)+pad)
		copy(chunk, code)
	}

	newData := make([]byte, len(s.data)-oldSize+len(chunk))
	copy(newData, s.data[:offset])
	copy(newData[offset:], chunk)
	copy(newData[offset+len(chunk):], s.data[offset+oldSize:])
	s.data = newData

	delta := len(chunk) - oldSize
	hdr.BytecodeSizeInBytes = uint32(len(code))

	if delta != 0 {
		for i := range s.fns {
			f := &s.fns[i]
			if uint32(i) != funcIdx && int64(f.Offset) >= splicePoint {
				f.Offset = uint32(int64(f.Offset) + int64(delta))
			}
			if f.Overflowed && f.LargeHeaderOffset >= splicePoint {
				f.LargeHeaderOffset += int64(delta)
			}
			if !f.Overflowed && s.header.Version < 97 && int64(f.InfoOffset) >= splicePoint {
				f.InfoOffset = uint32(int64(f.InfoOffset) + int64(delta))
			}
			if f.SmallHeaderOffset >= splicePoint {
				f.SmallHeaderOffset += int64(delta)
			}
		}
	}

	if err := s.writeFunctionHeaderOffsetAndSize(funcIdx); err != nil {
		return 0, fmt.Errorf("writing updated header for function #%d: %w", funcIdx, err)
	}
	if delta != 0 {
		for i := range s.fns {
			if uint32(i) == funcIdx {
				continue
			}
			if err := s.writeFunctionHeaderOffsetAndSize(uint32(i)); err != nil {
				return 0, fmt.Errorf("writing updated header for function #%d: %w", i, err)
			}
		}
		s.header.DebugInfoOffset = uint32(int64(s.header.DebugInfoOffset) + int64(delta))
		s.header.FileLength = uint32(int64(s.header.FileLength) + int64(delta))
		s.writeHeaderFields()
	}

	// Place switch jump tables at the end of the bytecode segment,
	// 4-byte aligned in absolute file space, then patch each arg2 with
	// the table's final distance from its instruction.
	for _, t := range tables {
		insertAt := s.tailStart()
		pad := 0
		if insertAt < 0 {
			// No tail structures exist; only the SHA1 footer follows.
			insertAt = s.bytecodeSegmentEnd()
			pad = int((4 - insertAt%4) % 4)
		}
		toInsert := t.TableBytes
		if pad > 0 {
			toInsert = make([]byte, pad+len(t.TableBytes))
			copy(toInsert[pad:], t.TableBytes)
		}
		tableStart := insertAt + int64(pad)

		if err := s.insertBytesAt(insertAt, toInsert); err != nil {
			return 0, fmt.Errorf("placing jump table for function #%d: %w", funcIdx, err)
		}
		delta += len(toInsert)

		instAbs := int64(hdr.Offset) + int64(t.InstFuncOffset)
		arg2 := uint32(tableStart - instAbs)
		arg2Abs := int64(hdr.Offset) + int64(t.Arg2Offset)
		if arg2Abs < 0 || arg2Abs+4 > int64(len(s.data)) {
			return 0, fmt.Errorf("function #%d: computed arg2 field position %d is out of bounds (please report this as a bug)", funcIdx, arg2Abs)
		}
		binary.LittleEndian.PutUint32(s.data[arg2Abs:], arg2)
	}

	return delta, nil
}

// finalize recomputes the SHA1 footer over the patched file.
func (s *fileState) finalize() error {
	if s.header.Version < 75 {
		return nil
	}
	fileLength := int(s.header.FileLength)
	if fileLength < 20 || fileLength > len(s.data) {
		return fmt.Errorf("patched file length %d is not consistent with the %d-byte buffer", fileLength, len(s.data))
	}
	sum := sha1.Sum(s.data[:fileLength-20])
	copy(s.data[fileLength-20:fileLength], sum[:])
	return nil
}
