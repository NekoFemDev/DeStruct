package parser

import (
	"fmt"

	"github.com/destruct/destruct/internal/hermes/ir"
)

// smallHeaderSize returns the on-disk size of one function header table
// entry: 16 bytes before v97 (the extra word is the infoOffset), 12 bytes
// from v97 on.
func smallHeaderSize(version uint32) int {
	if version >= 97 {
		return 12
	}
	return 16
}

// largeHeaderSize returns the size of the separately stored
// FunctionHeader an overflowed small header points at.
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

// readFunctions decodes the function header table. The cursor ends up
// just past the last small header entry, which is where the next
// section begins.
func readFunctions(r *reader, m *ir.Module) error {
	count, err := r.countToInt(uint64(m.Header.FunctionCount), smallHeaderSize(m.Version), "function headers")
	if err != nil {
		return err
	}
	m.Functions = make([]ir.Function, count)

	for i := range m.Functions {
		if err := readFunction(r, m, i); err != nil {
			return fmt.Errorf("function #%d: %w", i, err)
		}
	}
	return nil
}

// readFunction decodes one function header entry, following the overflow
// pointer to the large header (and the function info block after it) when
// the entry says the function overflowed.
func readFunction(r *reader, m *ir.Module, index int) error {
	f := &m.Functions[index]
	f.Index = uint32(index)

	entryStart := r.tell()
	raw, err := r.bytes(smallHeaderSize(m.Version))
	if err != nil {
		return err
	}
	f.SmallHeaderOffset = int64(entryStart)

	decodeSmallHeader(raw, m.Version, f)

	afterSmall := r.tell()

	if f.Overflowed {
		ptr, err := largeHeaderPointer(f, m.Version)
		if err != nil {
			return err
		}
		f.LargeHeaderOffset = int64(ptr)
		if err := r.seek(int64(ptr)); err != nil {
			return fmt.Errorf("overflow header pointer: %w", err)
		}
		largeRaw, err := r.bytes(largeHeaderSize(m.Version))
		if err != nil {
			return fmt.Errorf("large function header: %w", err)
		}
		decodeLargeHeader(largeRaw, m.Version, f)
		// The info block physically follows the large header.
		if err := readFunctionInfo(r, m.Version, f); err != nil {
			return err
		}
	} else if m.Version < 97 {
		// Pre-v97 small headers carry an infoOffset to the function's
		// exception-handler/debug block.
		if err := r.seek(int64(f.InfoOffset)); err != nil {
			return fmt.Errorf("info offset: %w", err)
		}
		if err := readFunctionInfo(r, m.Version, f); err != nil {
			return err
		}
	}
	// v97+ non-overflowed functions cannot carry exception handlers or
	// debug offsets: those live only behind overflow headers (see
	// BCProviderFromBuffer::getExceptionTableAndDebugOffsets).

	return r.seek(int64(afterSmall))
}

// decodeSmallHeader unpacks the bit fields of a small function header
// entry. Layouts:
//
//	v<97 (16 bytes): offset:25 paramCount:7 | size:15 functionName:17 |
//	                 infoOffset:25 frameSize:7 | environmentSize:8
//	                 highestReadCacheIndex:8 highestWriteCacheIndex:8 | flags:8
//	v97  (12 bytes): offset:25 paramCount:7 | size:15 functionName:17 |
//	                 frameSize:8 highestReadCacheIndex:8
//	                 highestWriteCacheIndex:8 | flags:8
//	v98+ (12 bytes): offset:25 paramCount:5 loopDepth:2 |
//	                 size:14 functionName:8 numberRegCount:5 nonPtrRegCount:5 |
//	                 frameSize:8 readCacheSize:8 writeCacheSize:7
//	                 privateNameCacheSize:1 | flags:8
func decodeSmallHeader(raw []byte, version uint32, f *ir.Function) {
	le := func(off int) uint32 {
		return uint32(raw[off]) | uint32(raw[off+1])<<8 | uint32(raw[off+2])<<16 | uint32(raw[off+3])<<24
	}

	// Overflowed is meaningful only on the small header; the large
	// header's same bit position belongs to its own flag byte and is not
	// re-read into this field.
	f.Overflowed = raw[len(raw)-1]&0x20 != 0

	w1 := le(0)
	f.Offset = w1 & 0x1FFFFFF
	f.ParamCount = w1 >> 25

	if version >= 98 {
		f.ParamCount = (w1 >> 25) & 0x1F
		f.LoopDepth = (w1 >> 30) & 0x3

		w2 := le(4)
		f.BytecodeSizeInBytes = w2 & 0x3FFF
		f.NameID = (w2 >> 14) & 0xFF
		f.NumberRegCount = (w2 >> 22) & 0x1F
		f.NonPtrRegCount = (w2 >> 27) & 0x1F

		f.FrameSize = uint32(raw[8])
		f.ReadCacheSize = raw[9]
		f.WriteCacheSize = raw[10] & 0x7F
		f.PrivateNameCacheSize = raw[10] >> 7

		decodeFlags(raw[11], f)
		return
	}

	w2 := le(4)
	f.BytecodeSizeInBytes = w2 & 0x7FFF
	f.NameID = w2 >> 15

	if version >= 97 {
		f.FrameSize = uint32(raw[8])
		f.HighestReadCacheIndex = raw[9]
		f.HighestWriteCacheIndex = raw[10]
		decodeFlags(raw[11], f)
		return
	}

	w3 := le(8)
	f.InfoOffset = w3 & 0x1FFFFFF
	f.FrameSize = (w3 >> 25) & 0x7F

	f.EnvironmentSize = uint32(raw[12])
	f.HighestReadCacheIndex = raw[13]
	f.HighestWriteCacheIndex = raw[14]
	decodeFlags(raw[15], f)
}

// decodeLargeHeader unpacks the plain-width fields of the large
// FunctionHeader. Flag bits are taken from the large header (they are
// authoritative for the info block that follows); the Overflowed flag is
// left as decoded from the small header.
func decodeLargeHeader(raw []byte, version uint32, f *ir.Function) {
	le := func(off int) uint32 {
		return uint32(raw[off]) | uint32(raw[off+1])<<8 | uint32(raw[off+2])<<16 | uint32(raw[off+3])<<24
	}

	f.Offset = le(0)
	f.ParamCount = le(4)

	switch {
	case version >= 98:
		// offset(4) paramCount(4) loopDepth(4) bytecodeSizeInBytes(4)
		// functionName(4) numberRegCount(4) nonPtrRegCount(4) frameSize(4)
		// readCacheSize(1) writeCacheSize(1) privateNameCacheSize(1) flags(1)
		f.LoopDepth = le(8)
		f.BytecodeSizeInBytes = le(12)
		f.NameID = le(16)
		f.NumberRegCount = le(20)
		f.NonPtrRegCount = le(24)
		f.FrameSize = le(28)
		f.ReadCacheSize = raw[32]
		f.WriteCacheSize = raw[33]
		f.PrivateNameCacheSize = raw[34]
		decodeFlags(raw[35], f)

	case version >= 97:
		// offset(4) paramCount(4) bytecodeSizeInBytes(4) functionName(4)
		// frameSize(4) highestReadCacheIndex(1) highestWriteCacheIndex(1) flags(1)
		f.BytecodeSizeInBytes = le(8)
		f.NameID = le(12)
		f.FrameSize = le(16)
		f.HighestReadCacheIndex = raw[20]
		f.HighestWriteCacheIndex = raw[21]
		decodeFlags(raw[22], f)

	default:
		// offset(4) paramCount(4) bytecodeSizeInBytes(4) functionName(4)
		// infoOffset(4) frameSize(4) environmentSize(4)
		// highestReadCacheIndex(1) highestWriteCacheIndex(1) flags(1)
		f.BytecodeSizeInBytes = le(8)
		f.NameID = le(12)
		f.InfoOffset = le(16)
		f.FrameSize = le(20)
		f.EnvironmentSize = le(24)
		f.HighestReadCacheIndex = raw[28]
		f.HighestWriteCacheIndex = raw[29]
		decodeFlags(raw[30], f)
	}
}

func decodeFlags(flags byte, f *ir.Function) {
	f.ProhibitInvoke = flags & 0x3
	f.StrictMode = flags&0x4 != 0
	f.HasExceptionHandler = flags&0x8 != 0
	f.HasDebugInfo = flags&0x10 != 0
	f.Kind = ir.FunctionKind((flags >> 6) & 0x3)
}

// largeHeaderPointer reconstructs the absolute file offset stored in an
// overflowed small header. The two high-order pointer bytes are kept in
// fields that otherwise hold real values:
//
//	v<97 : infoOffset (25 bits), pointer = infoOffset<<16 | offset (24-bit)
//	v97  : functionName (17 bits), pointer = functionName<<16 | offset
//	v98+ : functionName (8 bits), pointer = functionName<<24 | offset
func largeHeaderPointer(f *ir.Function, version uint32) (uint32, error) {
	switch {
	case version >= 98:
		ptr := f.NameID<<24 | f.Offset
		if ptr == 0 {
			return 0, fmt.Errorf("overflow header pointer is zero")
		}
		return ptr, nil
	case version >= 97:
		return f.NameID<<16 | f.Offset, nil
	default:
		return f.InfoOffset<<16 | f.Offset, nil
	}
}

// readFunctionInfo reads the exception handler table and debug offsets
// that follow either the large header or the pre-v97 infoOffset target,
// each 4-byte aligned.
func readFunctionInfo(r *reader, version uint32, f *ir.Function) error {
	if f.HasExceptionHandler {
		if err := r.align(4); err != nil {
			return err
		}
		count32, err := r.u32()
		if err != nil {
			return fmt.Errorf("exception handler count: %w", err)
		}
		count, err := r.countToInt(uint64(count32), 12, "exception handlers")
		if err != nil {
			return err
		}
		handlers := make([]ir.ExceptionHandler, count)
		for i := range handlers {
			if handlers[i].Start, err = r.u32(); err != nil {
				return fmt.Errorf("exception handler %d start: %w", i, err)
			}
			if handlers[i].End, err = r.u32(); err != nil {
				return fmt.Errorf("exception handler %d end: %w", i, err)
			}
			if handlers[i].Target, err = r.u32(); err != nil {
				return fmt.Errorf("exception handler %d target: %w", i, err)
			}
		}
		f.ExceptionHandlers = handlers
	}

	if f.HasDebugInfo {
		if err := r.align(4); err != nil {
			return err
		}
		var d ir.DebugOffsets
		var err error
		if d.SourceLocations, err = r.u32(); err != nil {
			return fmt.Errorf("debug offsets source locations: %w", err)
		}
		if d.ScopeDescData, err = r.u32(); err != nil {
			return fmt.Errorf("debug offsets scope desc data: %w", err)
		}
		if version >= 91 {
			if d.TextifiedCallees, err = r.u32(); err != nil {
				return fmt.Errorf("debug offsets textified callees: %w", err)
			}
		}
		f.DebugOffsets = &d
	}
	return nil
}

// attachBytecode slices each function's bytecode out of the module's raw
// buffer and resolves function names from the string table.
func attachBytecode(m *ir.Module) {
	for i := range m.Functions {
		f := &m.Functions[i]

		if name, ok := m.StringAt(f.NameID); ok {
			f.Name = name
		} else {
			f.Name = fmt.Sprintf("<bad_string:%d>", f.NameID)
		}

		size := uint64(f.BytecodeSizeInBytes)
		offset := uint64(f.Offset)
		if offset > uint64(len(m.Raw)) || size > uint64(len(m.Raw))-offset {
			f.Bytecode = nil
			continue
		}
		f.Bytecode = m.Raw[offset : offset+size]
	}
}
