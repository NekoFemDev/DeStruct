package parser

import (
	"bytes"
	"crypto/sha1"
	"fmt"

	"github.com/destruct/destruct/internal/hermes/ir"
)

// HeaderSize is the fixed size of BytecodeFileHeader once its trailing
// padding (which aligns it to 32 bytes) is included. Every version's
// header is tuned to exactly this size.
const HeaderSize = 128

// readHeader decodes BytecodeFileHeader. Field presence follows the
// version conditionals in Hermes's BytecodeFileFormat.h (and its Python
// mirrors): bigint fields exist from v87, the literal/shape-table fields
// replace the array/object-value buffers at v97, numStringSwitchImms
// exists from v98, and the function source count exists from v84.
func readHeader(r *reader) (ir.Header, error) {
	var h ir.Header

	magic, err := r.u64()
	if err != nil {
		return h, fmt.Errorf("header magic: %w", err)
	}
	if magic != ir.Magic {
		return h, fmt.Errorf("not a Hermes bytecode file: magic 0x%016x (expected 0x%016x)", magic, ir.Magic)
	}
	h.Magic = magic

	if h.Version, err = r.u32(); err != nil {
		return h, fmt.Errorf("header version: %w", err)
	}

	hash, err := r.bytes(20)
	if err != nil {
		return h, fmt.Errorf("header source hash: %w", err)
	}
	copy(h.SourceHash[:], hash)

	if h.FileLength, err = r.u32(); err != nil {
		return h, fmt.Errorf("header file length: %w", err)
	}
	if h.GlobalCodeIndex, err = r.u32(); err != nil {
		return h, fmt.Errorf("header global code index: %w", err)
	}
	if h.FunctionCount, err = r.u32(); err != nil {
		return h, fmt.Errorf("header function count: %w", err)
	}
	if h.StringKindCount, err = r.u32(); err != nil {
		return h, fmt.Errorf("header string kind count: %w", err)
	}
	if h.IdentifierCount, err = r.u32(); err != nil {
		return h, fmt.Errorf("header identifier count: %w", err)
	}
	if h.StringCount, err = r.u32(); err != nil {
		return h, fmt.Errorf("header string count: %w", err)
	}
	if h.OverflowStringCount, err = r.u32(); err != nil {
		return h, fmt.Errorf("header overflow string count: %w", err)
	}
	if h.StringStorageSize, err = r.u32(); err != nil {
		return h, fmt.Errorf("header string storage size: %w", err)
	}

	if h.Version >= 87 {
		if h.BigIntCount, err = r.u32(); err != nil {
			return h, fmt.Errorf("header bigint count: %w", err)
		}
		if h.BigIntStorageSize, err = r.u32(); err != nil {
			return h, fmt.Errorf("header bigint storage size: %w", err)
		}
	}

	if h.RegExpCount, err = r.u32(); err != nil {
		return h, fmt.Errorf("header regexp count: %w", err)
	}
	if h.RegExpStorageSize, err = r.u32(); err != nil {
		return h, fmt.Errorf("header regexp storage size: %w", err)
	}

	if h.Version < 97 {
		if h.ArrayBufferSize, err = r.u32(); err != nil {
			return h, fmt.Errorf("header array buffer size: %w", err)
		}
		if h.ObjKeyBufferSize, err = r.u32(); err != nil {
			return h, fmt.Errorf("header object key buffer size: %w", err)
		}
		if h.ObjValueBufferSize, err = r.u32(); err != nil {
			return h, fmt.Errorf("header object value buffer size: %w", err)
		}
	} else {
		if h.LiteralValueBufferSize, err = r.u32(); err != nil {
			return h, fmt.Errorf("header literal value buffer size: %w", err)
		}
		if h.ObjKeyBufferSize, err = r.u32(); err != nil {
			return h, fmt.Errorf("header object key buffer size: %w", err)
		}
		if h.ObjShapeTableCount, err = r.u32(); err != nil {
			return h, fmt.Errorf("header object shape table count: %w", err)
		}
		if h.Version >= 98 {
			if h.NumStringSwitchImms, err = r.u32(); err != nil {
				return h, fmt.Errorf("header num string switch imms: %w", err)
			}
		}
	}

	if h.SegmentID, err = r.u32(); err != nil {
		return h, fmt.Errorf("header segment id: %w", err)
	}
	if h.CJSModuleCount, err = r.u32(); err != nil {
		return h, fmt.Errorf("header cjs module count: %w", err)
	}

	if h.Version >= 84 {
		if h.FunctionSourceCount, err = r.u32(); err != nil {
			return h, fmt.Errorf("header function source count: %w", err)
		}
	}

	if h.DebugInfoOffset, err = r.u32(); err != nil {
		return h, fmt.Errorf("header debug info offset: %w", err)
	}

	flags, err := r.u8()
	if err != nil {
		return h, fmt.Errorf("header flags: %w", err)
	}
	h.StaticBuiltins = flags&1 != 0
	h.CJSModulesStaticallyResolved = flags&2 != 0
	h.HasAsync = flags&4 != 0

	// The header's trailing padding aligns the next segment to 32 bytes.
	if err := r.align(32); err != nil {
		return h, fmt.Errorf("header padding: %w", err)
	}
	if r.tell() > HeaderSize {
		return h, fmt.Errorf("header of version %d parsed %d bytes past the expected %d", h.Version, r.tell()-HeaderSize, HeaderSize)
	}
	if r.tell() < HeaderSize {
		// All known versions pad the header to exactly HeaderSize; a
		// shorter parse means a field-presence rule above is wrong.
		return h, fmt.Errorf("header of version %d parsed only %d of the expected %d bytes", h.Version, r.tell(), HeaderSize)
	}

	return h, nil
}

// checkSHA1 verifies the SHA1 footer written after bytecode version 75.
// The footer covers the first FileLength bytes of the file (fileLength
// includes the footer itself); the physical file may carry an epilogue
// past it, so the check must be anchored on FileLength, not the file's
// physical size.
func checkSHA1(data []byte, h *ir.Header) error {
	if h.Version < 75 {
		return nil
	}
	if h.FileLength < HeaderSize+20 {
		return fmt.Errorf("file length %d is too small for a version %d file", h.FileLength, h.Version)
	}
	if uint64(h.FileLength) > uint64(len(data)) {
		return fmt.Errorf("declared file length %d exceeds the %d-byte file", h.FileLength, len(data))
	}
	footer := data[h.FileLength-20 : h.FileLength]
	sum := sha1.Sum(data[:h.FileLength-20])
	if !bytes.Equal(footer, sum[:]) {
		return fmt.Errorf("SHA1 footer mismatch (file corrupt or truncated)")
	}
	return nil
}
