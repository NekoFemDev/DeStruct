// Package parser reads Hermes bytecode (.hbc) files into the ir.Module
// intermediate representation.
//
// Parsing is split in two stages so container-only consumers never pay
// for instruction decoding:
//
//   - Parse decodes the file header, the function header table (including
//     overflow headers and their exception handler / debug offset blocks),
//     the string and literal tables, and every other container section.
//   - Decode walks each function's bytecode and fills in the instruction
//     stream using the opcode table for the file's bytecode version, which
//     it resolves through the opcodes/registry package.
//
// The parser is version-agnostic: the same code paths handle v59 through
// v99, branching only where the file format actually changed (noted at
// each branch against the Hermes BytecodeFileFormat.h definitions).
package parser

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/destruct/destruct/internal/hermes/ir"
)

// MinVersion and MaxVersion bound the bytecode versions this parser
// accepts. The lower bound is the oldest version for which the
// pre-BigInt header layout is known; the upper bound is the newest
// version defined in Hermes's BytecodeVersion.h.
const (
	MinVersion uint32 = 59
	MaxVersion uint32 = 99
)

// ErrNotHermes is returned when the file magic does not match.
var ErrNotHermes = errors.New("not a Hermes bytecode file (bad magic)")

// DetectVersion reads the bytecode version from the file header without
// parsing anything else. It only validates the magic; callers that need
// to know whether the version is supported should consult
// opcodes/registry.Lookup or call Parse.
func DetectVersion(data []byte) (uint32, error) {
	if len(data) < 12 {
		return 0, fmt.Errorf("file too small (%d bytes) to be Hermes bytecode", len(data))
	}
	if binary.LittleEndian.Uint64(data) != ir.Magic {
		return 0, ErrNotHermes
	}
	return binary.LittleEndian.Uint32(data[8:]), nil
}

// Options controls ParseWithOptions.
type Options struct {
	// SkipHashCheck disables the SHA1 footer verification performed for
	// version 75 and later. Useful when parsing files whose footer was
	// edited by an external tool.
	SkipHashCheck bool
}

// Parse reads a complete Hermes bytecode file. The returned module owns
// no copies of immutable data: buffers are sub-slices of data, which the
// caller must keep alive for as long as the module is used.
func Parse(data []byte) (*ir.Module, error) {
	return ParseWithOptions(data, Options{})
}

// ParseWithOptions is Parse with explicit options.
func ParseWithOptions(data []byte, opts Options) (*ir.Module, error) {
	version, err := DetectVersion(data)
	if err != nil {
		return nil, err
	}
	if version < MinVersion || version > MaxVersion {
		return nil, fmt.Errorf("unsupported Hermes bytecode version %d (this parser covers %d-%d)", version, MinVersion, MaxVersion)
	}

	r := newReader(data)
	header, err := readHeader(r)
	if err != nil {
		return nil, err
	}
	if uint64(header.FileLength) > uint64(len(data)) {
		return nil, fmt.Errorf("declared file length %d exceeds the %d-byte file", header.FileLength, len(data))
	}
	if !opts.SkipHashCheck {
		if err := checkSHA1(data, &header); err != nil {
			return nil, err
		}
	}

	m := &ir.Module{
		Header:  header,
		Version: version,
		Raw:     data,
	}

	if err := readFunctions(r, m); err != nil {
		return nil, err
	}
	if err := readStringKinds(r, m); err != nil {
		return nil, err
	}
	if err := readIdentifierHashes(r, m); err != nil {
		return nil, err
	}
	if err := readStrings(r, m); err != nil {
		return nil, err
	}
	if err := readLiteralBuffers(r, m); err != nil {
		return nil, err
	}
	if version >= 87 {
		if err := readBigInts(r, m); err != nil {
			return nil, err
		}
	}
	if err := readRegExps(r, m); err != nil {
		return nil, err
	}
	if err := readCJSModules(r, m); err != nil {
		return nil, err
	}
	if version >= 84 {
		if err := readFunctionSources(r, m); err != nil {
			return nil, err
		}
	}

	attachBytecode(m)
	return m, nil
}
