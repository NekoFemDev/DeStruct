// Package registry maps a Hermes bytecode format version to its opcode
// table. It is the single place that knows which versions DeStruct has
// generated tables for; every consumer (parser, disassembler, assembler)
// goes through Lookup rather than importing version packages directly.
//
// Versions without a dedicated table are reported as unsupported by
// Lookup. The list of supported versions covers every version for which
// github.com/Kirlif/HBC-Tool ships data (59, 62, 74, 76, and 83-99).
// Newer versions added upstream can be vendored by dropping an
// hbcNN.json into ../data, re-running the generator, and adding the
// import below.
package registry

import (
	"fmt"
	"sort"

	"github.com/destruct/destruct/internal/hermes/opcodes"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc59"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc62"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc74"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc76"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc83"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc84"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc85"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc86"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc87"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc88"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc89"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc90"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc91"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc92"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc93"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc94"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc95"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc96"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc97"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc98"
	"github.com/destruct/destruct/internal/hermes/opcodes/hbc99"
)

var tables = map[uint32]*opcodes.Table{
	59: hbc59.Table,
	62: hbc62.Table,
	74: hbc74.Table,
	76: hbc76.Table,
	83: hbc83.Table,
	84: hbc84.Table,
	85: hbc85.Table,
	86: hbc86.Table,
	87: hbc87.Table,
	88: hbc88.Table,
	89: hbc89.Table,
	90: hbc90.Table,
	91: hbc91.Table,
	92: hbc92.Table,
	93: hbc93.Table,
	94: hbc94.Table,
	95: hbc95.Table,
	96: hbc96.Table,
	97: hbc97.Table,
	98: hbc98.Table,
	99: hbc99.Table,
}

var builtins = map[uint32][]string{
	59: hbc59.Builtins,
	62: hbc62.Builtins,
	74: hbc74.Builtins,
	76: hbc76.Builtins,
	83: hbc83.Builtins,
	84: hbc84.Builtins,
	85: hbc85.Builtins,
	86: hbc86.Builtins,
	87: hbc87.Builtins,
	88: hbc88.Builtins,
	89: hbc89.Builtins,
	90: hbc90.Builtins,
	91: hbc91.Builtins,
	92: hbc92.Builtins,
	93: hbc93.Builtins,
	94: hbc94.Builtins,
	95: hbc95.Builtins,
	96: hbc96.Builtins,
	97: hbc97.Builtins,
	98: hbc98.Builtins,
	99: hbc99.Builtins,
}

// Builtins returns the ordered builtin callable names for a bytecode
// version, indexed by the builtin operand of CallBuiltin and
// GetBuiltinClosure. Nil when the version has no list.
func Builtins(version uint32) []string {
	return builtins[version]
}

// UnsupportedVersionError is returned by Lookup for a bytecode version
// that has no generated table.
type UnsupportedVersionError struct {
	Version uint32
}

func (e *UnsupportedVersionError) Error() string {
	versions := Supported()
	strs := make([]string, len(versions))
	for i, v := range versions {
		strs[i] = fmt.Sprint(v)
	}
	return fmt.Sprintf("no opcode table for Hermes bytecode version %d (supported: %v)", e.Version, strs)
}

// Lookup returns the opcode table for a bytecode version, or a
// *UnsupportedVersionError when the version has no generated table.
func Lookup(version uint32) (*opcodes.Table, error) {
	if t, ok := tables[version]; ok {
		return t, nil
	}
	return nil, &UnsupportedVersionError{Version: version}
}

// Supported returns the sorted list of versions with a dedicated table.
func Supported() []uint32 {
	versions := make([]uint32, 0, len(tables))
	for v := range tables {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	return versions
}
