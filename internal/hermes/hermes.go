// Package hermes is DeStruct's top-level entry point for Hermes
// bytecode: parse, disassemble, and (re)assemble .hbc files.
//
// The heavy lifting lives in subpackages:
//
//	parser/   bytes -> ir.Module
//	ir/       the intermediate representation
//	opcodes/  per-version instruction tables
//	disasm/   ir.Module -> hermes-dec exact text
//	asm/      text + original -> patched .hbc
package hermes

import (
	"github.com/destruct/destruct/internal/hermes/asm"
	"github.com/destruct/destruct/internal/hermes/disasm"
	"github.com/destruct/destruct/internal/hermes/parser"
)

// Disassemble parses hbcData and renders the canonical hermes-dec exact
// .hasm text for every function.
func Disassemble(hbcData []byte) (string, error) {
	m, err := parser.Parse(hbcData)
	if err != nil {
		return "", err
	}
	return disasm.Disassemble(m)
}

// Assemble patches originalHbc with the edits contained in hasmData and
// returns the complete new .hbc file (function headers, offsets and the
// SHA1 footer are recomputed). hasmData must be a disassembly of
// originalHbc - the text references that file's string/function/bigint
// tables and cannot be assembled standalone. Functions absent from the
// text, or whose text is unchanged, stay byte-identical.
func Assemble(hasmData string, originalHbc []byte) ([]byte, error) {
	m, err := parser.Parse(originalHbc)
	if err != nil {
		return nil, err
	}
	res, err := asm.Assemble(m, hasmData)
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}
