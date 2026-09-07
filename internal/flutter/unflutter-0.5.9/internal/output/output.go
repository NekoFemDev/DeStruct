// Package output handles writing unflutter analysis artifacts to disk.
package output

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/disasm"
	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/snapshot"
)

// SymbolEntry is one symbol written to symbols.json.
type SymbolEntry struct {
	Address uint64 `json:"address"`
	Name    string `json:"name"`
	Size    uint64 `json:"size"`
}

// WriteSnapshotJSON writes info to dir/snapshot.json.
func WriteSnapshotJSON(dir string, info *snapshot.Info) error {
	path := filepath.Join(dir, "snapshot.json")
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// WriteSymbolsJSON writes entries to dir/symbols.json.
func WriteSymbolsJSON(dir string, entries []SymbolEntry) error {
	path := filepath.Join(dir, "symbols.json")
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// WriteASM writes a per-function assembly file to dir/asm/<filename>.txt.
func WriteASM(dir, filename string, insts []disasm.Inst, lookup disasm.SymbolLookup, annotators ...disasm.Annotator) error {
	asmDir := filepath.Join(dir, "asm")
	if err := os.MkdirAll(asmDir, 0755); err != nil {
		return err
	}
	path := filepath.Join(asmDir, filename+".txt")
	if err := os.WriteFile(path, []byte(disasm.Format(insts, lookup, annotators...)), 0644); err != nil {
		return err
	}
	return nil
}

// WriteASMSingle writes a single combined assembly file to dir/asm.txt.
func WriteASMSingle(dir string, insts []disasm.Inst, lookup disasm.SymbolLookup) error {
	path := filepath.Join(dir, "asm.txt")
	return os.WriteFile(path, []byte(disasm.Format(insts, lookup)), 0644)
}

// WriteBin writes raw function bytes to dir/asm/<filename>.bin.
func WriteBin(dir, filename string, data []byte) error {
	asmDir := filepath.Join(dir, "asm")
	if err := os.MkdirAll(asmDir, 0755); err != nil {
		return err
	}
	path := filepath.Join(asmDir, filename+".bin")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}
	return nil
}
