package parser

import (
	"fmt"
	"math/big"

	"github.com/destruct/destruct/internal/hermes/ir"
)

// readLiteralBuffers reads the array/literal value buffer (the array
// buffer before v97), the object key buffer, and either the object value
// buffer (v<97) or the object shape table (v97+).
func readLiteralBuffers(r *reader, m *ir.Module) error {
	if err := r.align(4); err != nil {
		return fmt.Errorf("literal buffer alignment: %w", err)
	}
	var err error

	if m.Version < 97 {
		if m.ArrayBuffer, err = r.bytes(int(m.Header.ArrayBufferSize)); err != nil {
			return fmt.Errorf("array buffer: %w", err)
		}
	} else {
		if m.LiteralValueBuffer, err = r.bytes(int(m.Header.LiteralValueBufferSize)); err != nil {
			return fmt.Errorf("literal value buffer: %w", err)
		}
	}

	if err := r.align(4); err != nil {
		return fmt.Errorf("object key buffer alignment: %w", err)
	}
	if m.ObjectKeyBuffer, err = r.bytes(int(m.Header.ObjKeyBufferSize)); err != nil {
		return fmt.Errorf("object key buffer: %w", err)
	}

	if m.Version < 97 {
		if err := r.align(4); err != nil {
			return fmt.Errorf("object value buffer alignment: %w", err)
		}
		if m.ObjectValueBuffer, err = r.bytes(int(m.Header.ObjValueBufferSize)); err != nil {
			return fmt.Errorf("object value buffer: %w", err)
		}
		return nil
	}

	if err := r.align(4); err != nil {
		return fmt.Errorf("object shape table alignment: %w", err)
	}
	count, err := r.countToInt(uint64(m.Header.ObjShapeTableCount), 8, "object shape table")
	if err != nil {
		return err
	}
	m.ObjectShapeTable = make([]ir.ShapeTableEntry, count)
	for i := range m.ObjectShapeTable {
		if m.ObjectShapeTable[i].KeyBufferOffset, err = r.u32(); err != nil {
			return fmt.Errorf("shape table entry %d key buffer offset: %w", i, err)
		}
		if m.ObjectShapeTable[i].NumProps, err = r.u32(); err != nil {
			return fmt.Errorf("shape table entry %d num props: %w", i, err)
		}
	}
	return nil
}

// readBigInts reads the bigint table and storage (v87+), decoding each
// entry's little-endian magnitude into its decimal rendering.
func readBigInts(r *reader, m *ir.Module) error {
	if err := r.align(4); err != nil {
		return fmt.Errorf("bigint table alignment: %w", err)
	}
	count, err := r.countToInt(uint64(m.Header.BigIntCount), 8, "bigint table")
	if err != nil {
		return err
	}
	m.BigInts = make([]ir.BigInt, count)
	for i := range m.BigInts {
		if m.BigInts[i].Offset, err = r.u32(); err != nil {
			return fmt.Errorf("bigint entry %d offset: %w", i, err)
		}
		if m.BigInts[i].Length, err = r.u32(); err != nil {
			return fmt.Errorf("bigint entry %d length: %w", i, err)
		}
	}

	if err := r.align(4); err != nil {
		return fmt.Errorf("bigint storage alignment: %w", err)
	}
	if m.BigIntData, err = r.bytes(int(m.Header.BigIntStorageSize)); err != nil {
		return fmt.Errorf("bigint storage: %w", err)
	}

	for i := range m.BigInts {
		entry := &m.BigInts[i]
		if uint64(entry.Offset) > uint64(len(m.BigIntData)) ||
			uint64(entry.Length) > uint64(len(m.BigIntData))-uint64(entry.Offset) {
			entry.Value = "0"
			continue
		}
		entry.Value = decodeLittleEndianBigInt(m.BigIntData[entry.Offset : entry.Offset+entry.Length]).String()
	}
	return nil
}

// readRegExps reads the regexp table and its storage blob.
func readRegExps(r *reader, m *ir.Module) error {
	if err := r.align(4); err != nil {
		return fmt.Errorf("regexp table alignment: %w", err)
	}
	count, err := r.countToInt(uint64(m.Header.RegExpCount), 8, "regexp table")
	if err != nil {
		return err
	}
	m.RegExpTable = make([]ir.RegExpRef, count)
	for i := range m.RegExpTable {
		if m.RegExpTable[i].Offset, err = r.u32(); err != nil {
			return fmt.Errorf("regexp entry %d offset: %w", i, err)
		}
		if m.RegExpTable[i].Length, err = r.u32(); err != nil {
			return fmt.Errorf("regexp entry %d length: %w", i, err)
		}
	}
	if err := r.align(4); err != nil {
		return fmt.Errorf("regexp storage alignment: %w", err)
	}
	if m.RegExpStorage, err = r.bytes(int(m.Header.RegExpStorageSize)); err != nil {
		return fmt.Errorf("regexp storage: %w", err)
	}
	return nil
}

// readCJSModules reads the CommonJS module table. Before v77, a file
// built with static resolution stores one plain uint32 per module
// instead of the (symbolID, offset) pair.
func readCJSModules(r *reader, m *ir.Module) error {
	if err := r.align(4); err != nil {
		return fmt.Errorf("cjs module table alignment: %w", err)
	}
	count, err := r.countToInt(uint64(m.Header.CJSModuleCount), 8, "cjs module table")
	if err != nil {
		return err
	}

	m.CJSModules = make([]ir.CJSModule, count)
	if m.Header.CJSModulesStaticallyResolved && m.Version < 77 {
		for i := range m.CJSModules {
			v, err := r.u32()
			if err != nil {
				return fmt.Errorf("cjs module %d: %w", i, err)
			}
			m.CJSModules[i] = ir.CJSModule{Raw: v, IsRaw: true}
		}
		return nil
	}

	for i := range m.CJSModules {
		if m.CJSModules[i].SymbolID, err = r.u32(); err != nil {
			return fmt.Errorf("cjs module %d symbol: %w", i, err)
		}
		if m.CJSModules[i].Offset, err = r.u32(); err != nil {
			return fmt.Errorf("cjs module %d offset: %w", i, err)
		}
	}
	return nil
}

// readFunctionSources reads the function source table (v84+).
func readFunctionSources(r *reader, m *ir.Module) error {
	if err := r.align(4); err != nil {
		return fmt.Errorf("function source table alignment: %w", err)
	}
	count, err := r.countToInt(uint64(m.Header.FunctionSourceCount), 8, "function source table")
	if err != nil {
		return err
	}
	m.FunctionSources = make([]ir.FunctionSource, count)
	for i := range m.FunctionSources {
		if m.FunctionSources[i].FunctionID, err = r.u32(); err != nil {
			return fmt.Errorf("function source %d function id: %w", i, err)
		}
		if m.FunctionSources[i].StringID, err = r.u32(); err != nil {
			return fmt.Errorf("function source %d string id: %w", i, err)
		}
	}
	return nil
}

// decodeLittleEndianBigInt decodes a little-endian magnitude.
func decodeLittleEndianBigInt(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i, v := range b {
		be[len(b)-1-i] = v
	}
	return new(big.Int).SetBytes(be)
}
