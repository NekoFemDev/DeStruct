package parser

import (
	"encoding/binary"
	"fmt"

	"github.com/destruct/destruct/internal/hermes/ir"
)

// readStringKinds reads the run-length encoded string kind table and
// expands it into one kind per string. The entry layout changed at v71:
// count:31 + kind:1 after it, count:30 + kind:2 before.
func readStringKinds(r *reader, m *ir.Module) error {
	if err := r.align(4); err != nil {
		return fmt.Errorf("string kind table alignment: %w", err)
	}
	count, err := r.countToInt(uint64(m.Header.StringKindCount), 4, "string kinds")
	if err != nil {
		return err
	}

	for i := 0; i < count; i++ {
		raw, err := r.u32()
		if err != nil {
			return fmt.Errorf("string kind %d: %w", i, err)
		}

		var run ir.StringKindRun
		if m.Version >= 71 {
			run.Count = raw & 0x7FFFFFFF
			run.Kind = ir.StringKind(raw >> 31)
		} else {
			run.Count = raw & 0x3FFFFFFF
			run.Kind = ir.StringKind((raw >> 30) & 0x3)
		}

		if uint64(len(m.StringKinds))+uint64(run.Count) > uint64(m.Header.StringCount) {
			return fmt.Errorf("string kind runs cover more than the %d declared strings", m.Header.StringCount)
		}
		for c := uint32(0); c < run.Count; c++ {
			m.StringKinds = append(m.StringKinds, run.Kind)
		}
		m.StringKindRuns = append(m.StringKindRuns, run)
	}
	return nil
}

// readIdentifierHashes reads (and keeps) the identifier hash table.
func readIdentifierHashes(r *reader, m *ir.Module) error {
	if err := r.align(4); err != nil {
		return fmt.Errorf("identifier hash table alignment: %w", err)
	}
	count, err := r.countToInt(uint64(m.Header.IdentifierCount), 4, "identifier hashes")
	if err != nil {
		return err
	}
	m.IdentifierHashes = make([]uint32, count)
	for i := range m.IdentifierHashes {
		v, err := r.u32()
		if err != nil {
			return fmt.Errorf("identifier hash %d: %w", i, err)
		}
		m.IdentifierHashes[i] = v
	}
	return nil
}

// readStrings reads the small string table, the overflow table and the
// string storage blob, then decodes every string.
//
// Small entry layout (v56+, i.e. every version this parser supports):
// isUTF16:1 | offset:23 | length:8. A length of 0xFF redirects through the
// overflow table, indexed by the entry's offset field.
func readStrings(r *reader, m *ir.Module) error {
	if err := r.align(4); err != nil {
		return fmt.Errorf("string table alignment: %w", err)
	}
	smallCount, err := r.countToInt(uint64(m.Header.StringCount), 4, "small string table")
	if err != nil {
		return err
	}
	smallRaw, err := r.bytes(smallCount * 4)
	if err != nil {
		return fmt.Errorf("small string table: %w", err)
	}

	if err := r.align(4); err != nil {
		return fmt.Errorf("overflow string table alignment: %w", err)
	}
	overflowCount, err := r.countToInt(uint64(m.Header.OverflowStringCount), 8, "overflow string table")
	if err != nil {
		return err
	}
	overflowRaw, err := r.bytes(overflowCount * 8)
	if err != nil {
		return fmt.Errorf("overflow string table: %w", err)
	}

	if err := r.align(4); err != nil {
		return fmt.Errorf("string storage alignment: %w", err)
	}
	storage, err := r.bytes(int(m.Header.StringStorageSize))
	if err != nil {
		return fmt.Errorf("string storage: %w", err)
	}

	m.Strings = make([]string, smallCount)
	for i := range m.Strings {
		entry := binary.LittleEndian.Uint32(smallRaw[i*4:])

		isUTF16 := entry&1 != 0
		offset := uint64((entry >> 1) & 0x7FFFFF)
		length := uint64((entry >> 24) & 0xFF)

		if length == 0xFF {
			// Redirect through the overflow table; the small entry's
			// offset is the overflow table index.
			ovIndex := offset
			if ovIndex >= uint64(overflowCount) {
				m.Strings[i] = fmt.Sprintf("<bad_overflow_index:%d>", ovIndex)
				continue
			}
			ov := overflowRaw[ovIndex*8:]
			offset = uint64(binary.LittleEndian.Uint32(ov))
			length = uint64(binary.LittleEndian.Uint32(ov[4:]))
		}

		if isUTF16 {
			length *= 2
		}

		if offset > uint64(len(storage)) || length > uint64(len(storage))-offset {
			m.Strings[i] = fmt.Sprintf("<out_of_range:off=%d,len=%d>", offset, length)
			continue
		}

		raw := storage[offset : offset+length]
		if isUTF16 {
			m.Strings[i] = decodeUTF16(raw)
		} else {
			m.Strings[i] = string(raw)
		}
	}
	return nil
}

// decodeUTF16 decodes Hermes's UTF-16 string bytes the way the reference
// reader does: an optional BOM (little- or big-endian) selects byte order
// and is not part of the string, surrogate pairs are combined, and lone
// surrogates pass through instead of failing the decode.
func decodeUTF16(b []byte) string {
	if len(b)%2 != 0 {
		// Not valid UTF-16; fall back to a byte string rather than lose
		// the data entirely.
		return string(b)
	}
	n := len(b) / 2
	if n == 0 {
		return ""
	}

	units := make([]uint16, n)
	for i := 0; i < n; i++ {
		units[i] = binary.LittleEndian.Uint16(b[i*2:])
	}

	start := 0
	bigEndian := false
	switch units[0] {
	case 0xFEFF: // little-endian BOM: consume, keep order
		start = 1
	case 0xFFFE: // byte-swapped BOM: consume, switch order
		start = 1
		bigEndian = true
	}

	if bigEndian {
		for i := start; i < n; i++ {
			units[i] = uint16(b[i*2])<<8 | uint16(b[i*2+1])
		}
	}

	// Combine surrogate pairs; lone surrogates are emitted as their own
	// code point (Python's errors='surrogatepass'). Go's string(runes)
	// renders invalid code points as U+FFFD, which is the one place this
	// deliberately diverges from a byte-exact Python rendering.
	runes := make([]rune, 0, n)
	for i := start; i < n; i++ {
		u := units[i]
		if u >= 0xD800 && u <= 0xDBFF && i+1 < n {
			next := units[i+1]
			if next >= 0xDC00 && next <= 0xDFFF {
				runes = append(runes, 0x10000+(rune(u)-0xD800)<<10+(rune(next)-0xDC00))
				i++
				continue
			}
		}
		runes = append(runes, rune(u))
	}

	return string(runes)
}
