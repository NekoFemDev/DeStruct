package il2cpp

import "encoding/binary"

// byteRange checks a file-backed range before converting it to int.
func byteRange(data []byte, off, size uint64) (int, int, bool) {
	if off > uint64(len(data)) || size > uint64(len(data))-off {
		return 0, 0, false
	}
	return int(off), int(off + size), true
}

func recordRange(data []byte, off, count, size uint64) (int, int, bool) {
	if size == 0 || count > ^uint64(0)/size {
		return 0, 0, false
	}
	return byteRange(data, off, count*size)
}

// structField is one field of a metadata/registration structure.
//
// Il2CppDumper reads these structures through .NET reflection and skips
// fields according to [Version] attributes; the sizes are simple sums
// with no alignment padding, because every field of every structure is
// naturally aligned on the 32/64-bit targets the tool supports. This
// layout engine reproduces that behaviour so the same struct definitions
// can be shared across metadata versions.
type structField struct {
	name string
	size int           // byte size; 0 when this is a nested struct
	sub  *structLayout // nested struct, when size == 0
	min  float64       // inclusive minimum version; 0 = unbounded
	max  float64       // inclusive maximum version; 0 = unbounded
}

func (f structField) active(v float64) bool {
	if f.min != 0 && v < f.min {
		return false
	}
	if f.max != 0 && v > f.max {
		return false
	}
	return true
}

type structLayout struct {
	fields []structField
}

func (l *structLayout) size(v float64) int {
	n := 0
	for i := range l.fields {
		f := &l.fields[i]
		if !f.active(v) {
			continue
		}
		if f.sub != nil {
			n += f.sub.size(v)
		} else {
			n += f.size
		}
	}
	return n
}

// offset returns the byte offset of a named field for version v, or -1
// when the field does not exist in that version.
func (l *structLayout) offset(v float64, name string) int {
	off := 0
	for i := range l.fields {
		f := &l.fields[i]
		if !f.active(v) {
			continue
		}
		if f.name == name {
			return off
		}
		if f.sub != nil {
			off += f.sub.size(v)
		} else {
			off += f.size
		}
	}
	return -1
}

// Primitive field constructors.

func p(name string, size int) structField {
	return structField{name: name, size: size}
}

func pv(name string, size int, min, max float64) structField {
	return structField{name: name, size: size, min: min, max: max}
}

func s(name string, sub *structLayout, min, max float64) structField {
	return structField{name: name, sub: sub, min: min, max: max}
}

// Little-endian read helpers. Callers guarantee in-range offsets when
// parsing metadata; the ELF reader has its own bounds-checked accessors.

func leU16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func leI16(b []byte, off int) int16  { return int16(binary.LittleEndian.Uint16(b[off:])) }
func leU32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
func leI32(b []byte, off int) int32  { return int32(binary.LittleEndian.Uint32(b[off:])) }
func leU64(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }
func leI64(b []byte, off int) int64  { return int64(binary.LittleEndian.Uint64(b[off:])) }

// record is a view over one fixed-size record plus the layout that
// describes it, so named fields are read at their version-dependent
// offsets.
type record struct {
	b   []byte
	l   *structLayout
	ver float64
}

func (r record) u16(name string) uint16 {
	off := r.l.offset(r.ver, name)
	if off < 0 || off+2 > len(r.b) {
		return 0
	}
	return leU16(r.b, off)
}

func (r record) i16(name string) int16 {
	off := r.l.offset(r.ver, name)
	if off < 0 || off+2 > len(r.b) {
		return 0
	}
	return leI16(r.b, off)
}

func (r record) u32(name string) uint32 {
	off := r.l.offset(r.ver, name)
	if off < 0 || off+4 > len(r.b) {
		return 0
	}
	return leU32(r.b, off)
}

func (r record) i32(name string) int32 {
	off := r.l.offset(r.ver, name)
	if off < 0 || off+4 > len(r.b) {
		return 0
	}
	return leI32(r.b, off)
}

func (r record) u64(name string) uint64 {
	off := r.l.offset(r.ver, name)
	if off < 0 || off+8 > len(r.b) {
		return 0
	}
	return leU64(r.b, off)
}

func (r record) i64(name string) int64 {
	off := r.l.offset(r.ver, name)
	if off < 0 || off+8 > len(r.b) {
		return 0
	}
	return leI64(r.b, off)
}

func (r record) has(name string) bool { return r.l.offset(r.ver, name) >= 0 }

// records slices a metadata table into fixed-size records.
func records(data []byte, off uint32, size int32, l *structLayout, ver float64) []record {
	esz := l.size(ver)
	if esz <= 0 || size <= 0 || int(size)%esz != 0 {
		return nil
	}
	start, _, ok := byteRange(data, uint64(off), uint64(size))
	if !ok {
		return nil
	}
	n := int(size) / esz
	out := make([]record, n)
	for i := 0; i < n; i++ {
		pos := start + i*esz
		out[i] = record{b: data[pos : pos+esz], l: l, ver: ver}
	}
	return out
}
