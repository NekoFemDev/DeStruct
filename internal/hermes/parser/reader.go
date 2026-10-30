package parser

import (
	"encoding/binary"
	"fmt"
)

// reader is a bounds-checked cursor over a byte slice. Every parse step
// goes through it so malformed input produces errors, never panics.
type reader struct {
	data []byte
	pos  int
}

func newReader(data []byte) *reader {
	return &reader{data: data}
}

// tell returns the current absolute offset.
func (r *reader) tell() int {
	return r.pos
}

// size returns the total length of the backing slice.
func (r *reader) size() int {
	return len(r.data)
}

// remaining returns how many bytes are left to read.
func (r *reader) remaining() int {
	return len(r.data) - r.pos
}

// seek moves the cursor to an absolute offset.
func (r *reader) seek(offset int64) error {
	if offset < 0 || offset > int64(len(r.data)) {
		return fmt.Errorf("seek to %d out of range (file is %d bytes)", offset, len(r.data))
	}
	r.pos = int(offset)
	return nil
}

// skip advances the cursor by n bytes.
func (r *reader) skip(n int) error {
	if n < 0 || n > r.remaining() {
		return fmt.Errorf("skip %d bytes with only %d remaining", n, r.remaining())
	}
	r.pos += n
	return nil
}

// align advances the cursor to the next multiple of alignment, reporting
// an error if that would move past the end of the data.
func (r *reader) align(alignment int) error {
	if alignment <= 0 {
		return nil
	}
	if mod := r.pos % alignment; mod != 0 {
		r.pos += alignment - mod
	}
	if r.pos > len(r.data) {
		return fmt.Errorf("alignment to %d moved past the end of the %d-byte slice (offset %d)", alignment, len(r.data), r.pos)
	}
	return nil
}

// inBounds reports whether [pos, pos+n) is fully inside the backing slice.
func (r *reader) inBounds(n int) bool {
	return n >= 0 && r.pos >= 0 && r.pos+n <= len(r.data)
}

func (r *reader) u8() (byte, error) {
	if !r.inBounds(1) {
		return 0, fmt.Errorf("read u8 at offset %d past end of %d-byte slice", r.pos, len(r.data))
	}
	v := r.data[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if !r.inBounds(2) {
		return 0, fmt.Errorf("read u16 at offset %d past end of %d-byte slice", r.pos, len(r.data))
	}
	v := binary.LittleEndian.Uint16(r.data[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *reader) u32() (uint32, error) {
	if !r.inBounds(4) {
		return 0, fmt.Errorf("read u32 at offset %d past end of %d-byte slice", r.pos, len(r.data))
	}
	v := binary.LittleEndian.Uint32(r.data[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *reader) u64() (uint64, error) {
	if !r.inBounds(8) {
		return 0, fmt.Errorf("read u64 at offset %d past end of %d-byte slice", r.pos, len(r.data))
	}
	v := binary.LittleEndian.Uint64(r.data[r.pos:])
	r.pos += 8
	return v, nil
}

// bytes returns a sub-slice of the backing data without copying.
func (r *reader) bytes(n int) ([]byte, error) {
	if !r.inBounds(n) {
		return nil, fmt.Errorf("read %d bytes at offset %d past end of %d-byte slice", n, r.pos, len(r.data))
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

// u32At reads a little-endian u32 at an absolute offset without moving
// the cursor.
func (r *reader) u32At(offset int64) (uint32, error) {
	if offset < 0 || offset+4 > int64(len(r.data)) {
		return 0, fmt.Errorf("read u32 at offset %d out of range (file is %d bytes)", offset, len(r.data))
	}
	return binary.LittleEndian.Uint32(r.data[offset:]), nil
}

// countToInt validates a file-supplied element count against the bytes
// actually remaining before converting it to int, so a corrupt count can
// neither overflow the conversion nor drive an oversized allocation.
func (r *reader) countToInt(count uint64, elementSize int, what string) (int, error) {
	if elementSize <= 0 {
		return 0, fmt.Errorf("%s: invalid element size %d", what, elementSize)
	}
	remaining := uint64(r.remaining())
	if count > remaining/uint64(elementSize) {
		return 0, fmt.Errorf("%s: %d entries of %d bytes do not fit in the %d bytes remaining",
			what, count, elementSize, remaining)
	}
	return int(count), nil
}
