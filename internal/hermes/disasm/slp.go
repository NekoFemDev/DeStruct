package disasm

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
)

// This file is the Go port of hermes-dec's serialized_literal_parser.py:
// the TLV ("Serialized Literal") format used by the array/literal buffer
// and the object key/value buffers.
//
// Binary format: a tag byte per run, with tag type in bits 4-6, an
// extended-length flag in bit 7, and a run length in the low four bits
// (or the low four bits plus a following byte when extended). Each run's
// payload items follow according to their tag.
//
// One version dependency: starting with bytecode version 98, raw tag 6
// was repurposed from ByteStringTag (a 1-byte string index) to
// UndefinedTag (no payload), so the tag is synthesized here.

type slpTag uint8

const (
	slpNull slpTag = iota
	slpTrue
	slpFalse
	slpNumber
	slpLongString
	slpShortString
	slpByteString
	slpInteger
	// slpUndefined is not an on-disk tag value; it is what a raw tag 6
	// decodes to on bytecode version 98 and later.
	slpUndefined
)

type slpValue struct {
	tag  slpTag
	num  float64
	ival uint64
}

type slpArray struct {
	items []slpValue
}

// maxSLPItems bounds how many entries unpackSLPArray will produce. The
// item count operand is normally small, but with a corrupt file or the
// wrong opcode table it can be a garbage 32-bit value; several tags
// (null/true/false/undefined) consume zero payload bytes, so an
// unguarded loop could allocate far beyond what the input can encode.
const maxSLPItems = 1 << 20

// unpackSLPArray decodes up to numItems values from data, following the
// tag/length framing of unpack_slp_array().
func unpackSLPArray(data []byte, numItems int, version uint32) slpArray {
	if numItems < 0 {
		numItems = 0
	}
	if numItems > maxSLPItems {
		numItems = maxSLPItems
	}
	// Bound total output by what the input could plausibly encode; the
	// multiplier covers zero-payload tags at the densest packing.
	if numItems > len(data)*8+64 {
		numItems = len(data)*8 + 64
	}

	var items []slpValue
	pos := 0

	readByte := func() (byte, bool) {
		if pos >= len(data) {
			return 0, false
		}
		b := data[pos]
		pos++
		return b, true
	}

	for len(items) < numItems {
		nextTag, ok := readByte()
		if !ok {
			break
		}
		tagType := slpTag((nextTag >> 4) & 0b111)

		var length int
		if nextTag>>7 == 1 {
			lenLo, ok := readByte()
			if !ok {
				break
			}
			length = (int(nextTag&0b1111) << 8) | int(lenLo)
		} else {
			length = int(nextTag & 0b1111)
		}

		if tagType == slpByteString && version >= 98 {
			tagType = slpUndefined
		}

		for i := 0; i < length; i++ {
			switch tagType {
			case slpNull, slpTrue, slpFalse, slpUndefined:
				items = append(items, slpValue{tag: tagType})
			case slpNumber:
				if pos+8 > len(data) {
					items = append(items, slpValue{tag: slpNumber})
					pos = len(data)
					continue
				}
				items = append(items, slpValue{tag: slpNumber, num: math.Float64frombits(binary.LittleEndian.Uint64(data[pos:]))})
				pos += 8
			case slpLongString:
				if pos+4 > len(data) {
					items = append(items, slpValue{tag: slpLongString})
					pos = len(data)
					continue
				}
				items = append(items, slpValue{tag: slpLongString, ival: uint64(binary.LittleEndian.Uint32(data[pos:]))})
				pos += 4
			case slpShortString:
				if pos+2 > len(data) {
					items = append(items, slpValue{tag: slpShortString})
					pos = len(data)
					continue
				}
				items = append(items, slpValue{tag: slpShortString, ival: uint64(binary.LittleEndian.Uint16(data[pos:]))})
				pos += 2
			case slpByteString:
				if pos+1 > len(data) {
					items = append(items, slpValue{tag: slpByteString})
					pos = len(data)
					continue
				}
				items = append(items, slpValue{tag: slpByteString, ival: uint64(data[pos])})
				pos++
			case slpInteger:
				if pos+4 > len(data) {
					items = append(items, slpValue{tag: slpInteger})
					pos = len(data)
					continue
				}
				items = append(items, slpValue{tag: slpInteger, ival: uint64(binary.LittleEndian.Uint32(data[pos:]))})
				pos += 4
			}
		}
	}

	if len(items) > numItems {
		items = items[:numItems]
	}
	return slpArray{items: items}
}

// toStrings renders each item the way SLPArray.to_strings does in the
// Python reference: bare words for null/true/false/undefined, Python
// str() for numbers and integers, Python repr() of the referenced string
// for the string tags.
func (a slpArray) toStrings(stringTable []string) []string {
	out := make([]string, 0, len(a.items))
	for _, item := range a.items {
		var s string
		switch item.tag {
		case slpNull:
			s = "null"
		case slpTrue:
			s = "true"
		case slpFalse:
			s = "false"
		case slpUndefined:
			s = "undefined"
		case slpNumber:
			s = formatPyFloat(item.num)
		case slpInteger:
			s = strconv.FormatUint(item.ival, 10)
		case slpLongString, slpShortString, slpByteString:
			id := int(item.ival)
			if id >= 0 && id < len(stringTable) {
				s = pyRepr(stringTable[id])
			} else {
				s = fmt.Sprintf("<bad_string_id:%d>", id)
			}
		default:
			s = "<?>"
		}
		out = append(out, s)
	}
	return out
}
