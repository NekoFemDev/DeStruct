package dex

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// DexAnnotation is one decoded annotation_item.
type DexAnnotation struct {
	TypeDesc   string
	Visibility uint8
	Elements   []DexAnnotationElement
}

type DexAnnotationElement struct {
	Name  string
	Value string
}

// DexAnnotationDirectory holds class/field/method annotations for one
// class definition.
type DexAnnotationDirectory struct {
	Class  []DexAnnotation
	Fields map[uint32][]DexAnnotation
	// Methods maps a method_idx to its method-level annotations.
	Methods map[uint32][]DexAnnotation
	// Params maps a method_idx to one annotation set per declared
	// parameter (the implicit this is not included).
	Params map[uint32][][]DexAnnotation
}

// GetAnnotations decodes the annotations_directory_item referenced by
// cd.AnnotationsOff. A missing or malformed directory yields nil.
func (dex *DexFile) GetAnnotations(cd ClassDef) *DexAnnotationDirectory {
	if cd.AnnotationsOff == 0 {
		return nil
	}
	off := cd.AnnotationsOff
	if dex.checkRange(off, 16, 1, "annotation directory") != nil {
		return nil
	}
	dir := &DexAnnotationDirectory{
		Fields:  make(map[uint32][]DexAnnotation),
		Methods: make(map[uint32][]DexAnnotation),
		Params:  make(map[uint32][][]DexAnnotation),
	}
	classOff := binary.LittleEndian.Uint32(dex.data[off : off+4])
	fieldsSize := binary.LittleEndian.Uint32(dex.data[off+4 : off+8])
	methodsSize := binary.LittleEndian.Uint32(dex.data[off+8 : off+12])
	paramsSize := binary.LittleEndian.Uint32(dex.data[off+12 : off+16])

	dir.Class = dex.parseAnnotationSet(classOff)
	pos := off + 16
	for i := uint32(0); i < fieldsSize; i++ {
		if dex.checkRange(pos, 8, 1, "field annotation") != nil {
			return dir
		}
		fieldIdx := binary.LittleEndian.Uint32(dex.data[pos : pos+4])
		annOff := binary.LittleEndian.Uint32(dex.data[pos+4 : pos+8])
		dir.Fields[fieldIdx] = dex.parseAnnotationSet(annOff)
		pos += 8
	}
	for i := uint32(0); i < methodsSize; i++ {
		if dex.checkRange(pos, 8, 1, "method annotation") != nil {
			return dir
		}
		methodIdx := binary.LittleEndian.Uint32(dex.data[pos : pos+4])
		annOff := binary.LittleEndian.Uint32(dex.data[pos+4 : pos+8])
		dir.Methods[methodIdx] = dex.parseAnnotationSet(annOff)
		pos += 8
	}
	for i := uint32(0); i < paramsSize; i++ {
		if dex.checkRange(pos, 8, 1, "parameter annotation") != nil {
			return dir
		}
		methodIdx := binary.LittleEndian.Uint32(dex.data[pos : pos+4])
		annOff := binary.LittleEndian.Uint32(dex.data[pos+4 : pos+8])
		dir.Params[methodIdx] = dex.parseAnnotationSetRefList(annOff)
		pos += 8
	}
	return dir
}

// javaQuote renders s as a Java string literal. Unlike strconv.Quote it
// never emits Go-only escapes such as \xNN, and it escapes non-ASCII as
// UTF-16 \uNNNN sequences.
func javaQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r >= 0x20 && r <= 0x7e {
				b.WriteRune(r)
				continue
			}
			if r <= 0xffff {
				fmt.Fprintf(&b, `\u%04x`, r)
				continue
			}
			r -= 0x10000
			fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (dex *DexFile) parseAnnotationSetRefList(off uint32) [][]DexAnnotation {
	if off == 0 || dex.checkRange(off, 4, 1, "annotation set ref list") != nil {
		return nil
	}
	size := binary.LittleEndian.Uint32(dex.data[off : off+4])
	if size > 4096 || dex.checkRange(off+4, size*4, 1, "annotation set ref entries") != nil {
		return nil
	}
	out := make([][]DexAnnotation, size)
	for i := uint32(0); i < size; i++ {
		pos := off + 4 + i*4
		setOff := binary.LittleEndian.Uint32(dex.data[pos : pos+4])
		out[i] = dex.parseAnnotationSet(setOff)
	}
	return out
}

func (dex *DexFile) parseAnnotationSet(off uint32) []DexAnnotation {
	if off == 0 || dex.checkRange(off, 4, 1, "annotation set") != nil {
		return nil
	}
	size := binary.LittleEndian.Uint32(dex.data[off : off+4])
	if size > 4096 || dex.checkRange(off+4, size*4, 1, "annotation set entries") != nil {
		return nil
	}
	out := make([]DexAnnotation, 0, size)
	for i := uint32(0); i < size; i++ {
		pos := off + 4 + i*4
		itemOff := binary.LittleEndian.Uint32(dex.data[pos : pos+4])
		if ann, ok := dex.parseAnnotationItem(itemOff); ok {
			out = append(out, ann)
		}
	}
	return out
}

func (dex *DexFile) parseAnnotationItem(off uint32) (DexAnnotation, bool) {
	if off == 0 || dex.checkRange(off, 2, 1, "annotation item") != nil {
		return DexAnnotation{}, false
	}
	ann := DexAnnotation{Visibility: dex.data[off]}
	pos := off + 1
	typeIdx, next, err := dex.readULEB128(pos)
	if err != nil {
		return DexAnnotation{}, false
	}
	pos = next
	ann.TypeDesc = dex.GetTypeDesc(typeIdx)
	size, next, err := dex.readULEB128(pos)
	if err != nil {
		return DexAnnotation{}, false
	}
	pos = next
	for i := uint32(0); i < size; i++ {
		nameIdx, next, err := dex.readULEB128(pos)
		if err != nil {
			return DexAnnotation{}, false
		}
		value, next, err := dex.parseEncodedValue(next)
		if err != nil {
			return DexAnnotation{}, false
		}
		pos = next
		ann.Elements = append(ann.Elements, DexAnnotationElement{
			Name:  dex.GetString(nameIdx),
			Value: value,
		})
	}
	return ann, true
}

// parseEncodedValue decodes one encoded_value into Java source text.
func (dex *DexFile) parseEncodedValue(off uint32) (string, uint32, error) {
	if int(off) >= len(dex.data) {
		return "", off, fmt.Errorf("encoded value out of range")
	}
	header := dex.data[off]
	pos := off + 1
	valueType := header & 0x1f
	valueArg := uint32(header >> 5)
	size := valueArg + 1

	readUnsigned := func() (uint64, error) {
		if dex.checkRange(pos, size, 1, "encoded value") != nil {
			return 0, fmt.Errorf("encoded value out of range")
		}
		var v uint64
		for i := uint32(0); i < size && i < 8; i++ {
			v |= uint64(dex.data[pos+i]) << (8 * i)
		}
		pos += size
		return v, nil
	}
	readSigned := func() (int64, error) {
		v, err := readUnsigned()
		if err != nil {
			return 0, err
		}
		bits := size * 8
		if bits < 64 && v&(1<<(bits-1)) != 0 {
			v |= ^uint64(0) << bits
		}
		return int64(v), nil
	}

	switch valueType {
	case 0x00: // byte
		v, err := readSigned()
		return strconv.FormatInt(v, 10), pos, err
	case 0x02: // short
		v, err := readSigned()
		return strconv.FormatInt(v, 10), pos, err
	case 0x03: // char
		v, err := readUnsigned()
		return fmt.Sprintf("'\\u%04x'", v&0xffff), pos, err
	case 0x04: // int
		v, err := readSigned()
		return strconv.FormatInt(v, 10), pos, err
	case 0x06: // long
		v, err := readSigned()
		return strconv.FormatInt(v, 10) + "L", pos, err
	case 0x10: // float
		v, err := readUnsigned()
		if err != nil {
			return "", pos, err
		}
		return strconv.FormatFloat(float64(math.Float32frombits(uint32(v))), 'g', -1, 32) + "f", pos, nil
	case 0x11: // double
		v, err := readUnsigned()
		if err != nil {
			return "", pos, err
		}
		return strconv.FormatFloat(math.Float64frombits(v), 'g', -1, 64), pos, nil
	case 0x17: // string
		v, err := readUnsigned()
		if err != nil {
			return "", pos, err
		}
		return javaQuote(dex.GetString(uint32(v))), pos, nil
	case 0x18: // type
		v, err := readUnsigned()
		if err != nil {
			return "", pos, err
		}
		return JavaClassName(dex.GetTypeDesc(uint32(v))) + ".class", pos, nil
	case 0x1a: // method
		v, err := readUnsigned()
		if err != nil {
			return "", pos, err
		}
		return fmt.Sprintf("0x%x", v), pos, nil
	case 0x19: // field
		v, err := readUnsigned()
		if err != nil {
			return "", pos, err
		}
		return fmt.Sprintf("0x%x", v), pos, nil
	case 0x1b: // enum
		v, err := readUnsigned()
		if err != nil {
			return "", pos, err
		}
		if fid := dex.GetFieldId(uint32(v)); fid != nil {
			return JavaClassName(dex.GetTypeDesc(uint32(fid.ClassIdx))) + "." + dex.GetString(fid.NameIdx), pos, nil
		}
		return "null", pos, nil
	case 0x1c: // array
		count, next, err := dex.readULEB128(pos)
		if err != nil {
			return "", pos, err
		}
		pos = next
		parts := make([]string, 0, count)
		for i := uint32(0); i < count; i++ {
			value, next, err := dex.parseEncodedValue(pos)
			if err != nil {
				return "", pos, err
			}
			pos = next
			parts = append(parts, value)
		}
		return "{ " + strings.Join(parts, ", ") + " }", pos, nil
	case 0x1d: // annotation
		typeIdx, next, err := dex.readULEB128(pos)
		if err != nil {
			return "", pos, err
		}
		pos = next
		count, next, err := dex.readULEB128(pos)
		if err != nil {
			return "", pos, err
		}
		pos = next
		parts := make([]string, 0, count)
		for i := uint32(0); i < count; i++ {
			nameIdx, next, err := dex.readULEB128(pos)
			if err != nil {
				return "", pos, err
			}
			value, next, err := dex.parseEncodedValue(next)
			if err != nil {
				return "", pos, err
			}
			pos = next
			parts = append(parts, dex.GetString(nameIdx)+" = "+value)
		}
		return "@" + JavaClassName(dex.GetTypeDesc(typeIdx)) + "(" + strings.Join(parts, ", ") + ")", pos, nil
	case 0x1e: // null
		return "null", pos, nil
	case 0x1f: // boolean
		if valueArg != 0 {
			return "true", pos, nil
		}
		return "false", pos, nil
	default:
		return fmt.Sprintf("0x%x", valueType), pos, nil
	}
}
