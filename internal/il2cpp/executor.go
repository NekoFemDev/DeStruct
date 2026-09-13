package il2cpp

import (
	"fmt"
	"math"
	"strings"
)

// C# / IL2CPP reflection constants.

const (
	fieldAttributeFieldAccessMask = 0x0007
	fieldAttributePrivate         = 0x0001
	fieldAttributeFamAndAssem     = 0x0002
	fieldAttributeAssembly        = 0x0003
	fieldAttributeFamily          = 0x0004
	fieldAttributeFamOrAssem      = 0x0005
	fieldAttributePublic          = 0x0006
	fieldAttributeStatic          = 0x0010
	fieldAttributeInitOnly        = 0x0020
	fieldAttributeLiteral         = 0x0040

	methodAttributeMemberAccessMask = 0x0007
	methodAttributePrivate          = 0x0001
	methodAttributeFamAndAssem      = 0x0002
	methodAttributeAssem            = 0x0003
	methodAttributeFamily           = 0x0004
	methodAttributeFamOrAssem       = 0x0005
	methodAttributePublic           = 0x0006
	methodAttributeStatic           = 0x0010
	methodAttributeFinal            = 0x0020
	methodAttributeVirtual          = 0x0040
	methodAttributeVtableLayoutMask = 0x0100
	methodAttributeReuseSlot        = 0x0000
	methodAttributeNewSlot          = 0x0100
	methodAttributeAbstract         = 0x0400
	methodAttributePinvokeImpl      = 0x2000

	typeAttributeVisibilityMask    = 0x00000007
	typeAttributeNotPublic         = 0x00000000
	typeAttributePublic            = 0x00000001
	typeAttributeNestedPublic      = 0x00000002
	typeAttributeNestedPrivate     = 0x00000003
	typeAttributeNestedFamily      = 0x00000004
	typeAttributeNestedAssembly    = 0x00000005
	typeAttributeNestedFamAndAssem = 0x00000006
	typeAttributeNestedFamOrAssem  = 0x00000007
	typeAttributeInterface         = 0x00000020
	typeAttributeAbstract          = 0x00000080
	typeAttributeSealed            = 0x00000100
	typeAttributeSerializable      = 0x00002000

	paramAttributeIn  = 0x0001
	paramAttributeOut = 0x0002
)

// IL2CPP type enum values.
const (
	typeEnd             = 0x00
	typeVoid            = 0x01
	typeBoolean         = 0x02
	typeChar            = 0x03
	typeI1              = 0x04
	typeU1              = 0x05
	typeI2              = 0x06
	typeU2              = 0x07
	typeI4              = 0x08
	typeU4              = 0x09
	typeI8              = 0x0a
	typeU8              = 0x0b
	typeR4              = 0x0c
	typeR8              = 0x0d
	typeString          = 0x0e
	typePtr             = 0x0f
	typeByRef           = 0x10
	typeValueType       = 0x11
	typeClass           = 0x12
	typeVar             = 0x13
	typeArray           = 0x14
	typeGenericInst     = 0x15
	typeTypedByRef      = 0x16
	typeI               = 0x18
	typeU               = 0x19
	typeFnPtr           = 0x1b
	typeObject          = 0x1c
	typeSZArray         = 0x1d
	typeMVar            = 0x1e
	typeEnum            = 0x55
	typeIl2CppTypeIndex = 0xff
)

var typeStrings = map[uint8]string{
	typeVoid:       "void",
	typeBoolean:    "bool",
	typeChar:       "char",
	typeI1:         "sbyte",
	typeU1:         "byte",
	typeI2:         "short",
	typeU2:         "ushort",
	typeI4:         "int",
	typeU4:         "uint",
	typeI8:         "long",
	typeU8:         "ulong",
	typeR4:         "float",
	typeR8:         "double",
	typeString:     "string",
	typeTypedByRef: "TypedReference",
	typeI:          "IntPtr",
	typeU:          "UIntPtr",
	typeObject:     "object",
}

// Executor mirrors Il2CppDumper's Il2CppExecutor: it turns metadata
// records into the type names and constant values used by the dump.
type Executor struct {
	Metadata *Metadata
	IL2CPP   *IL2CPP

	customAttributeGenerators []uint64
	includeAttrArgs           bool
}

func NewExecutor(m *Metadata, ic *IL2CPP) *Executor {
	e := &Executor{Metadata: m, IL2CPP: ic}
	if ic.Version >= 27 && ic.Version < 29 {
		total := 0
		for i := 0; i < m.ImageCount(); i++ {
			total += int(m.Image(i).u32("customAttributeCount"))
		}
		e.customAttributeGenerators = make([]uint64, total)
		for i := 0; i < m.ImageCount(); i++ {
			img := m.Image(i)
			mod := ic.CodeGenModules[m.ImageName(i)]
			if mod == nil || img.u32("customAttributeCount") == 0 {
				continue
			}
			ptrs := ic.readU64s(mod.CustomAttributeCacheGenerator, int64(img.u32("customAttributeCount")))
			copy(e.customAttributeGenerators[int(img.i32("customAttributeStart")):], ptrs)
		}
	} else if ic.Version < 27 {
		e.customAttributeGenerators = ic.CustomAttributeGenerators
	}
	return e
}

func (e *Executor) typeAt(index int) *Il2CppType {
	if index < 0 || index >= len(e.IL2CPP.Types) {
		panic(fmt.Sprintf("il2cpp: type index %d out of range", index))
	}
	t := e.IL2CPP.Types[index]
	if t == nil {
		panic(fmt.Sprintf("il2cpp: nil type at index %d", index))
	}
	return t
}

// GetTypeName renders an Il2CppType as a C# type name.
func (e *Executor) GetTypeName(t *Il2CppType, addNamespace, isNested bool) string {
	switch t.TypeEnum {
	case typeArray:
		at := e.readArrayType(t.DataPoint)
		elementType := e.IL2CPP.GetIl2CppType(at.etype)
		if elementType == nil {
			panic("il2cpp: array element type not found")
		}
		return fmt.Sprintf("%s[%s]", e.GetTypeName(elementType, addNamespace, false), strings.Repeat(",", int(at.rank)-1))
	case typeSZArray:
		elementType := e.IL2CPP.GetIl2CppType(t.DataPoint)
		if elementType == nil {
			panic("il2cpp: szarray element type not found")
		}
		return e.GetTypeName(elementType, addNamespace, false) + "[]"
	case typePtr:
		oriType := e.IL2CPP.GetIl2CppType(t.DataPoint)
		if oriType == nil {
			panic("il2cpp: pointer element type not found")
		}
		return e.GetTypeName(oriType, addNamespace, false) + "*"
	case typeVar:
		// The reference dump renders every type generic parameter as the
		// literal name "T", regardless of its metadata name.
		return "T"
	case typeMVar:
		// ... and every method generic parameter as "TMethod".
		return "TMethod"
	case typeClass, typeValueType, typeGenericInst:
		var str string
		var typeDef record
		var genericClass *genericClass
		if t.TypeEnum == typeGenericInst {
			genericClass = e.readGenericClass(t.DataPoint)
			typeDef = e.GetGenericClassTypeDefinition(genericClass)
		} else {
			typeDef = e.GetTypeDefinitionFromIl2CppType(t)
		}
		if d := tdDeclaring(typeDef); d != -1 {
			dt := e.typeAt(d)
			switch dt.TypeEnum {
			case typeGenericInst:
				// Nested inside an instantiated generic outer type: the
				// reference drops the nested name (KeyCollection nested
				// in Dictionary<TKey,TValue> shows as Dictionary<T, T>).
				return e.GetTypeName(dt, addNamespace, false)
			case typeClass, typeValueType:
				dtd := e.GetTypeDefinitionFromIl2CppType(dt)
				if genericClass != nil {
					// Walk up the declaring chain looking for the
					// outermost generic definition or instantiation; the
					// reference collapses ValueTask<T>.ValueTaskSourceAsTask.<>c,
					// Values<T>.TransitionEventsFrameState.<>c and
					// UniTask<T>.Awaiter to ValueTask<T> / Values<T> /
					// UniTask<T>. Non-generic outer types are kept only
					// as part of the rendered prefix.
					cur := dtd
					var top record
					haveTop := false
					for {
						if tdGenericContainer(cur) >= 0 {
							top = cur
							haveTop = true
						}
						pd := tdDeclaring(cur)
						if pd == -1 {
							break
						}
						pt := e.typeAt(pd)
						if pt.TypeEnum == typeGenericInst {
							return e.GetTypeName(pt, addNamespace, false)
						}
						if pt.TypeEnum != typeClass && pt.TypeEnum != typeValueType {
							break
						}
						cur = e.GetTypeDefinitionFromIl2CppType(pt)
					}
					if haveTop {
						return e.GetTypeDefName(top, addNamespace, false) +
							e.GetGenericInstParams(e.GenericInstAt(genericClass.contextClassInst))
					}
				}
				str = e.GetTypeDefName(dtd, addNamespace, false) + "."
			default:
				// Primitives such as System.String keep a typeDef index
				// in the datapoint (string.TrimType -> System.String).
				dtd := e.GetTypeDefinitionFromIl2CppType(dt)
				str = e.GetTypeDefName(dtd, addNamespace, false) + "."
			}
		} else if addNamespace {
			ns := e.Metadata.GetStringFromIndex(typeDef.u32("namespaceIndex"))
			if ns != "" {
				str += ns + "."
			}
		}
		typeName := e.Metadata.GetStringFromIndex(typeDef.u32("nameIndex"))
		if idx := strings.Index(typeName, "`"); idx != -1 {
			str += typeName[:idx]
		} else {
			str += typeName
		}
		if isNested {
			return str
		}
		if genericClass != nil {
			inst := e.GenericInstAt(genericClass.contextClassInst)
			str += e.GetGenericInstParams(inst)
		} else if gci := tdGenericContainer(typeDef); gci >= 0 {
			gc := e.Metadata.GenericContainer(int(gci))
			str += e.GetGenericContainerParams(gc)
		}
		return str
	default:
		if s, ok := typeStrings[t.TypeEnum]; ok {
			return s
		}
		panic(fmt.Sprintf("il2cpp: unknown type enum 0x%X", t.TypeEnum))
	}
}

type arrayType struct {
	etype uint64
	rank  uint8
}

func (e *Executor) readArrayType(addr uint64) arrayType {
	b, ok := e.IL2CPP.readRecord(addr, &layoutArrayType)
	if !ok {
		panic("il2cpp: cannot map Il2CppArrayType")
	}
	return arrayType{etype: leU64(b, 0), rank: b[8]}
}

var layoutArrayType = structLayout{fields: []structField{
	p("etype", 8), p("rank", 1), p("numsizes", 1), p("numlobounds", 1),
	p("sizes", 8), p("lobounds", 8),
}}

type genericClass struct {
	typeDefIndex      int64
	typ               uint64
	contextClassInst  uint64
	contextMethodInst uint64
	cachedClass       uint64
}

func (e *Executor) readGenericClass(addr uint64) *genericClass {
	b, ok := e.IL2CPP.readRecord(addr, &layoutGenericClass)
	if !ok {
		panic("il2cpp: cannot map Il2CppGenericClass")
	}
	r := record{b: b, l: &layoutGenericClass, ver: e.IL2CPP.Version}
	ctxOff := layoutGenericClass.offset(e.IL2CPP.Version, "context")
	gc := &genericClass{
		typeDefIndex: r.i64("typeDefinitionIndex"),
		typ:          r.u64("type"),
		cachedClass:  r.u64("cached_class"),
	}
	if ctxOff >= 0 && ctxOff+16 <= len(b) {
		gc.contextClassInst = leU64(b, ctxOff)
		gc.contextMethodInst = leU64(b, ctxOff+8)
	}
	return gc
}

func (e *Executor) typeDefAt(index int) record {
	if index < 0 || index >= len(e.Metadata.typeDefs) {
		panic(fmt.Sprintf("il2cpp: type definition index %d out of range", index))
	}
	return e.Metadata.typeDefs[index]
}

func tdDeclaring(td record) int {
	if !td.has("declaringTypeIndex") {
		return -1
	}
	return int(td.i32("declaringTypeIndex"))
}

func tdGenericContainer(td record) int32 {
	if !td.has("genericContainerIndex") {
		return -1
	}
	return td.i32("genericContainerIndex")
}

// GetTypeDefName renders a type definition's own name.
func (e *Executor) GetTypeDefName(td record, addNamespace, genericParameter bool) string {
	prefix := ""
	if d := tdDeclaring(td); d != -1 {
		prefix = e.GetTypeName(e.typeAt(d), addNamespace, true) + "."
	} else if addNamespace {
		ns := e.Metadata.GetStringFromIndex(td.u32("namespaceIndex"))
		if ns != "" {
			prefix = ns + "."
		}
	}
	typeName := e.Metadata.GetStringFromIndex(td.u32("nameIndex"))
	if gci := tdGenericContainer(td); gci >= 0 {
		if idx := strings.Index(typeName, "`"); idx != -1 {
			typeName = typeName[:idx]
		}
		if genericParameter {
			gc := e.Metadata.GenericContainer(int(gci))
			typeName += e.GetGenericContainerParams(gc)
		}
	}
	return prefix + typeName
}

func (e *Executor) GetGenericInstParams(inst *il2CppGenericInst) string {
	if inst == nil {
		return "<?>"
	}
	pointers := e.IL2CPP.readU64s(inst.TypeArgv, inst.TypeArgc)
	names := make([]string, 0, len(pointers))
	for _, p := range pointers {
		t := e.IL2CPP.GetIl2CppType(p)
		if t == nil {
			names = append(names, "?")
			continue
		}
		names = append(names, e.GetTypeName(t, true, false))
	}
	return "<" + strings.Join(names, ", ") + ">"
}

func (e *Executor) GetGenericContainerParams(gc record) string {
	n := int(gc.i32("type_argc"))
	start := int(gc.i32("genericParameterStart"))
	names := make([]string, 0, n)
	for i := 0; i < n; i++ {
		idx := start + i
		if idx < 0 || idx >= len(e.Metadata.genericParams) {
			break
		}
		gp := e.Metadata.genericParams[idx]
		names = append(names, e.Metadata.GetStringFromIndex(gp.u32("nameIndex")))
	}
	return "<" + strings.Join(names, ", ") + ">"
}

// GetMethodSpecName renders a generic method instantiation.
func (e *Executor) GetMethodSpecName(spec Il2CppMethodSpec, addNamespace bool) (string, string) {
	methodDef := e.Metadata.MethodDef(int(spec.MethodDefinitionIndex))
	typeDef := e.typeDefAt(int(methodDef.i32("declaringType")))
	typeName := e.GetTypeDefName(typeDef, addNamespace, false)
	if spec.ClassIndexIndex != -1 && int(spec.ClassIndexIndex) < len(e.IL2CPP.GenericInsts) {
		typeName += e.GetGenericInstParams(e.IL2CPP.GenericInsts[spec.ClassIndexIndex])
	}
	methodName := e.Metadata.GetStringFromIndex(methodDef.u32("nameIndex"))
	if spec.MethodIndexIndex != -1 && int(spec.MethodIndexIndex) < len(e.IL2CPP.GenericInsts) {
		methodName += e.GetGenericInstParams(e.IL2CPP.GenericInsts[spec.MethodIndexIndex])
	}
	return typeName, methodName
}

// GenericInstAt maps a runtime Il2CppGenericInst pointer.
func (e *Executor) GenericInstAt(addr uint64) *il2CppGenericInst {
	if addr == 0 {
		return nil
	}
	b, ok := e.IL2CPP.readRecord(addr, &layoutGenericInst)
	if !ok {
		return nil
	}
	r := record{b: b, l: &layoutGenericInst, ver: e.IL2CPP.Version}
	return &il2CppGenericInst{TypeArgc: r.i64("type_argc"), TypeArgv: r.u64("type_argv")}
}

func (e *Executor) GetGenericClassTypeDefinition(gc *genericClass) record {
	if e.IL2CPP.Version >= 27 {
		t := e.IL2CPP.GetIl2CppType(gc.typ)
		if t == nil {
			panic("il2cpp: generic class type not found")
		}
		return e.GetTypeDefinitionFromIl2CppType(t)
	}
	if gc.typeDefIndex == 4294967295 || gc.typeDefIndex == -1 {
		panic("il2cpp: generic class has no type definition")
	}
	return e.typeDefAt(int(gc.typeDefIndex))
}

func (e *Executor) GetTypeDefinitionFromIl2CppType(t *Il2CppType) record {
	return e.typeDefAt(int(t.DataPoint))
}

func (e *Executor) GenericParameterFromType(t *Il2CppType) record {
	return e.Metadata.GenericParameter(int(t.DataPoint))
}

// Default values.

// charValue distinguishes a decoded System.Char from an int32.
type charValue rune

type blobValue struct {
	value    any
	typeEnum uint8
}

type metadataReader struct {
	data []byte
	pos  int
	// limit bounds reads to the containing metadata section; 0 means the
	// whole file. Default value blobs are bounded so a corrupt length
	// can't run past the default-value data section.
	limit int
}

func (r *metadataReader) end() int {
	if r.limit > 0 && r.limit < len(r.data) {
		return r.limit
	}
	return len(r.data)
}

func (r *metadataReader) readByte() byte {
	if r.pos >= r.end() {
		panic("il2cpp: metadata reader out of bounds")
	}
	b := r.data[r.pos]
	r.pos++
	return b
}

func (r *metadataReader) readBytes(n int) []byte {
	if n < 0 || r.pos+n > r.end() {
		panic("il2cpp: metadata reader out of bounds")
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b
}

func (r *metadataReader) compressedUInt32() uint32 {
	read := r.readByte()
	switch {
	case read&0x80 == 0:
		return uint32(read)
	case read&0xC0 == 0x80:
		val := uint32(read&^0x80) << 8
		val |= uint32(r.readByte())
		return val
	case read&0xE0 == 0xC0:
		val := uint32(read&^0xC0) << 24
		val |= uint32(r.readByte()) << 16
		val |= uint32(r.readByte()) << 8
		val |= uint32(r.readByte())
		return val
	case read == 0xF0:
		b := r.readBytes(4)
		return leU32(b, 0)
	case read == 0xFE:
		return ^uint32(0) - 1
	case read == 0xFF:
		return ^uint32(0)
	default:
		panic("il2cpp: invalid compressed integer")
	}
}

func (r *metadataReader) compressedInt32() int32 {
	encoded := r.compressedUInt32()
	if encoded == ^uint32(0) {
		return -1 << 31
	}
	negative := encoded&1 != 0
	encoded >>= 1
	if negative {
		return -int32(encoded + 1)
	}
	return int32(encoded)
}

// TryGetDefaultValue decodes a field/parameter default value blob. The
// reference dump reads fixed-width integers here (not the compressed
// form used for custom attribute arguments), so callers pass the blob
// style explicitly.
func (e *Executor) TryGetDefaultValue(typeIndex int, dataIndex int32) (out any, ok bool) {
	defer func() {
		if recover() != nil {
			out = nil
			ok = false
		}
	}()
	pointer := e.Metadata.GetDefaultValueFromIndex(dataIndex)
	defaultValueType := e.typeAt(typeIndex)
	limit := int(e.Metadata.Header.u32("fieldAndParameterDefaultValueDataOffset")) +
		int(e.Metadata.Header.i32("fieldAndParameterDefaultValueDataSize"))
	reader := &metadataReader{data: e.Metadata.Data, pos: int(pointer), limit: limit}
	if v, ok := e.constantValueFromBlob(defaultValueType.TypeEnum, reader, false); ok {
		return v.value, true
	}
	return pointer, false
}

// constantValueFromBlob decodes one serialized constant. When compressed
// is true the length/integer fields use v29+ compressed integers (custom
// attribute data); otherwise they are fixed-width (default values).
func (e *Executor) constantValueFromBlob(typ uint8, reader *metadataReader, compressed bool) (blobValue, bool) {
	v := blobValue{typeEnum: typ}
	switch typ {
	case typeBoolean:
		v.value = reader.readByte() != 0
		return v, true
	case typeU1:
		v.value = reader.readByte()
		return v, true
	case typeI1:
		v.value = int8(reader.readByte())
		return v, true
	case typeChar:
		b := reader.readBytes(2)
		v.value = charValue(leU16(b, 0))
		return v, true
	case typeU2:
		v.value = leU16(reader.readBytes(2), 0)
		return v, true
	case typeI2:
		v.value = int16(leU16(reader.readBytes(2), 0))
		return v, true
	case typeU4:
		if compressed {
			v.value = reader.compressedUInt32()
		} else {
			v.value = leU32(reader.readBytes(4), 0)
		}
		return v, true
	case typeI4:
		if compressed {
			v.value = reader.compressedInt32()
		} else {
			v.value = leI32(reader.readBytes(4), 0)
		}
		return v, true
	case typeU8:
		v.value = leU64(reader.readBytes(8), 0)
		return v, true
	case typeI8:
		v.value = leI64(reader.readBytes(8), 0)
		return v, true
	case typeR4:
		v.value = float32frombits(leU32(reader.readBytes(4), 0))
		return v, true
	case typeR8:
		v.value = float64frombits(leU64(reader.readBytes(8), 0))
		return v, true
	case typeString:
		if compressed {
			length := reader.compressedInt32()
			if length == -1 {
				v.value = nil
			} else {
				v.value = string(reader.readBytes(int(length)))
			}
		} else {
			length := leI32(reader.readBytes(4), 0)
			if length < 0 {
				v.value = nil
			} else {
				v.value = string(reader.readBytes(int(length)))
			}
		}
		return v, true
	case typeSZArray:
		arrayLen := reader.compressedInt32()
		if arrayLen == -1 {
			v.value = nil
			return v, true
		}
		elementType, _ := e.readEncodedTypeEnum(reader)
		different := reader.readByte()
		array := make([]blobValue, arrayLen)
		for i := 0; i < int(arrayLen); i++ {
			et := elementType
			if different == 1 {
				et, _ = e.readEncodedTypeEnum(reader)
			}
			data, _ := e.constantValueFromBlob(et, reader, compressed)
			data.typeEnum = et
			array[i] = data
		}
		v.value = array
		return v, true
	case typeIl2CppTypeIndex:
		typeIndex := reader.compressedInt32()
		if typeIndex == -1 {
			v.value = nil
		} else {
			v.value = e.typeAt(int(typeIndex))
		}
		return v, true
	default:
		return blobValue{}, false
	}
}

func (e *Executor) readEncodedTypeEnum(reader *metadataReader) (uint8, *Il2CppType) {
	var enumType *Il2CppType
	typ := reader.readByte()
	if typ == typeEnum {
		enumTypeIndex := reader.compressedInt32()
		enumType = e.typeAt(int(enumTypeIndex))
		typeDef := e.GetTypeDefinitionFromIl2CppType(enumType)
		typ = e.typeAt(int(typeDef.i32("elementTypeIndex"))).TypeEnum
	}
	return typ, enumType
}

func float32frombits(b uint32) float32 { return math.Float32frombits(b) }
func float64frombits(b uint64) float64 { return math.Float64frombits(b) }
