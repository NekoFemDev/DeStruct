package il2cpp

import (
	"context"
	"fmt"
)

// Metadata is a parsed global-metadata.dat file. Table records are kept
// in their raw form and exposed through version-aware field accessors,
// since the on-disk structure layout depends on the metadata version.
type Metadata struct {
	Data    []byte
	Version float64
	Header  MetadataHeader

	imageDefs     []record
	assemblyDefs  []record
	typeDefs      []record
	methodDefs    []record
	parameterDefs []record
	fieldDefs     []record
	propertyDefs  []record
	eventDefs     []record
	genericConts  []record
	genericParams []record
	fieldRefs     []record

	fieldDefaultValues     map[int32]record
	parameterDefaultValues map[int32]record

	stringLiterals []record

	attributeTypeRanges []record
	attributeDataRanges []record
	attributeTypes      []int32

	// attributeRanges maps image index -> entity token -> global
	// attribute range index, for metadata versions > 24.
	attributeRanges map[int]map[uint32]int

	interfaceIndices  []int32
	nestedTypeIndices []int32
	vtableMethods     []uint32

	// metadataUsageDic maps encoded usage kind -> destination index ->
	// decoded metadata index. Only populated for versions 16 < v < 27.
	metadataUsageDic    map[uint32]map[uint32]uint32
	MetadataUsagesCount int64

	// assemblyVersion is the version used for the assembly table, which
	// differs from Version for the 24.1/24.4 variant probe.
	assemblyVersion float64

	stringCache map[uint32]string
}

// MetadataHeader holds the global metadata header. Every field is a
// 32-bit integer on disk; field presence varies by metadata version.
type MetadataHeader struct {
	Sanity  uint32
	Version int32
	Raw     map[string]int64
}

func (h *MetadataHeader) u32(name string) uint32 {
	v, ok := h.Raw[name]
	if !ok {
		return 0
	}
	return uint32(v)
}

func (h *MetadataHeader) i32(name string) int32 {
	v, ok := h.Raw[name]
	if !ok {
		return 0
	}
	return int32(v)
}

var layoutMetadataHeader = structLayout{fields: []structField{
	p("sanity", 4), p("version", 4),
	p("stringLiteralOffset", 4), p("stringLiteralSize", 4),
	p("stringLiteralDataOffset", 4), p("stringLiteralDataSize", 4),
	p("stringOffset", 4), p("stringSize", 4),
	p("eventsOffset", 4), p("eventsSize", 4),
	p("propertiesOffset", 4), p("propertiesSize", 4),
	p("methodsOffset", 4), p("methodsSize", 4),
	p("parameterDefaultValuesOffset", 4), p("parameterDefaultValuesSize", 4),
	p("fieldDefaultValuesOffset", 4), p("fieldDefaultValuesSize", 4),
	p("fieldAndParameterDefaultValueDataOffset", 4), p("fieldAndParameterDefaultValueDataSize", 4),
	p("fieldMarshaledSizesOffset", 4), p("fieldMarshaledSizesSize", 4),
	p("parametersOffset", 4), p("parametersSize", 4),
	p("fieldsOffset", 4), p("fieldsSize", 4),
	p("genericParametersOffset", 4), p("genericParametersSize", 4),
	p("genericParameterConstraintsOffset", 4), p("genericParameterConstraintsSize", 4),
	p("genericContainersOffset", 4), p("genericContainersSize", 4),
	p("nestedTypesOffset", 4), p("nestedTypesSize", 4),
	p("interfacesOffset", 4), p("interfacesSize", 4),
	p("vtableMethodsOffset", 4), p("vtableMethodsSize", 4),
	p("interfaceOffsetsOffset", 4), p("interfaceOffsetsSize", 4),
	p("typeDefinitionsOffset", 4), p("typeDefinitionsSize", 4),
	pv("rgctxEntriesOffset", 4, 0, 24.1), pv("rgctxEntriesCount", 4, 0, 24.1),
	p("imagesOffset", 4), p("imagesSize", 4),
	p("assembliesOffset", 4), p("assembliesSize", 4),
	pv("metadataUsageListsOffset", 4, 19, 24.5), pv("metadataUsageListsCount", 4, 19, 24.5),
	pv("metadataUsagePairsOffset", 4, 19, 24.5), pv("metadataUsagePairsCount", 4, 19, 24.5),
	pv("fieldRefsOffset", 4, 19, 0), pv("fieldRefsSize", 4, 19, 0),
	pv("referencedAssembliesOffset", 4, 20, 0), pv("referencedAssembliesSize", 4, 20, 0),
	pv("attributesInfoOffset", 4, 21, 27.2), pv("attributesInfoCount", 4, 21, 27.2),
	pv("attributeTypesOffset", 4, 21, 27.2), pv("attributeTypesCount", 4, 21, 27.2),
	pv("attributeDataOffset", 4, 29, 0), pv("attributeDataSize", 4, 29, 0),
	pv("attributeDataRangeOffset", 4, 29, 0), pv("attributeDataRangeSize", 4, 29, 0),
	pv("unresolvedVirtualCallParameterTypesOffset", 4, 22, 0), pv("unresolvedVirtualCallParameterTypesSize", 4, 22, 0),
	pv("unresolvedVirtualCallParameterRangesOffset", 4, 22, 0), pv("unresolvedVirtualCallParameterRangesSize", 4, 22, 0),
	pv("windowsRuntimeTypeNamesOffset", 4, 23, 0), pv("windowsRuntimeTypeNamesSize", 4, 23, 0),
	pv("windowsRuntimeStringsOffset", 4, 27, 0), pv("windowsRuntimeStringsSize", 4, 27, 0),
	pv("exportedTypeDefinitionsOffset", 4, 24, 0), pv("exportedTypeDefinitionsSize", 4, 24, 0),
}}

var (
	layoutImageDefinition = structLayout{fields: []structField{
		p("nameIndex", 4), p("assemblyIndex", 4),
		p("typeStart", 4), p("typeCount", 4),
		pv("exportedTypeStart", 4, 24, 0), pv("exportedTypeCount", 4, 24, 0),
		p("entryPointIndex", 4),
		pv("token", 4, 19, 0),
		pv("customAttributeStart", 4, 24.1, 0), pv("customAttributeCount", 4, 24.1, 0),
	}}

	layoutAssemblyNameDefinition = structLayout{fields: []structField{
		p("nameIndex", 4), p("cultureIndex", 4),
		pv("hashValueIndex", 4, 0, 24.3),
		p("publicKeyIndex", 4), p("hash_alg", 4), p("hash_len", 4), p("flags", 4),
		p("major", 4), p("minor", 4), p("build", 4), p("revision", 4),
		p("public_key_token", 8),
	}}

	layoutAssemblyDefinition = structLayout{fields: []structField{
		p("imageIndex", 4),
		pv("token", 4, 24.1, 0),
		pv("customAttributeIndex", 4, 0, 24),
		pv("referencedAssemblyStart", 4, 20, 0), pv("referencedAssemblyCount", 4, 20, 0),
		s("aname", &layoutAssemblyNameDefinition, 0, 0),
	}}

	layoutTypeDefinition = structLayout{fields: []structField{
		p("nameIndex", 4), p("namespaceIndex", 4),
		pv("customAttributeIndex", 4, 0, 24),
		p("byvalTypeIndex", 4),
		pv("byrefTypeIndex", 4, 0, 24.5),
		p("declaringTypeIndex", 4), p("parentIndex", 4), p("elementTypeIndex", 4),
		pv("rgctxStartIndex", 4, 0, 24.1), pv("rgctxCount", 4, 0, 24.1),
		p("genericContainerIndex", 4),
		pv("delegateWrapperFromManagedToNativeIndex", 4, 0, 22),
		pv("marshalingFunctionsIndex", 4, 0, 22),
		pv("ccwFunctionIndex", 4, 21, 22), pv("guidIndex", 4, 21, 22),
		p("flags", 4),
		p("fieldStart", 4), p("methodStart", 4), p("eventStart", 4), p("propertyStart", 4),
		p("nestedTypesStart", 4), p("interfacesStart", 4), p("vtableStart", 4), p("interfaceOffsetsStart", 4),
		p("method_count", 2), p("property_count", 2), p("field_count", 2), p("event_count", 2),
		p("nested_type_count", 2), p("vtable_count", 2), p("interfaces_count", 2), p("interface_offsets_count", 2),
		p("bitfield", 4),
		pv("token", 4, 19, 0),
	}}

	layoutMethodDefinition = structLayout{fields: []structField{
		p("nameIndex", 4), p("declaringType", 4), p("returnType", 4),
		pv("returnParameterToken", 4, 31, 0),
		p("parameterStart", 4),
		pv("customAttributeIndex", 4, 0, 24),
		p("genericContainerIndex", 4),
		pv("methodIndex", 4, 0, 24.1), pv("invokerIndex", 4, 0, 24.1),
		pv("delegateWrapperIndex", 4, 0, 24.1),
		pv("rgctxStartIndex", 4, 0, 24.1), pv("rgctxCount", 4, 0, 24.1),
		p("token", 4), p("flags", 2), p("iflags", 2), p("slot", 2), p("parameterCount", 2),
	}}

	layoutParameterDefinition = structLayout{fields: []structField{
		p("nameIndex", 4), p("token", 4),
		pv("customAttributeIndex", 4, 0, 24),
		p("typeIndex", 4),
	}}

	layoutFieldDefinition = structLayout{fields: []structField{
		p("nameIndex", 4), p("typeIndex", 4),
		pv("customAttributeIndex", 4, 0, 24),
		pv("token", 4, 19, 0),
	}}

	layoutPropertyDefinition = structLayout{fields: []structField{
		p("nameIndex", 4), p("get", 4), p("set", 4), p("attrs", 4),
		pv("customAttributeIndex", 4, 0, 24),
		pv("token", 4, 19, 0),
	}}

	layoutEventDefinition = structLayout{fields: []structField{
		p("nameIndex", 4), p("typeIndex", 4), p("add", 4), p("remove", 4), p("raise", 4),
		pv("customAttributeIndex", 4, 0, 24),
		pv("token", 4, 19, 0),
	}}

	layoutGenericContainer = structLayout{fields: []structField{
		p("ownerIndex", 4), p("type_argc", 4), p("is_method", 4), p("genericParameterStart", 4),
	}}

	layoutGenericParameter = structLayout{fields: []structField{
		p("ownerIndex", 4), p("nameIndex", 4),
		p("constraintsStart", 2), p("constraintsCount", 2),
		p("num", 2), p("flags", 2),
	}}

	layoutFieldRef = structLayout{fields: []structField{
		p("typeIndex", 4), p("fieldIndex", 4),
	}}

	layoutStringLiteral = structLayout{fields: []structField{
		p("length", 4), p("dataIndex", 4),
	}}

	layoutFieldDefaultValue = structLayout{fields: []structField{
		p("fieldIndex", 4), p("typeIndex", 4), p("dataIndex", 4),
	}}

	layoutParameterDefaultValue = structLayout{fields: []structField{
		p("parameterIndex", 4), p("typeIndex", 4), p("dataIndex", 4),
	}}

	layoutCustomAttributeTypeRange = structLayout{fields: []structField{
		pv("token", 4, 24.1, 0), p("start", 4), p("count", 4),
	}}

	layoutCustomAttributeDataRange = structLayout{fields: []structField{
		p("token", 4), p("startOffset", 4),
	}}

	layoutMetadataUsageList = structLayout{fields: []structField{
		p("start", 4), p("count", 4),
	}}

	layoutMetadataUsagePair = structLayout{fields: []structField{
		p("destinationIndex", 4), p("encodedSourceIndex", 4),
	}}

	layoutRGCTXDefinitionData = structLayout{fields: []structField{
		p("rgctxDataDummy", 4),
	}}

	layoutRGCTXDefinition = structLayout{fields: []structField{
		pv("type_pre29", 4, 0, 27.1),
		s("data", &layoutRGCTXDefinitionData, 0, 27.1),
		pv("type_post29", 8, 29, 0),
		pv("_data", 8, 27.2, 0),
	}}
)

// NewMetadata parses a global-metadata.dat image.
func NewMetadata(data []byte) (*Metadata, error) {
	return NewMetadataContext(context.Background(), data)
}

// NewMetadataContext is NewMetadata with cancellation. The parse is
// mostly a bounded pass over the tables, but the nested per-image/
// per-attribute-range scans in readTables and processMetadataUsage poll
// ctx so that a dump cancelled while parsing a very large metadata file
// stops at the next table boundary. The single-pass copiers (records,
// readInt32Array, readUint32Array) run to completion without checks.
func NewMetadataContext(ctx context.Context, data []byte) (*Metadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) < 8 {
		return nil, fmt.Errorf("metadata file too small")
	}
	sanity := leU32(data, 0)
	version := leI32(data, 4)
	if sanity != 0xFAB11BAF {
		return nil, fmt.Errorf("not a valid metadata file (bad magic 0x%X)", sanity)
	}
	if version < 16 || version > 31 {
		return nil, fmt.Errorf("unsupported metadata version %d (supported: 16-31)", version)
	}
	m := &Metadata{
		Data:        data,
		Version:     float64(version),
		stringCache: make(map[uint32]string),
	}
	if int(version) == 24 {
		if err := m.readHeader(); err != nil {
			return nil, err
		}
		if m.Header.u32("stringLiteralOffset") == 264 {
			m.Version = 24.2
			if err := m.readHeader(); err != nil {
				return nil, err
			}
		} else {
			defs := records(data, m.Header.u32("imagesOffset"), m.Header.i32("imagesSize"), &layoutImageDefinition, m.Version)
			for i := range defs {
				if defs[i].has("token") && defs[i].u32("token") != 1 {
					m.Version = 24.1
					break
				}
			}
		}
	}
	if err := m.readHeader(); err != nil {
		return nil, err
	}
	m.assemblyVersion = m.Version
	m.imageDefs = records(data, m.Header.u32("imagesOffset"), m.Header.i32("imagesSize"), &layoutImageDefinition, m.Version)
	m.versionDetect()
	if err := m.readTables(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Metadata) readHeader() error {
	esz := layoutMetadataHeader.size(m.Version)
	if len(m.Data) < esz {
		return fmt.Errorf("metadata header truncated")
	}
	raw := make(map[string]int64, len(layoutMetadataHeader.fields))
	off := 0
	for i := range layoutMetadataHeader.fields {
		f := &layoutMetadataHeader.fields[i]
		if !f.active(m.Version) {
			continue
		}
		switch f.name {
		case "sanity", "version":
			raw[f.name] = int64(leU32(m.Data, off))
		default:
			raw[f.name] = int64(leI32(m.Data, off))
		}
		off += 4
	}
	m.Header = MetadataHeader{
		Sanity:  uint32(raw["sanity"]),
		Version: int32(raw["version"]),
		Raw:     raw,
	}
	return nil
}

// versionDetect applies the 24.1/24.4 assembly-layout variant probe,
// mirroring Il2CppDumper's Metadata constructor. The probe compares the
// raw assemblies table size against the two known Il2CppAssemblyName
// layouts (64 vs 68 bytes per definition).
func (m *Metadata) versionDetect() {
	switch m.Version {
	case 24.1:
		if int(m.Header.i32("assembliesSize"))/64 == len(m.imageDefs) {
			m.assemblyVersion = 24.4
		}
	case 24.2:
		if int(m.Header.i32("assembliesSize"))/68 < len(m.imageDefs) {
			m.Version = 24.4
			m.assemblyVersion = 24.4
		}
	}
}

func (m *Metadata) readTables(ctx context.Context) error {
	h := &m.Header
	v := m.Version

	m.imageDefs = records(m.Data, h.u32("imagesOffset"), h.i32("imagesSize"), &layoutImageDefinition, v)
	m.assemblyDefs = records(m.Data, h.u32("assembliesOffset"), h.i32("assembliesSize"), &layoutAssemblyDefinition, m.assemblyVersion)
	m.typeDefs = records(m.Data, h.u32("typeDefinitionsOffset"), h.i32("typeDefinitionsSize"), &layoutTypeDefinition, v)
	m.methodDefs = records(m.Data, h.u32("methodsOffset"), h.i32("methodsSize"), &layoutMethodDefinition, v)
	m.parameterDefs = records(m.Data, h.u32("parametersOffset"), h.i32("parametersSize"), &layoutParameterDefinition, v)
	m.fieldDefs = records(m.Data, h.u32("fieldsOffset"), h.i32("fieldsSize"), &layoutFieldDefinition, v)
	m.propertyDefs = records(m.Data, h.u32("propertiesOffset"), h.i32("propertiesSize"), &layoutPropertyDefinition, v)
	m.eventDefs = records(m.Data, h.u32("eventsOffset"), h.i32("eventsSize"), &layoutEventDefinition, v)
	m.genericConts = records(m.Data, h.u32("genericContainersOffset"), h.i32("genericContainersSize"), &layoutGenericContainer, v)
	m.genericParams = records(m.Data, h.u32("genericParametersOffset"), h.i32("genericParametersSize"), &layoutGenericParameter, v)
	m.fieldRefs = records(m.Data, h.u32("fieldRefsOffset"), h.i32("fieldRefsSize"), &layoutFieldRef, v)
	m.stringLiterals = records(m.Data, h.u32("stringLiteralOffset"), h.i32("stringLiteralSize"), &layoutStringLiteral, v)
	if err := ctx.Err(); err != nil {
		return err
	}

	m.fieldDefaultValues = make(map[int32]record)
	for i, r := range records(m.Data, h.u32("fieldDefaultValuesOffset"), h.i32("fieldDefaultValuesSize"), &layoutFieldDefaultValue, v) {
		if i%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		m.fieldDefaultValues[r.i32("fieldIndex")] = r
	}
	m.parameterDefaultValues = make(map[int32]record)
	for i, r := range records(m.Data, h.u32("parameterDefaultValuesOffset"), h.i32("parameterDefaultValuesSize"), &layoutParameterDefaultValue, v) {
		if i%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		m.parameterDefaultValues[r.i32("parameterIndex")] = r
	}

	m.interfaceIndices = readInt32Array(m.Data, h.u32("interfacesOffset"), h.i32("interfacesSize"))
	m.nestedTypeIndices = readInt32Array(m.Data, h.u32("nestedTypesOffset"), h.i32("nestedTypesSize"))
	m.vtableMethods = readUint32Array(m.Data, h.u32("vtableMethodsOffset"), h.i32("vtableMethodsSize"))

	if v > 20 && v < 29 {
		m.attributeTypeRanges = records(m.Data, h.u32("attributesInfoOffset"), h.i32("attributesInfoCount"), &layoutCustomAttributeTypeRange, v)
		m.attributeTypes = readInt32Array(m.Data, h.u32("attributeTypesOffset"), h.i32("attributeTypesCount"))
	}
	if v >= 29 {
		m.attributeDataRanges = records(m.Data, h.u32("attributeDataRangeOffset"), h.i32("attributeDataRangeSize"), &layoutCustomAttributeDataRange, v)
	}
	if v > 24 {
		m.attributeRanges = make(map[int]map[uint32]int)
		for i := range m.imageDefs {
			if err := ctx.Err(); err != nil {
				return err
			}
			dic := make(map[uint32]int)
			m.attributeRanges[i] = dic
			start := int(m.imageDefs[i].i32("customAttributeStart"))
			count := uint64(m.imageDefs[i].u32("customAttributeCount"))
			if start < 0 {
				continue
			}
			limit := len(m.attributeTypeRanges)
			if v >= 29 {
				limit = len(m.attributeDataRanges)
			}
			if start >= limit {
				continue
			}
			if count > uint64(limit-start) {
				count = uint64(limit - start)
			}
			for j := start; j < start+int(count); j++ {
				if (j-start)%4096 == 0 {
					if err := ctx.Err(); err != nil {
						return err
					}
				}
				if v >= 29 {
					if j < len(m.attributeDataRanges) {
						dic[m.attributeDataRanges[j].u32("token")] = j
					}
				} else if j < len(m.attributeTypeRanges) {
					dic[m.attributeTypeRanges[j].u32("token")] = j
				}
			}
		}
	}
	if v > 16 && v < 27 {
		if err := m.processMetadataUsage(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (m *Metadata) processMetadataUsage(ctx context.Context) error {
	h := &m.Header
	lists := records(m.Data, h.u32("metadataUsageListsOffset"), h.i32("metadataUsageListsCount"), &layoutMetadataUsageList, m.Version)
	pairs := records(m.Data, h.u32("metadataUsagePairsOffset"), h.i32("metadataUsagePairsCount"), &layoutMetadataUsagePair, m.Version)
	m.metadataUsageDic = make(map[uint32]map[uint32]uint32)
	for i := uint32(1); i <= 6; i++ {
		m.metadataUsageDic[i] = make(map[uint32]uint32)
	}
	for _, l := range lists {
		if err := ctx.Err(); err != nil {
			return err
		}
		start := l.u32("start")
		count := l.u32("count")
		if uint64(start) >= uint64(len(pairs)) {
			continue
		}
		end := uint64(start) + uint64(count)
		if end > uint64(len(pairs)) {
			end = uint64(len(pairs))
		}
		for off := uint64(start); off < end; off++ {
			if (off-uint64(start))%4096 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			p := pairs[off]
			usage := encodedIndexType(p.u32("encodedSourceIndex"))
			decoded := m.DecodedMethodIndex(p.u32("encodedSourceIndex"))
			m.metadataUsageDic[usage][p.u32("destinationIndex")] = decoded
		}
	}
	var maxDest uint32
	n := 0
	for _, dic := range m.metadataUsageDic {
		for dest := range dic {
			n++
			if n%4096 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			if dest > maxDest {
				maxDest = dest
			}
		}
	}
	m.MetadataUsagesCount = int64(maxDest) + 1
	return nil
}

func encodedIndexType(index uint32) uint32 { return (index & 0xE0000000) >> 29 }

// DecodedMethodIndex decodes an encoded metadata usage index.
func (m *Metadata) DecodedMethodIndex(index uint32) uint32 {
	if m.Version >= 27 {
		return (index & 0x1FFFFFFE) >> 1
	}
	return index & 0x1FFFFFFF
}

// GetStringFromIndex reads a metadata string by its string table offset.
func (m *Metadata) GetStringFromIndex(index uint32) string {
	if s, ok := m.stringCache[index]; ok {
		return s
	}
	base, _, ok := byteRange(m.Data, uint64(m.Header.u32("stringOffset"))+uint64(index), 1)
	if !ok {
		m.stringCache[index] = ""
		return ""
	}
	end := base
	for end < len(m.Data) && m.Data[end] != 0 {
		end++
	}
	s := string(m.Data[base:end])
	m.stringCache[index] = s
	return s
}

// GetStringLiteralFromIndex reads a managed string literal.
func (m *Metadata) GetStringLiteralFromIndex(index uint32) string {
	if uint64(index) >= uint64(len(m.stringLiterals)) {
		return ""
	}
	lit := m.stringLiterals[index]
	base, end, ok := byteRange(m.Data, uint64(m.Header.u32("stringLiteralDataOffset"))+uint64(lit.u32("dataIndex")), uint64(lit.u32("length")))
	if !ok {
		return ""
	}
	return string(m.Data[base:end])
}

func (m *Metadata) GetFieldDefaultValueFromIndex(index int32) (record, bool) {
	r, ok := m.fieldDefaultValues[index]
	return r, ok
}

func (m *Metadata) GetParameterDefaultValueFromIndex(index int32) (record, bool) {
	r, ok := m.parameterDefaultValues[index]
	return r, ok
}

// GetDefaultValueFromIndex returns the file offset of a default value blob.
func (m *Metadata) GetDefaultValueFromIndex(index int32) uint32 {
	return m.Header.u32("fieldAndParameterDefaultValueDataOffset") + uint32(index)
}

// GetCustomAttributeIndex resolves an entity token to a global attribute
// range index, or -1 when the entity has no attributes.
func (m *Metadata) GetCustomAttributeIndex(imageIndex int, customAttributeIndex int32, token uint32) int {
	if m.Version > 24 {
		if dic, ok := m.attributeRanges[imageIndex]; ok {
			if idx, ok := dic[token]; ok {
				return idx
			}
		}
		return -1
	}
	return int(customAttributeIndex)
}

// Table accessors used by the executor and the dump writer.

func (m *Metadata) ImageCount() int { return len(m.imageDefs) }

func (m *Metadata) Image(index int) record { return m.imageDefs[index] }

func (m *Metadata) ImageName(index int) string {
	return m.GetStringFromIndex(m.imageDefs[index].u32("nameIndex"))
}

func (m *Metadata) TypeDefCount() int { return len(m.typeDefs) }

func (m *Metadata) TypeDef(index int) record { return m.typeDefs[index] }

func (m *Metadata) MethodDef(index int) record { return m.methodDefs[index] }

func (m *Metadata) MethodDefCount() int { return len(m.methodDefs) }

func (m *Metadata) ParameterDef(index int) record { return m.parameterDefs[index] }

func (m *Metadata) FieldDef(index int) record { return m.fieldDefs[index] }

func (m *Metadata) PropertyDef(index int) record { return m.propertyDefs[index] }

func (m *Metadata) GenericContainer(index int) record { return m.genericConts[index] }

func (m *Metadata) GenericParameter(index int) record { return m.genericParams[index] }

func (m *Metadata) InterfaceIndex(offset int) int32 { return m.interfaceIndices[offset] }

func (m *Metadata) NestedTypeIndex(offset int) int32 { return m.nestedTypeIndices[offset] }

func (m *Metadata) FieldRef(index int) record { return m.fieldRefs[index] }

// readInt32Array/readUint32Array (and records in layout.go) are
// single-pass table copiers: they run to completion and are not
// interrupted mid-table; cancellation is observed at the readTables /
// processMetadataUsage boundaries above.
func readInt32Array(data []byte, off uint32, size int32) []int32 {
	if off == 0 || size <= 0 || size%4 != 0 {
		return nil
	}
	start, _, ok := byteRange(data, uint64(off), uint64(size))
	if !ok {
		return nil
	}
	n := int(size) / 4
	out := make([]int32, n)
	for i := 0; i < n; i++ {
		out[i] = leI32(data, start+i*4)
	}
	return out
}

func readUint32Array(data []byte, off uint32, size int32) []uint32 {
	if off == 0 || size <= 0 || size%4 != 0 {
		return nil
	}
	start, _, ok := byteRange(data, uint64(off), uint64(size))
	if !ok {
		return nil
	}
	n := int(size) / 4
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		out[i] = leU32(data, start+i*4)
	}
	return out
}
