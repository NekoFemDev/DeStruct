package il2cpp

import (
	"context"
	"fmt"
)

// MethodInfo is one managed method indexed by its native entry address.
type MethodInfo struct {
	RVA        uint64
	TypeName   string
	Name       string
	Params     []string
	ParamTypes []string
	IsStatic   bool
}

// FieldInfo is one instance field indexed by (type, byte offset).
type FieldInfo struct {
	Owner     string
	Name      string
	FieldType string
	Offset    int
}

// MetadataIndex maps native addresses and object offsets back to
// IL2CPP metadata. It implements arm64lift.MetadataProvider structurally.
type MetadataIndex struct {
	Methods map[uint64]MethodInfo
	// Fields is keyed by full type name, then byte offset.
	Fields map[string]map[uint64]FieldInfo
	// Parents maps a type to its base type for field-offset lookup.
	Parents map[string]string
}

// MethodAtRVA implements arm64lift.MetadataProvider.
func (idx *MetadataIndex) MethodAtRVA(rva uint64) (typeName string, params []string, isStatic bool, ok bool) {
	if idx == nil {
		return "", nil, false, false
	}
	m, ok := idx.Methods[rva]
	if !ok {
		return "", nil, false, false
	}
	return m.TypeName, append([]string(nil), m.Params...), m.IsStatic, true
}

// FieldAtOffset implements arm64lift.MetadataProvider. Only direct
// fields of typeName are indexed (base-class walking is left to future
// work).
func (idx *MetadataIndex) FieldAtOffset(typeName string, offset uint64) (fieldName, fieldType string, ok bool) {
	if idx == nil {
		return "", "", false
	}
	for depth := 0; typeName != "" && depth < 64; depth++ {
		fields := idx.Fields[typeName]
		if f, ok := fields[offset]; ok {
			return f.Name, f.FieldType, true
		}
		typeName = idx.Parents[typeName]
	}
	return "", "", false
}

// MethodAt returns the full method record (parameters/types too).
func (idx *MetadataIndex) MethodAt(addr uint64) (MethodInfo, bool) {
	if idx == nil {
		return MethodInfo{}, false
	}
	m, ok := idx.Methods[addr]
	return m, ok
}

// BuildIndexContext walks images/type definitions and builds the
// address/offset index without writing dump.cs.
func BuildIndexContext(ctx context.Context, e *Executor) (*MetadataIndex, error) {
	if e == nil || e.Metadata == nil || e.IL2CPP == nil {
		return nil, fmt.Errorf("il2cpp: executor is not initialized")
	}
	m := e.Metadata
	idx := &MetadataIndex{
		Methods: make(map[uint64]MethodInfo),
		Fields:  make(map[string]map[uint64]FieldInfo),
		Parents: make(map[string]string),
	}

	for imageIndex := 0; imageIndex < m.ImageCount(); imageIndex++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		img := m.Image(imageIndex)
		imageName := m.ImageName(imageIndex)
		typeStart := int(img.i32("typeStart"))
		count := int(img.u32("typeCount"))
		if typeStart < 0 || typeStart > len(m.typeDefs) || count > len(m.typeDefs)-typeStart {
			return nil, fmt.Errorf("il2cpp: image %d type range out of bounds", imageIndex)
		}

		for typeDefIndex := typeStart; typeDefIndex < typeStart+count; typeDefIndex++ {
			if typeDefIndex&0xFF == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			if e.Err() != nil {
				return nil, e.Err()
			}
			td := m.TypeDef(typeDefIndex)
			typeName := e.GetTypeDefName(td, true, false)
			if td.has("parentIndex") && td.i32("parentIndex") >= 0 {
				parent := e.typeAt(int(td.i32("parentIndex")))
				if parent != nil {
					idx.Parents[typeName] = e.GetTypeName(parent, true, false)
				}
			}

			fieldStart := int(td.i32("fieldStart"))
			fieldCount := int(td.u16("field_count"))
			for i := fieldStart; i < fieldStart+fieldCount; i++ {
				fieldDef := m.FieldDef(i)
				fieldType := e.typeAt(int(fieldDef.i32("typeIndex")))
				if fieldType == nil {
					continue
				}
				if fieldType.Attrs&fieldAttributeStatic != 0 || fieldType.Attrs&fieldAttributeLiteral != 0 {
					continue
				}
				off := e.IL2CPP.GetFieldOffsetFromIndex(typeDefIndex, i-fieldStart, i, e.isValueType(td), false)
				if off < 0 {
					continue
				}
				fields := idx.Fields[typeName]
				if fields == nil {
					fields = make(map[uint64]FieldInfo)
					idx.Fields[typeName] = fields
				}
				key := uint64(off)
				if _, exists := fields[key]; exists {
					continue
				}
				fields[key] = FieldInfo{
					Owner:     typeName,
					Name:      m.GetStringFromIndex(fieldDef.u32("nameIndex")),
					FieldType: e.GetTypeName(fieldType, true, false),
					Offset:    off,
				}
			}

			methodStart := int(td.i32("methodStart"))
			methodCount := int(td.u16("method_count"))
			for i := methodStart; i < methodStart+methodCount; i++ {
				methodDef := m.MethodDef(i)
				ptr := e.IL2CPP.GetMethodPointer(imageName, methodDef)
				if ptr == 0 {
					continue
				}
				rva := e.IL2CPP.GetRVA(ptr)
				if rva == 0 {
					continue
				}
				if _, exists := idx.Methods[rva]; exists {
					continue
				}
				info := MethodInfo{
					RVA:      rva,
					TypeName: typeName,
					Name:     m.GetStringFromIndex(methodDef.u32("nameIndex")),
					IsStatic: methodDef.u16("flags")&methodAttributeStatic != 0,
				}
				parameterStart := int(methodDef.i32("parameterStart"))
				parameterCount := int(methodDef.u16("parameterCount"))
				for j := 0; j < parameterCount; j++ {
					parameterDef := m.ParameterDef(parameterStart + j)
					info.Params = append(info.Params, m.GetStringFromIndex(parameterDef.u32("nameIndex")))
					pt := e.typeAt(int(parameterDef.i32("typeIndex")))
					if pt == nil {
						info.ParamTypes = append(info.ParamTypes, "")
					} else {
						info.ParamTypes = append(info.ParamTypes, e.GetTypeName(pt, true, false))
					}
				}
				idx.Methods[rva] = info
			}
		}
	}

	if err := e.Err(); err != nil {
		return nil, err
	}
	return idx, nil
}
