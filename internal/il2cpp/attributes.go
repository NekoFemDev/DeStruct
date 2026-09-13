package il2cpp

import (
	"fmt"
	"strings"
)

// customAttributeDataReader decodes the compressed custom-attribute blob
// format introduced in metadata v29. The layout is:
//
//	compressed uint32 attributeCount
//	attributeCount compressed constructor method indices
//	<attributeCount*4 bytes after the ctor list start> argument data
//
// The constructor list is read sequentially (each entry is compressed and
// may occupy 1-4 bytes); the argument data offset is always reserved as
// four bytes per attribute from the start of the list.
type customAttributeDataReader struct {
	executor    *Executor
	metadata    *Metadata
	r           metadataReader
	count       uint32
	ctorBuffer  int
	dataBuffer  int
	includeArgs bool
}

func newCustomAttributeDataReader(e *Executor, buff []byte, includeArgs bool) *customAttributeDataReader {
	r := &customAttributeDataReader{
		executor:    e,
		metadata:    e.Metadata,
		r:           metadataReader{data: buff},
		includeArgs: includeArgs,
	}
	r.count = r.r.compressedUInt32()
	r.ctorBuffer = r.r.pos
	r.dataBuffer = r.r.pos + int(r.count)*4
	return r
}

func (c *customAttributeDataReader) Count() uint32 { return c.count }

// safeGetString decodes one attribute, treating malformed data as an
// empty result so a single bad entry doesn't abort the enclosing type.
func (c *customAttributeDataReader) safeGetString() (out string) {
	defer func() {
		if recover() != nil {
			out = ""
		}
	}()
	return c.getStringCustomAttributeData()
}

func (c *customAttributeDataReader) getStringCustomAttributeData() string {
	if c.ctorBuffer < 0 || c.ctorBuffer >= len(c.r.data) {
		return ""
	}
	c.r.pos = c.ctorBuffer
	ctorIndex := int(c.r.compressedUInt32())
	c.ctorBuffer = c.r.pos
	if ctorIndex < 0 || ctorIndex >= len(c.metadata.methodDefs) {
		return ""
	}
	methodDef := c.metadata.MethodDef(ctorIndex)
	declaring := methodDef.i32("declaringType")
	if declaring < 0 || int(declaring) >= len(c.metadata.typeDefs) {
		return ""
	}
	typeDef := c.metadata.TypeDef(int(declaring))
	typeName := strings.ReplaceAll(c.metadata.GetStringFromIndex(typeDef.u32("nameIndex")), "Attribute", "")
	if !c.includeArgs {
		return fmt.Sprintf("[%s]", typeName)
	}

	c.r.pos = c.dataBuffer
	argumentCount := c.r.compressedUInt32()
	fieldCount := c.r.compressedUInt32()
	propertyCount := c.r.compressedUInt32()

	var args []string
	for i := uint32(0); i < argumentCount; i++ {
		args = append(args, c.attributeDataToString(c.readAttributeDataValue()))
	}
	for i := uint32(0); i < fieldCount; i++ {
		str := c.attributeDataToString(c.readAttributeDataValue())
		declaring, fieldIndex := c.readNamedArgumentClassAndIndex(typeDef)
		fieldDef := c.metadata.FieldDef(int(declaring.i32("fieldStart")) + fieldIndex)
		args = append(args, fmt.Sprintf("%s = %s", c.metadata.GetStringFromIndex(fieldDef.u32("nameIndex")), str))
	}
	for i := uint32(0); i < propertyCount; i++ {
		str := c.attributeDataToString(c.readAttributeDataValue())
		declaring, propertyIndex := c.readNamedArgumentClassAndIndex(typeDef)
		propertyDef := c.metadata.PropertyDef(int(declaring.i32("propertyStart")) + propertyIndex)
		args = append(args, fmt.Sprintf("%s = %s", c.metadata.GetStringFromIndex(propertyDef.u32("nameIndex")), str))
	}
	c.dataBuffer = c.r.pos

	if len(args) > 0 {
		return fmt.Sprintf("[%s(%s)]", typeName, strings.Join(args, ", "))
	}
	return fmt.Sprintf("[%s]", typeName)
}

func (c *customAttributeDataReader) attributeDataToString(v blobValue) string {
	if v.value == nil {
		return "null"
	}
	switch v.typeEnum {
	case typeString:
		if s, ok := v.value.(string); ok {
			return fmt.Sprintf("%q", s)
		}
		return fmt.Sprint(v.value)
	case typeSZArray:
		array, _ := v.value.([]blobValue)
		items := make([]string, 0, len(array))
		for _, item := range array {
			items = append(items, c.attributeDataToString(item))
		}
		return "new[] { " + strings.Join(items, ", ") + " }"
	case typeIl2CppTypeIndex:
		if t, ok := v.value.(*Il2CppType); ok {
			return "typeof(" + c.executor.GetTypeName(t, false, false) + ")"
		}
		return "typeof(?)"
	default:
		return formatBlobValue(v.value)
	}
}

func formatBlobValue(v any) string {
	switch val := v.(type) {
	case bool:
		if val {
			return "true"
		}
		return "false"
	case string:
		return val
	case charValue:
		return fmt.Sprintf("'\\x%x'", int(val))
	default:
		return fmt.Sprint(v)
	}
}

func (c *customAttributeDataReader) readAttributeDataValue() blobValue {
	typ, _ := c.executor.readEncodedTypeEnum(&c.r)
	v, _ := c.executor.constantValueFromBlob(typ, &c.r, true)
	return v
}

func (c *customAttributeDataReader) readNamedArgumentClassAndIndex(typeDef record) (record, int) {
	memberIndex := c.r.compressedInt32()
	if memberIndex >= 0 {
		return typeDef, int(memberIndex)
	}
	memberIndex = -(memberIndex + 1)
	typeIndex := c.r.compressedUInt32()
	return c.metadata.TypeDef(int(typeIndex)), int(memberIndex)
}
