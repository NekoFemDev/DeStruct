package il2cpp

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DumpOptions controls dump.cs generation.
type DumpOptions struct {
	// OutputDir receives dump.cs.
	OutputDir string
	// DumpFields / DumpMethods / DumpProperties toggle table sections.
	DumpFields     bool
	DumpMethods    bool
	DumpProperties bool
	// DumpAttributes emits custom attributes.
	DumpAttributes bool
	// DumpAttributeArgs includes custom attribute constructor arguments,
	// e.g. [Tooltip("...")]. The reference dump omits them.
	DumpAttributeArgs bool
	// DumpFieldOffsets emits "; // 0xNN" comments.
	DumpFieldOffsets bool
	// DumpTypeDefIndex emits "// TypeDefIndex: N".
	DumpTypeDefIndex bool
}

// DefaultDumpOptions mirrors the options used for the reference dump.
func DefaultDumpOptions() DumpOptions {
	return DumpOptions{
		DumpFields:       true,
		DumpMethods:      true,
		DumpProperties:   true,
		DumpAttributes:   true,
		DumpFieldOffsets: true,
		DumpTypeDefIndex: true,
	}
}

// DumpCS writes a dump.cs in the Il2CppDumper format.
func (e *Executor) DumpCS(opts DumpOptions) error {
	m := e.Metadata
	if opts.OutputDir == "" {
		opts.OutputDir = "output"
	}
	e.includeAttrArgs = opts.DumpAttributeArgs
	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}
	path := filepath.Join(opts.OutputDir, "dump.cs")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating dump.cs: %w", err)
	}
	w := bufio.NewWriterSize(f, 1<<20)

	for i := 0; i < m.ImageCount(); i++ {
		img := m.Image(i)
		fmt.Fprintf(w, "// Image %d: %s - %d\n", i, m.ImageName(i), img.i32("typeStart"))
	}

	for imageIndex := 0; imageIndex < m.ImageCount(); imageIndex++ {
		img := m.Image(imageIndex)
		imageName := m.ImageName(imageIndex)
		typeStart := int(img.i32("typeStart"))
		count := uint64(img.u32("typeCount"))
		if typeStart < 0 || typeStart > len(m.typeDefs) || count > uint64(len(m.typeDefs)-typeStart) {
			e.fail("images", int64(imageIndex), "type definition range out of bounds")
			f.Close()
			return e.Err()
		}
		typeEnd := typeStart + int(count)
		for typeDefIndex := typeStart; typeDefIndex < typeEnd; typeDefIndex++ {
			e.dumpType(w, imageIndex, imageName, typeDefIndex, opts)
			if err := e.Err(); err != nil {
				f.Close()
				return err
			}
		}
	}
	w.WriteString("\n")

	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

// dumpType writes one type definition. Any unexpected decoder panic is
// returned as a table-indexed error instead of leaking to the CLI.
func (e *Executor) dumpType(w *bufio.Writer, imageIndex int, imageName string, typeDefIndex int, opts DumpOptions) {
	defer func() {
		if r := recover(); r != nil {
			e.fail("typeDefs", int64(typeDefIndex), fmt.Sprintf("decoder error: %v", r))
		}
	}()

	m := e.Metadata
	td := m.TypeDef(typeDefIndex)

	var extends []string
	if td.has("parentIndex") && td.i32("parentIndex") >= 0 {
		parent := e.typeAt(int(td.i32("parentIndex")))
		parentName := e.GetTypeName(parent, true, false)
		// The reference dump omits generic-instantiation base classes.
		if !e.isValueType(td) && !isEnumTD(td) && parentName != "object" && parent.TypeEnum != typeGenericInst {
			extends = append(extends, parentName)
		}
	}
	if count := int(td.u16("interfaces_count")); count > 0 {
		start := int(td.i32("interfacesStart"))
		for i := 0; i < count; i++ {
			idx := start + i
			if idx < 0 || idx >= len(m.interfaceIndices) {
				break
			}
			iface := e.typeAt(int(m.interfaceIndices[idx]))
			extends = append(extends, e.GetTypeName(iface, true, false))
		}
	}

	fmt.Fprintf(w, "\n// Dll : %s\n", imageName)
	fmt.Fprintf(w, "// Namespace: %s\n", m.GetStringFromIndex(td.u32("namespaceIndex")))
	if opts.DumpAttributes {
		w.WriteString(e.GetCustomAttribute(imageIndex, td.i32("customAttributeIndex"), td.u32("token"), ""))
	}

	flags := td.u32("flags")
	switch flags & typeAttributeVisibilityMask {
	case typeAttributePublic, typeAttributeNestedPublic:
		w.WriteString("public ")
	case typeAttributeNotPublic, typeAttributeNestedFamAndAssem, typeAttributeNestedAssembly:
		w.WriteString("internal ")
	case typeAttributeNestedPrivate:
		w.WriteString("private ")
	case typeAttributeNestedFamily:
		w.WriteString("protected ")
	case typeAttributeNestedFamOrAssem:
		w.WriteString("protected internal ")
	}
	if flags&typeAttributeAbstract != 0 && flags&typeAttributeSealed != 0 {
		w.WriteString("static ")
	} else if flags&typeAttributeInterface == 0 && flags&typeAttributeAbstract != 0 {
		w.WriteString("abstract ")
	} else if !e.isValueType(td) && !isEnumTD(td) && flags&typeAttributeSealed != 0 {
		w.WriteString("sealed ")
	}
	switch {
	case flags&typeAttributeInterface != 0:
		w.WriteString("interface ")
	case isEnumTD(td):
		w.WriteString("enum ")
	case e.isValueType(td):
		w.WriteString("struct ")
	default:
		w.WriteString("class ")
	}
	// The reference dumper emits the metadata name verbatim for type
	// declarations (backtick arity kept, no declaring-type prefix).
	// Nested / generic references elsewhere still use full type names.
	w.WriteString(m.GetStringFromIndex(td.u32("nameIndex")))
	if len(extends) > 0 {
		w.WriteString(" : " + strings.Join(extends, ", "))
	}
	if opts.DumpTypeDefIndex {
		fmt.Fprintf(w, " // TypeDefIndex: %d\n{\n", typeDefIndex)
	} else {
		w.WriteString("\n{\n")
	}

	firstSection := true
	if opts.DumpFields && td.u16("field_count") > 0 {
		e.dumpFields(w, imageIndex, typeDefIndex, td, opts)
		firstSection = false
	}
	if opts.DumpProperties && td.u16("property_count") > 0 {
		if !firstSection {
			w.WriteString("\n")
		}
		e.dumpProperties(w, imageIndex, td)
		firstSection = false
	}
	if opts.DumpMethods && td.u16("method_count") > 0 {
		if !firstSection {
			w.WriteString("\n")
		}
		e.dumpMethods(w, imageIndex, imageName, td, opts)
		firstSection = false
	}
	if firstSection {
		w.WriteString("}\n")
	} else {
		w.WriteString("\n}\n")
	}
}

func (e *Executor) dumpFields(w *bufio.Writer, imageIndex int, typeDefIndex int, td record, opts DumpOptions) {
	m := e.Metadata
	fieldCount := int(td.u16("field_count"))
	if fieldCount == 0 {
		return
	}
	w.WriteString("\t// Fields\n")
	fieldStart := int(td.i32("fieldStart"))
	for i := fieldStart; i < fieldStart+fieldCount; i++ {
		fieldDef := m.FieldDef(i)
		fieldType := e.typeAt(int(fieldDef.i32("typeIndex")))
		isStatic := false
		isConst := false
		if opts.DumpAttributes {
			w.WriteString(e.GetCustomAttribute(imageIndex, fieldDef.i32("customAttributeIndex"), fieldDef.u32("token"), "\t"))
		}
		w.WriteString("\t")
		switch fieldType.Attrs & fieldAttributeFieldAccessMask {
		case fieldAttributePrivate:
			w.WriteString("private ")
		case fieldAttributePublic:
			w.WriteString("public ")
		case fieldAttributeFamily:
			w.WriteString("protected ")
		case fieldAttributeAssembly:
			w.WriteString("internal ")
		case fieldAttributeFamAndAssem:
			w.WriteString("private protected ")
		case fieldAttributeFamOrAssem:
			w.WriteString("protected internal ")
		}
		if fieldType.Attrs&fieldAttributeLiteral != 0 {
			isConst = true
			w.WriteString("const ")
		} else {
			if fieldType.Attrs&fieldAttributeStatic != 0 {
				isStatic = true
				w.WriteString("static ")
			}
			if fieldType.Attrs&fieldAttributeInitOnly != 0 {
				w.WriteString("readonly ")
			}
		}
		w.WriteString(e.GetTypeName(fieldType, true, false) + " " + m.GetStringFromIndex(fieldDef.u32("nameIndex")))
		if defaultValue, ok := m.GetFieldDefaultValueFromIndex(int32(i)); ok && defaultValue.i32("dataIndex") != -1 {
			if value, ok := e.TryGetDefaultValue(int(defaultValue.i32("typeIndex")), defaultValue.i32("dataIndex")); ok {
				w.WriteString(" = ")
				w.WriteString(renderDefaultValue(value))
			}
		}
		if opts.DumpFieldOffsets && !isConst {
			if offset := e.IL2CPP.GetFieldOffsetFromIndex(typeDefIndex, i-fieldStart, i, e.isValueType(td), isStatic); offset >= 0 {
				fmt.Fprintf(w, "; // 0x%X\n", offset)
			} else {
				w.WriteString(";\n")
			}
		} else {
			w.WriteString(";\n")
		}
	}
}

func (e *Executor) dumpProperties(w *bufio.Writer, imageIndex int, td record) {
	m := e.Metadata
	propertyCount := int(td.u16("property_count"))
	if propertyCount == 0 {
		return
	}
	w.WriteString("\t// Properties\n")
	propertyStart := int(td.i32("propertyStart"))
	methodStart := int(td.i32("methodStart"))
	for i := propertyStart; i < propertyStart+propertyCount; i++ {
		propertyDef := m.PropertyDef(i)
		w.WriteString(e.GetCustomAttribute(imageIndex, propertyDef.i32("customAttributeIndex"), propertyDef.u32("token"), "\t"))
		w.WriteString("\t")
		if get := propertyDef.i32("get"); get >= 0 {
			methodDef := m.MethodDef(methodStart + int(get))
			w.WriteString(e.getModifiers(methodDef))
			propertyType := e.typeAt(int(methodDef.i32("returnType")))
			fmt.Fprintf(w, "%s %s { ", e.GetTypeName(propertyType, true, false), m.GetStringFromIndex(propertyDef.u32("nameIndex")))
		} else if set := propertyDef.i32("set"); set >= 0 {
			methodDef := m.MethodDef(methodStart + int(set))
			w.WriteString(e.getModifiers(methodDef))
			parameterDef := m.ParameterDef(int(methodDef.i32("parameterStart")))
			propertyType := e.typeAt(int(parameterDef.i32("typeIndex")))
			fmt.Fprintf(w, "%s %s { ", e.GetTypeName(propertyType, true, false), m.GetStringFromIndex(propertyDef.u32("nameIndex")))
		}
		if propertyDef.i32("get") >= 0 {
			w.WriteString("get; ")
		}
		if propertyDef.i32("set") >= 0 {
			w.WriteString("set; ")
		}
		w.WriteString("}\n")
	}
}

func (e *Executor) dumpMethods(w *bufio.Writer, imageIndex int, imageName string, td record, opts DumpOptions) {
	m := e.Metadata
	methodCount := int(td.u16("method_count"))
	if methodCount == 0 {
		return
	}
	w.WriteString("\t// Methods\n")
	methodStart := int(td.i32("methodStart"))
	for i := methodStart; i < methodStart+methodCount; i++ {
		w.WriteString("\n")
		methodDef := m.MethodDef(i)
		isAbstract := methodDef.u16("flags")&methodAttributeAbstract != 0
		if opts.DumpAttributes {
			w.WriteString(e.GetCustomAttribute(imageIndex, methodDef.i32("customAttributeIndex"), methodDef.u32("token"), "\t"))
		}
		methodPointer := e.IL2CPP.GetMethodPointer(imageName, methodDef)
		slot := methodDef.u16("slot")
		fixedPointer := e.IL2CPP.GetRVA(methodPointer)
		fileOff, _ := e.IL2CPP.mapVATR(methodPointer)
		w.WriteString(formatMethodLocation(isAbstract, methodPointer, fixedPointer, fileOff, slot, slot != 0xFFFF))
		w.WriteString("\t")
		w.WriteString(e.getModifiers(methodDef))
		methodReturnType := e.typeAt(int(methodDef.i32("returnType")))
		methodName := m.GetStringFromIndex(methodDef.u32("nameIndex"))
		if methodReturnType.ByRef == 1 {
			w.WriteString("ref ")
		}
		fmt.Fprintf(w, "%s %s(", e.GetTypeName(methodReturnType, true, false), methodName)
		var params []string
		parameterCount := int(methodDef.u16("parameterCount"))
		parameterStart := int(methodDef.i32("parameterStart"))
		for j := 0; j < parameterCount; j++ {
			idx := parameterStart + j
			parameterDef := m.ParameterDef(idx)
			parameterName := m.GetStringFromIndex(parameterDef.u32("nameIndex"))
			parameterType := e.typeAt(int(parameterDef.i32("typeIndex")))
			parameterTypeName := e.GetTypeName(parameterType, true, false)
			var sb strings.Builder
			if parameterType.ByRef == 1 {
				if parameterType.Attrs&paramAttributeOut != 0 && parameterType.Attrs&paramAttributeIn == 0 {
					sb.WriteString("out ")
				} else if parameterType.Attrs&paramAttributeOut == 0 && parameterType.Attrs&paramAttributeIn != 0 {
					sb.WriteString("in ")
				} else {
					sb.WriteString("ref ")
				}
			}
			sb.WriteString(parameterTypeName + " " + parameterName)
			params = append(params, sb.String())
		}
		w.WriteString(strings.Join(params, ", "))
		if isAbstract {
			w.WriteString(");\n")
		} else {
			w.WriteString(") { }\n")
		}
	}
}

// formatMethodLocation builds the tab-indented location comment line
// that precedes every method declaration, mirroring the reference
// dumper's own output exactly: the RVA/Offset/VA fields are ALWAYS
// emitted (shown as -1 when isAbstract or no native pointer was
// resolved - e.g. an ordinary interface method), and a vtable slot,
// when present, is appended to that same line. The else-if chain this
// replaces dropped the RVA line entirely whenever a slot existed,
// leaving interface methods with just "// Slot: N" and making it
// impossible to tell a method with no native body from one whose
// pointer simply couldn't be resolved.
func formatMethodLocation(isAbstract bool, methodPointer, rva, fileOff uint64, slot uint16, haveSlot bool) string {
	var b strings.Builder
	if !isAbstract && methodPointer > 0 {
		fmt.Fprintf(&b, "\t// RVA: 0x%X Offset: 0x%X VA: 0x%X", rva, fileOff, methodPointer)
	} else {
		b.WriteString("\t// RVA: -1 Offset: -1")
	}
	if haveSlot {
		fmt.Fprintf(&b, " Slot: %d", slot)
	}
	b.WriteByte('\n')
	return b.String()
}

func isEnumTD(td record) bool { return (td.u32("bitfield")>>1)&1 == 1 }

// isValueType mirrors the reference dumper: the valuetype bitfield bit,
// or a direct System.ValueType base (System.Enum and the
// __Il2CppFullySharedGeneric* helpers are not flagged in metadata).
func (e *Executor) isValueType(td record) bool {
	if td.u32("bitfield")&1 == 1 {
		return true
	}
	p := td.i32("parentIndex")
	if p < 0 {
		return false
	}
	pt := e.typeAt(int(p))
	if pt.TypeEnum != typeClass && pt.TypeEnum != typeValueType {
		return false
	}
	ptd := e.GetTypeDefinitionFromIl2CppType(pt)
	return e.Metadata.GetStringFromIndex(ptd.u32("nameIndex")) == "ValueType" &&
		e.Metadata.GetStringFromIndex(ptd.u32("namespaceIndex")) == "System"
}

func renderDefaultValue(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case string:
		return "\"" + escapeString(v) + "\""
	case float32:
		return strconv.FormatFloat(float64(v), 'g', 6, 32)
	case float64:
		return strconv.FormatFloat(v, 'g', 6, 64)
	default:
		return fmt.Sprint(v)
	}
}

// escapeString mirrors Il2CppDumper's ToEscapedString.
func escapeString(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case '\'':
			b.WriteString(`\'`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\x00':
			b.WriteString(`\0`)
		case '\a':
			b.WriteString(`\a`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\v':
			b.WriteString(`\v`)
		case '\u0085':
			b.WriteString(`\u0085`)
		case '\u2028':
			b.WriteString(`\u2028`)
		case '\u2029':
			b.WriteString(`\u2029`)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// getModifiers renders C# method modifiers.
func (e *Executor) getModifiers(methodDef record) string {
	var sb strings.Builder
	switch methodDef.u16("flags") & methodAttributeMemberAccessMask {
	case methodAttributePrivate:
		sb.WriteString("private ")
	case methodAttributePublic:
		sb.WriteString("public ")
	case methodAttributeFamily:
		sb.WriteString("protected ")
	case methodAttributeAssem:
		sb.WriteString("internal ")
	case methodAttributeFamOrAssem:
		sb.WriteString("protected internal ")
	}
	if methodDef.u16("flags")&methodAttributeStatic != 0 {
		sb.WriteString("static ")
	}
	if methodDef.u16("flags")&methodAttributeAbstract != 0 {
		sb.WriteString("abstract ")
		if methodDef.u16("flags")&methodAttributeVtableLayoutMask == methodAttributeReuseSlot {
			sb.WriteString("override ")
		}
	} else if methodDef.u16("flags")&methodAttributeFinal != 0 {
		if methodDef.u16("flags")&methodAttributeVtableLayoutMask == methodAttributeReuseSlot {
			sb.WriteString("sealed override ")
		}
	} else if methodDef.u16("flags")&methodAttributeVirtual != 0 {
		if methodDef.u16("flags")&methodAttributeVtableLayoutMask == methodAttributeNewSlot {
			sb.WriteString("virtual ")
		} else {
			sb.WriteString("override ")
		}
	}
	return sb.String()
}

// GetCustomAttribute renders every custom attribute attached to an
// entity, one per line.
func (e *Executor) GetCustomAttribute(imageIndex int, customAttributeIndex int32, token uint32, padding string) string {
	m := e.Metadata
	if m.Version < 21 {
		return ""
	}
	attributeIndex := m.GetCustomAttributeIndex(imageIndex, customAttributeIndex, token)
	if attributeIndex < 0 {
		return ""
	}
	var sb strings.Builder
	if m.Version < 29 {
		if attributeIndex >= len(e.customAttributeGenerators) || attributeIndex >= len(m.attributeTypeRanges) {
			return ""
		}
		methodPointer := e.customAttributeGenerators[attributeIndex]
		fixedPointer := e.IL2CPP.GetRVA(methodPointer)
		fileOff, _ := e.IL2CPP.mapVATR(methodPointer)
		rangeRec := m.attributeTypeRanges[attributeIndex]
		count := int(rangeRec.i32("count"))
		start := int(rangeRec.i32("start"))
		for i := 0; i < count; i++ {
			idx := start + i
			if idx < 0 || idx >= len(m.attributeTypes) {
				break
			}
			t := e.typeAt(int(m.attributeTypes[idx]))
			fmt.Fprintf(&sb, "%s[%s] // RVA: 0x%X Offset: 0x%X VA: 0x%X\n",
				padding, e.GetTypeName(t, false, false), fixedPointer, fileOff, methodPointer)
		}
		return sb.String()
	}
	if attributeIndex >= len(m.attributeDataRanges) {
		return ""
	}
	startRange := m.attributeDataRanges[attributeIndex]
	endOffset := uint32(0)
	if attributeIndex+1 < len(m.attributeDataRanges) {
		endOffset = m.attributeDataRanges[attributeIndex+1].u32("startOffset")
	}
	base := m.Header.u32("attributeDataOffset")
	start := base + startRange.u32("startOffset")
	end := base + endOffset
	if int(end) > len(m.Data) || start > end {
		return ""
	}
	reader := e.newAttributeReader(m.Data[start:end])
	if reader == nil || reader.Count() == 0 {
		return ""
	}
	// A malformed entry invalidates the whole entity's attribute list,
	// matching the reference dumper (which aborts on the first bad ctor
	// and emits nothing for that entity).
	lines := make([]string, 0, reader.Count())
	for i := uint32(0); i < reader.Count(); i++ {
		s := reader.safeGetString()
		if s == "" {
			break
		}
		lines = append(lines, s)
	}
	for _, s := range lines {
		sb.WriteString(padding)
		sb.WriteString(s)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// newAttributeReader builds a reader for a possibly malformed attribute
// blob; bad ranges are treated as "no attributes" instead of aborting
// the enclosing type.
func (e *Executor) newAttributeReader(buff []byte) (r *customAttributeDataReader) {
	defer func() {
		if recover() != nil {
			r = nil
		}
	}()
	return newCustomAttributeDataReader(e, buff, e.includeAttrArgs)
}
