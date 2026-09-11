package dex

import (
	"archive/zip"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/destruct/destruct/internal/ir"
)

// classFromDef builds an IR class from a DEX class definition.
func classFromDef(dex *DexFile, classDef ClassDef) *ir.Class {
	className := dex.GetClassName(classDef.ClassIdx)
	if className == "" {
		return nil
	}

	name := JavaClassName(className)
	pkg := ""
	parts := strings.Split(name, ".")
	if len(parts) > 1 {
		pkg = strings.Join(parts[:len(parts)-1], ".")
		name = parts[len(parts)-1]
	}

	super := JavaClassName(dex.GetTypeDesc(classDef.SuperclassIdx))
	if super == "java.lang.Object" {
		super = ""
	}

	class := &ir.Class{
		Name:       name,
		Package:    pkg,
		Access:     convertClassAccessFlags(classDef.AccessFlags),
		SuperClass: super,
	}

	for _, iface := range dex.GetInterfaces(classDef) {
		class.Interfaces = append(class.Interfaces, JavaClassName(dex.GetTypeDesc(iface)))
	}

	classData := dex.GetClassData(classDef)
	if classData == nil {
		return class
	}

	for _, field := range classData.StaticFields {
		if f := dex.convertField(field); f != nil {
			class.Fields = append(class.Fields, f)
		}
	}
	for _, field := range classData.InstanceFields {
		if f := dex.convertField(field); f != nil {
			class.Fields = append(class.Fields, f)
		}
	}
	for _, method := range classData.DirectMethods {
		if m := dex.convertMethod(method); m != nil {
			class.Methods = append(class.Methods, m)
		}
	}
	for _, method := range classData.VirtualMethods {
		if m := dex.convertMethod(method); m != nil {
			class.Methods = append(class.Methods, m)
		}
	}

	return class
}

func (dex *DexFile) convertField(field Field) *ir.Field {
	fid := dex.GetFieldId(field.FieldIdx)
	if fid == nil {
		return nil
	}
	return &ir.Field{
		Name:   dex.GetString(fid.NameIdx),
		Type:   TypeFromDesc(dex.GetTypeDesc(uint32(fid.TypeIdx))),
		Access: convertFieldAccessFlags(field.AccessFlags),
	}
}

func (dex *DexFile) convertMethod(method Method) *ir.Method {
	methodID := dex.GetMethodId(method.MethodIdx)
	if methodID == nil {
		return nil
	}

	proto := dex.GetProto(uint32(methodID.ProtoIdx))
	if proto == nil {
		return nil
	}

	var params []*ir.Param
	for i, typeIdx := range dex.GetParameters(*proto) {
		params = append(params, &ir.Param{
			Name: fmt.Sprintf("p%d", i),
			Type: TypeFromDesc(dex.GetTypeDesc(typeIdx)),
		})
	}

	var body *ir.Block
	if method.CodeOff != 0 {
		codeItem := dex.GetCodeItem(method.CodeOff)
		if codeItem != nil {
			converter := NewDalvikToIR(dex, &method, codeItem)
			body = converter.Convert()
		}
	}

	name := dex.GetString(methodID.NameIdx)
	if name == "<init>" && body != nil {
		moveConstructorCallFirst(body)
	}

	return &ir.Method{
		Name:       name,
		Access:     convertMethodAccessFlags(method.AccessFlags),
		Params:     params,
		ReturnType: TypeFromDesc(dex.GetTypeDesc(proto.ReturnTypeIdx)),
		Body:       body,
	}
}

// moveConstructorCallFirst hoists a constructor's super(...)/this(...)
// call to the top of its body. Dalvik allows field stores and argument
// setup before the superclass constructor call, but Java source requires
// it first; argument registers whose most recent assignment is available
// are folded into the call so hoisting doesn't change evaluation order.
func moveConstructorCallFirst(body *ir.Block) {
	var call ir.Stmt
	callIdx := -1
	for i, stmt := range body.Statements {
		switch stmt.(type) {
		case *ir.SuperCallStmt, *ir.ThisCallStmt:
			call, callIdx = stmt, i
		}
		if call != nil {
			break
		}
	}
	if call == nil || callIdx == 0 {
		return
	}

	var args []ir.Expr
	switch c := call.(type) {
	case *ir.SuperCallStmt:
		args = c.Args
	case *ir.ThisCallStmt:
		args = c.Args
	}
	for i, arg := range args {
		lv, ok := arg.(*ir.LocalVar)
		if !ok {
			continue
		}
		for j := callIdx - 1; j >= 0; j-- {
			as, ok := body.Statements[j].(*ir.AssignStmt)
			if !ok {
				continue
			}
			if tlv, ok := as.Target.(*ir.LocalVar); ok && tlv == lv {
				args[i] = as.Value
				break
			}
		}
	}

	copy(body.Statements[1:callIdx+1], body.Statements[0:callIdx])
	body.Statements[0] = call
}

func convertClassAccessFlags(flags uint32) ir.AccessFlags {
	var access ir.AccessFlags
	if flags&ACC_PUBLIC != 0 {
		access |= ir.AccPublic
	}
	if flags&ACC_FINAL != 0 {
		access |= ir.AccFinal
	}
	if flags&ACC_INTERFACE != 0 {
		access |= ir.AccInterface
	}
	if flags&ACC_ABSTRACT != 0 {
		access |= ir.AccAbstract
	}
	if flags&ACC_SYNTHETIC != 0 {
		access |= ir.AccSynthetic
	}
	if flags&ACC_ANNOTATION != 0 {
		access |= ir.AccAnnotation
	}
	if flags&ACC_ENUM != 0 {
		access |= ir.AccEnum
	}
	return access
}

func convertMethodAccessFlags(flags uint32) ir.AccessFlags {
	var access ir.AccessFlags
	if flags&ACC_PUBLIC != 0 {
		access |= ir.AccPublic
	}
	if flags&ACC_PRIVATE != 0 {
		access |= ir.AccPrivate
	}
	if flags&ACC_PROTECTED != 0 {
		access |= ir.AccProtected
	}
	if flags&ACC_STATIC != 0 {
		access |= ir.AccStatic
	}
	if flags&ACC_FINAL != 0 {
		access |= ir.AccFinal
	}
	if flags&ACC_SYNCHRONIZED != 0 {
		access |= ir.AccSynchronized
	}
	if flags&ACC_BRIDGE != 0 {
		access |= ir.AccBridge
	}
	if flags&ACC_VARARGS != 0 {
		access |= ir.AccVarargs
	}
	if flags&ACC_NATIVE != 0 {
		access |= ir.AccNative
	}
	if flags&ACC_ABSTRACT != 0 {
		access |= ir.AccAbstract
	}
	if flags&ACC_STRICT != 0 {
		access |= ir.AccStrict
	}
	if flags&ACC_SYNTHETIC != 0 {
		access |= ir.AccSynthetic
	}
	return access
}

func convertFieldAccessFlags(flags uint32) ir.AccessFlags {
	var access ir.AccessFlags
	if flags&ACC_PUBLIC != 0 {
		access |= ir.AccPublic
	}
	if flags&ACC_PRIVATE != 0 {
		access |= ir.AccPrivate
	}
	if flags&ACC_PROTECTED != 0 {
		access |= ir.AccProtected
	}
	if flags&ACC_STATIC != 0 {
		access |= ir.AccStatic
	}
	if flags&ACC_FINAL != 0 {
		access |= ir.AccFinal
	}
	// ACC_VOLATILE and ACC_TRANSIENT share bits with ACC_BRIDGE/ACC_VARARGS,
	// which are method-only flags.
	if flags&0x0040 != 0 {
		access |= ir.AccVolatile
	}
	if flags&0x0080 != 0 {
		access |= ir.AccTransient
	}
	if flags&ACC_SYNTHETIC != 0 {
		access |= ir.AccSynthetic
	}
	if flags&ACC_ENUM != 0 {
		access |= ir.AccEnum
	}
	return access
}

// DecompileDexBytes decompiles DEX bytes to IR.
func DecompileDexBytes(data []byte) (*ir.Program, error) {
	dex, err := ParseDexBytes(data)
	if err != nil {
		return nil, fmt.Errorf("parsing dex bytes: %w", err)
	}
	return dexToProgram(dex), nil
}

// DecompileDexFile decompiles a single DEX file to IR.
func DecompileDexFile(path string) (*ir.Program, error) {
	dex, err := ParseDexFile(path)
	if err != nil {
		return nil, fmt.Errorf("parsing dex file: %w", err)
	}
	return dexToProgram(dex), nil
}

func dexToProgram(dex *DexFile) *ir.Program {
	prog := &ir.Program{}
	for _, classDef := range dex.Classes {
		if class := classFromDef(dex, classDef); class != nil {
			prog.Classes = append(prog.Classes, class)
		}
	}
	return prog
}

// DecompileDexStreaming processes a DEX file with a callback for each class.
func DecompileDexStreaming(path string, onClass func(*ir.Class), onSkip func(string, error)) error {
	dex, err := ParseDexFile(path)
	if err != nil {
		return fmt.Errorf("parsing dex file: %w", err)
	}

	for _, classDef := range dex.Classes {
		class := classFromDef(dex, classDef)
		if class == nil {
			continue
		}
		onClass(class)
	}

	return nil
}

// DecompileApkStreaming processes every classes*.dex in an APK, invoking
// onClass once per class. Duplicate class names (multidex overrides) are
// skipped after the first occurrence.
func DecompileApkStreaming(path string, onClass func(*ir.Class), onSkip func(string, error)) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("opening apk: %w", err)
	}
	defer r.Close()

	seen := make(map[string]bool)
	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, ".dex") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			if onSkip != nil {
				onSkip(f.Name, err)
			}
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			if onSkip != nil {
				onSkip(f.Name, err)
			}
			continue
		}
		dex, err := ParseDexBytes(data)
		if err != nil {
			if onSkip != nil {
				onSkip(f.Name, err)
			}
			continue
		}
		for _, classDef := range dex.Classes {
			class := classFromDef(dex, classDef)
			if class == nil {
				continue
			}
			full := class.Package + "." + class.Name
			if seen[full] {
				continue
			}
			seen[full] = true
			onClass(class)
		}
	}

	return nil
}

// CountDexClasses counts the number of classes in a DEX file.
func CountDexClasses(path string) (int, error) {
	dex, err := ParseDexFile(path)
	if err != nil {
		return 0, err
	}
	return len(dex.Classes), nil
}

// CountApkDexClasses counts the total number of classes across all DEX files
// in an APK.
func CountApkDexClasses(path string) (int, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return 0, fmt.Errorf("opening apk: %w", err)
	}
	defer r.Close()

	total := 0
	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, ".dex") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		dex, err := ParseDexBytes(data)
		if err != nil {
			continue
		}
		total += len(dex.Classes)
	}

	return total, nil
}

// DecompileDexFiles decompiles multiple DEX/APK files.
func DecompileDexFiles(paths []string) (*ir.Program, error) {
	prog := &ir.Program{}

	for _, path := range paths {
		ext := strings.ToLower(filepath.Ext(path))
		var sub *ir.Program
		var err error
		switch ext {
		case ".dex":
			sub, err = DecompileDexFile(path)
		case ".apk":
			err = DecompileApkStreaming(path, func(c *ir.Class) {
				prog.Classes = append(prog.Classes, c)
			}, nil)
			if err != nil {
				return nil, fmt.Errorf("decompiling %s: %w", path, err)
			}
			continue
		default:
			return nil, fmt.Errorf("unsupported file type: %s", ext)
		}
		if err != nil {
			return nil, fmt.Errorf("decompiling %s: %w", path, err)
		}
		prog.Classes = append(prog.Classes, sub.Classes...)
	}

	return prog, nil
}
