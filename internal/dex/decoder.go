package dex

import (
	"fmt"
	"strings"

	"github.com/destruct/destruct/internal/ir"
)

// DalvikToIR converts a Dalvik method body to the shared IR.
type DalvikToIR struct {
	dex      *DexFile
	method   *Method
	methodID *MethodId
	proto    *ProtoId
	codeItem *CodeItem

	classDesc string // descriptor of the declaring class, e.g. Lcom/x/Foo;
	className string // java name of the declaring class, e.g. com.x.Foo

	insns         []Instruction
	blocks        []*basicBlock
	loops         map[int]*loopInfo
	dom           [][]bool
	offsetToBlock map[int]int
	reachable     []bool

	locals     map[int]*ir.LocalVar
	paramNames map[int]string
	objRegs    map[int]bool
	regTypes   map[int]string // register -> type descriptor
	thisReg    int
	isStatic   bool
	isCtor     bool

	pending     ir.Expr
	pendingDesc string

	// switchStack guards against re-entering the same switch while
	// structuring its own case bodies.
	switchStack map[int]bool
}

// NewDalvikToIR creates a new Dalvik to IR converter.
func NewDalvikToIR(dex *DexFile, method *Method, codeItem *CodeItem) *DalvikToIR {
	d := &DalvikToIR{
		dex:         dex,
		method:      method,
		codeItem:    codeItem,
		locals:      make(map[int]*ir.LocalVar),
		paramNames:  make(map[int]string),
		objRegs:     make(map[int]bool),
		regTypes:    make(map[int]string),
		thisReg:     -1,
		switchStack: make(map[int]bool),
	}
	d.methodID = dex.GetMethodId(method.MethodIdx)
	d.isStatic = method.AccessFlags&ACC_STATIC != 0
	if d.methodID != nil {
		d.proto = dex.GetProto(uint32(d.methodID.ProtoIdx))
		d.classDesc = dex.GetTypeDesc(uint32(d.methodID.ClassIdx))
		d.className = JavaClassName(d.classDesc)
	}
	d.isCtor = d.name() == "<init>"
	d.initRegisters()
	return d
}

func (d *DalvikToIR) name() string {
	if d.methodID == nil {
		return ""
	}
	return d.dex.GetString(d.methodID.NameIdx)
}

// JavaClassName converts a DEX type descriptor to a dotted Java class name.
// Non-class descriptors are returned unchanged.
func JavaClassName(desc string) string {
	if strings.HasPrefix(desc, "L") && strings.HasSuffix(desc, ";") {
		return strings.ReplaceAll(desc[1:len(desc)-1], "/", ".")
	}
	return strings.ReplaceAll(desc, "/", ".")
}

// TypeFromDesc converts a DEX type descriptor to an IR type.
func TypeFromDesc(desc string) ir.Type {
	desc = strings.TrimSpace(desc)
	if desc == "" {
		return &ir.PrimitiveType{Name: "void"}
	}

	switch desc[0] {
	case 'V':
		return &ir.PrimitiveType{Name: "void"}
	case 'Z':
		return &ir.PrimitiveType{Name: "boolean"}
	case 'B':
		return &ir.PrimitiveType{Name: "byte"}
	case 'C':
		return &ir.PrimitiveType{Name: "char"}
	case 'S':
		return &ir.PrimitiveType{Name: "short"}
	case 'I':
		return &ir.PrimitiveType{Name: "int"}
	case 'J':
		return &ir.PrimitiveType{Name: "long"}
	case 'F':
		return &ir.PrimitiveType{Name: "float"}
	case 'D':
		return &ir.PrimitiveType{Name: "double"}
	case 'L':
		return &ir.ClassType{Name: JavaClassName(desc)}
	case '[':
		return &ir.ArrayType{Elem: TypeFromDesc(desc[1:])}
	default:
		return &ir.ClassType{Name: desc}
	}
}

// TypeDescWidth returns how many registers a value of this type occupies.
func TypeDescWidth(desc string) int {
	if len(desc) > 0 && (desc[0] == 'J' || desc[0] == 'D') {
		return 2
	}
	return 1
}

// IsRefDesc reports whether a type descriptor is an object/array type.
func IsRefDesc(desc string) bool {
	return len(desc) > 0 && (desc[0] == 'L' || desc[0] == '[')
}

// initRegisters maps incoming argument registers (vN where N >= registers-ins)
// to names. Instance methods get "this" in the first incoming register.
func (d *DalvikToIR) initRegisters() {
	if d.codeItem == nil {
		return
	}
	regsSize := int(d.codeItem.RegistersSize)
	insSize := int(d.codeItem.InsSize)
	if insSize > regsSize {
		insSize = regsSize
	}
	start := regsSize - insSize
	reg := start

	if !d.isStatic {
		d.thisReg = reg
		d.locals[reg] = &ir.LocalVar{Name: "this"}
		d.setRegType(reg, d.classDesc)
		reg++
	}

	if d.proto != nil {
		params := d.dex.GetParameters(*d.proto)
		for i, typeIdx := range params {
			desc := d.dex.GetTypeDesc(typeIdx)
			name := fmt.Sprintf("p%d", i)
			if reg < regsSize {
				d.paramNames[reg] = name
				d.locals[reg] = &ir.LocalVar{Name: name}
				d.setRegType(reg, desc)
			}
			reg += TypeDescWidth(desc)
		}
	}
}

// Convert converts the method body to an IR block.
func (d *DalvikToIR) Convert() *ir.Block {
	if d.codeItem == nil {
		return nil
	}

	code := d.dex.GetInstructions(d.codeItem)
	if d.codeItem != nil && d.codeItem.RegistersSize > 0 {
		d.insns, _ = decodeInstructionsFor(code, int(d.codeItem.RegistersSize))
	} else {
		d.insns = DecodeInstructions(code)
	}
	if len(d.insns) == 0 {
		return &ir.Block{}
	}

	d.buildBlocks()
	d.computeDominators()
	d.findLoops()
	d.computeReachable()

	block := d.structureRange(0, len(d.blocks), nil)
	if block == nil {
		return &ir.Block{}
	}
	return block
}

// convertBlock converts a straight-line instruction sequence into statements,
// resolving invoke/move-result pairing and new-instance/constructor fusion.
func (d *DalvikToIR) convertBlock(insts []Instruction) []ir.Stmt {
	var out []ir.Stmt
	d.pending = nil

	flushPending := func() {
		if d.pending != nil {
			out = append(out, &ir.ExprStmt{Expr: d.pending})
			d.pending = nil
		}
	}

	for i := range insts {
		inst := &insts[i]

		if isMoveResult(inst.Op) {
			if d.pending != nil {
				out = append(out, &ir.AssignStmt{Target: d.getRegister(inst.A), Value: d.pending})
				desc := d.pendingDesc
				if inst.Op == OP_MOVE_RESULT_OBJECT && !IsRefDesc(desc) {
					desc = "Ljava/lang/Object;"
				}
				d.setRegType(inst.A, desc)
				d.pending = nil
				d.pendingDesc = ""
			} else {
				out = append(out, &ir.AssignStmt{Target: d.getRegister(inst.A), Value: &ir.NullLit{}})
				d.setRegType(inst.A, "Ljava/lang/Object;")
			}
			continue
		}

		flushPending()

		if isInvoke(inst.Op) {
			d.convertInvoke(inst, &out)
			continue
		}

		stmts := d.convertInstruction(inst)
		if stmts == nil {
			continue
		}
		d.trackTypes(inst)
		out = append(out, stmts...)
	}

	flushPending()
	return out
}

// setRegType records the descriptor of the value currently held in a
// register, keeping the object/primitive bit in sync.
func (d *DalvikToIR) setRegType(reg int, desc string) {
	if desc == "" {
		delete(d.regTypes, reg)
		delete(d.objRegs, reg)
		return
	}
	d.regTypes[reg] = desc
	if IsRefDesc(desc) {
		d.objRegs[reg] = true
	} else {
		delete(d.objRegs, reg)
	}
}

// trackTypes updates register type information after an instruction that
// writes a register.
func (d *DalvikToIR) trackTypes(inst *Instruction) {
	switch inst.Op {
	case OP_CONST_4, OP_CONST_16, OP_CONST, OP_CONST_HIGH_16,
		OP_ADD_INT, OP_SUB_INT, OP_MUL_INT, OP_DIV_INT, OP_REM_INT,
		OP_AND_INT, OP_OR_INT, OP_XOR_INT, OP_SHL_INT, OP_SHR_INT, OP_USHR_INT,
		OP_ADD_INT_2ADDR, OP_SUB_INT_2ADDR, OP_MUL_INT_2ADDR, OP_DIV_INT_2ADDR,
		OP_REM_INT_2ADDR, OP_AND_INT_2ADDR, OP_OR_INT_2ADDR, OP_XOR_INT_2ADDR,
		OP_SHL_INT_2ADDR, OP_SHR_INT_2ADDR, OP_USHR_INT_2ADDR,
		OP_ADD_INT_LIT8, OP_RSUB_INT_LIT8, OP_MUL_INT_LIT8, OP_DIV_INT_LIT8,
		OP_REM_INT_LIT8, OP_AND_INT_LIT8, OP_OR_INT_LIT8, OP_XOR_INT_LIT8,
		OP_SHL_INT_LIT8, OP_SHR_INT_LIT8, OP_USHR_INT_LIT8,
		OP_ADD_INT_LIT16, OP_RSUB_INT, OP_MUL_INT_LIT16, OP_DIV_INT_LIT16,
		OP_REM_INT_LIT16, OP_AND_INT_LIT16, OP_OR_INT_LIT16, OP_XOR_INT_LIT16,
		OP_ARRAY_LENGTH, OP_CMPL_FLOAT, OP_CMPG_FLOAT, OP_CMPL_DOUBLE,
		OP_CMPG_DOUBLE, OP_CMP_LONG:
		d.setRegType(inst.A, "I")

	case OP_CONST_WIDE_16, OP_CONST_WIDE_32, OP_CONST_WIDE, OP_CONST_WIDE_HIGH_16,
		OP_ADD_LONG, OP_SUB_LONG, OP_MUL_LONG, OP_DIV_LONG, OP_REM_LONG,
		OP_AND_LONG, OP_OR_LONG, OP_XOR_LONG, OP_SHL_LONG, OP_SHR_LONG, OP_USHR_LONG,
		OP_ADD_LONG_2ADDR, OP_SUB_LONG_2ADDR, OP_MUL_LONG_2ADDR, OP_DIV_LONG_2ADDR,
		OP_REM_LONG_2ADDR, OP_AND_LONG_2ADDR, OP_OR_LONG_2ADDR, OP_XOR_LONG_2ADDR,
		OP_SHL_LONG_2ADDR, OP_SHR_LONG_2ADDR, OP_USHR_LONG_2ADDR:
		d.setRegType(inst.A, "J")

	case OP_ADD_FLOAT, OP_SUB_FLOAT, OP_MUL_FLOAT, OP_DIV_FLOAT, OP_REM_FLOAT,
		OP_ADD_FLOAT_2ADDR, OP_SUB_FLOAT_2ADDR, OP_MUL_FLOAT_2ADDR,
		OP_DIV_FLOAT_2ADDR, OP_REM_FLOAT_2ADDR:
		d.setRegType(inst.A, "F")

	case OP_ADD_DOUBLE, OP_SUB_DOUBLE, OP_MUL_DOUBLE, OP_DIV_DOUBLE, OP_REM_DOUBLE,
		OP_ADD_DOUBLE_2ADDR, OP_SUB_DOUBLE_2ADDR, OP_MUL_DOUBLE_2ADDR,
		OP_DIV_DOUBLE_2ADDR, OP_REM_DOUBLE_2ADDR:
		d.setRegType(inst.A, "D")

	case OP_CONST_STRING, OP_CONST_STRING_JUMBO:
		d.setRegType(inst.A, "Ljava/lang/String;")
	case OP_CONST_CLASS:
		d.setRegType(inst.A, "Ljava/lang/Class;")
	case OP_CHECK_CAST:
		d.setRegType(inst.A, d.dex.GetTypeDesc(inst.Ref))
	case OP_INSTANCE_OF:
		d.setRegType(inst.A, "Z")
	case OP_NEW_INSTANCE:
		d.setRegType(inst.A, d.dex.GetTypeDesc(inst.Ref))
	case OP_NEW_ARRAY:
		d.setRegType(inst.A, d.dex.GetTypeDesc(inst.Ref))

	case OP_IGET, OP_IGET_WIDE, OP_IGET_OBJECT, OP_IGET_BOOLEAN,
		OP_IGET_BYTE, OP_IGET_CHAR, OP_IGET_SHORT,
		OP_SGET, OP_SGET_WIDE, OP_SGET_OBJECT, OP_SGET_BOOLEAN,
		OP_SGET_BYTE, OP_SGET_CHAR, OP_SGET_SHORT:
		if fid := d.dex.GetFieldId(inst.Ref); fid != nil {
			d.setRegType(inst.A, d.dex.GetTypeDesc(uint32(fid.TypeIdx)))
		}

	case OP_AGET:
		d.setRegType(inst.A, "I")
	case OP_AGET_WIDE:
		d.setRegType(inst.A, "J")
	case OP_AGET_OBJECT:
		d.setRegType(inst.A, "Ljava/lang/Object;")
	case OP_AGET_BOOLEAN:
		d.setRegType(inst.A, "Z")
	case OP_AGET_BYTE:
		d.setRegType(inst.A, "B")
	case OP_AGET_CHAR:
		d.setRegType(inst.A, "C")
	case OP_AGET_SHORT:
		d.setRegType(inst.A, "S")

	case OP_MOVE, OP_MOVE_FROM16, OP_MOVE_16,
		OP_MOVE_WIDE, OP_MOVE_WIDE_FROM16, OP_MOVE_WIDE_16,
		OP_MOVE_OBJECT, OP_MOVE_OBJECT_FROM16, OP_MOVE_OBJECT_16:
		d.setRegType(inst.A, d.regTypes[inst.B])

	case OP_INT_TO_LONG, OP_LONG_TO_INT, OP_FLOAT_TO_INT, OP_DOUBLE_TO_INT,
		OP_INT_TO_FLOAT, OP_LONG_TO_FLOAT, OP_DOUBLE_TO_FLOAT,
		OP_INT_TO_DOUBLE, OP_LONG_TO_DOUBLE, OP_FLOAT_TO_DOUBLE,
		OP_INT_TO_BYTE, OP_INT_TO_CHAR, OP_INT_TO_SHORT,
		OP_NEG_INT, OP_NOT_INT, OP_NEG_LONG, OP_NOT_LONG,
		OP_NEG_FLOAT, OP_NEG_DOUBLE:
		d.setRegType(inst.A, conversionDesc(inst.Op))
		if inst.Op == OP_NEG_INT || inst.Op == OP_NOT_INT ||
			inst.Op == OP_NEG_LONG || inst.Op == OP_NOT_LONG ||
			inst.Op == OP_NEG_FLOAT || inst.Op == OP_NEG_DOUBLE {
			d.setRegType(inst.A, d.regTypes[inst.B])
		}
	}
}

func isMoveResult(op byte) bool {
	switch op {
	case OP_MOVE_RESULT, OP_MOVE_RESULT_WIDE, OP_MOVE_RESULT_OBJECT:
		return true
	}
	return false
}

func isObjectValue(e ir.Expr) bool {
	switch e.(type) {
	case *ir.NewExpr, *ir.NewArrayExpr, *ir.ArrayInitExpr, *ir.StringLit,
		*ir.ClassLiteral, *ir.NullLit:
		return true
	}
	return false
}

func isInvoke(op byte) bool {
	return (op >= OP_INVOKE_VIRTUAL && op <= OP_INVOKE_INTERFACE) ||
		(op >= OP_INVOKE_VIRTUAL_RANGE && op <= OP_INVOKE_INTERFACE_RANGE) ||
		op == OP_INVOKE_POLYMORPHIC || op == OP_INVOKE_POLYMORPHIC_RANGE
}

func isStaticInvokeOp(op byte) bool {
	return op == OP_INVOKE_STATIC || op == OP_INVOKE_STATIC_RANGE
}

// getRegister returns the IR variable for a Dalvik register.
func (d *DalvikToIR) getRegister(reg int) ir.Expr {
	if v, ok := d.locals[reg]; ok {
		return v
	}
	v := &ir.LocalVar{Name: fmt.Sprintf("v%d", reg)}
	d.locals[reg] = v
	return v
}

// convertInvoke converts an invoke-* instruction, appending to the current
// statement list. Non-void invokes are stored as the pending expression and
// materialized by the following move-result.
func (d *DalvikToIR) convertInvoke(inst *Instruction, out *[]ir.Stmt) {
	mid := d.dex.GetMethodId(inst.Ref)
	if mid == nil {
		return
	}
	name := d.dex.GetString(mid.NameIdx)
	class := JavaClassName(d.dex.GetTypeDesc(uint32(mid.ClassIdx)))
	proto := d.dex.GetProto(uint32(mid.ProtoIdx))
	if (inst.Op == OP_INVOKE_POLYMORPHIC || inst.Op == OP_INVOKE_POLYMORPHIC_RANGE) && inst.Ref2 != 0 {
		proto = d.dex.GetProto(inst.Ref2)
	}

	objectReg := -1
	if !isStaticInvokeOp(inst.Op) && len(inst.Regs) > 0 {
		objectReg = inst.Regs[0]
	}
	args := d.invokeArgs(proto, inst.Regs, isStaticInvokeOp(inst.Op))
	args = d.coerceRefArgs(args, proto, *out)

	// Constructor calls.
	if name == "<init>" {
		if objectReg == d.thisReg && d.thisReg >= 0 {
			if class == d.className {
				*out = append(*out, &ir.ThisCallStmt{Args: args})
			} else {
				*out = append(*out, &ir.SuperCallStmt{Args: args})
			}
			return
		}
		// new-instance + invoke-direct <init> fusion: find the preceding
		// "vX = new Type()" and turn it into "vX = new Type(args)",
		// removing the stale no-arg assignment. The fused assignment is
		// appended at the invoke position so any argument setup
		// statements in between stay evaluated first.
		obj := d.getRegister(objectReg)
		for i := len(*out) - 1; i >= 0; i-- {
			as, ok := (*out)[i].(*ir.AssignStmt)
			if !ok {
				continue
			}
			lv, ok := as.Target.(*ir.LocalVar)
			if !ok || lv != obj {
				continue
			}
			if _, ok := as.Value.(*ir.NewExpr); ok {
				*out = append((*out)[:i], (*out)[i+1:]...)
				*out = append(*out, &ir.AssignStmt{
					Target: obj,
					Value:  &ir.NewExpr{Type: class, Args: args},
				})
				d.objRegs[objectReg] = true
				return
			}
			break
		}
		// Fallback: no recognizable new-instance.
		*out = append(*out, &ir.AssignStmt{
			Target: obj,
			Value:  &ir.NewExpr{Type: class, Args: args},
		})
		d.objRegs[objectReg] = true
		return
	}

	if name == "<clinit>" {
		return
	}

	var call ir.Expr
	if isStaticInvokeOp(inst.Op) {
		call = &ir.StaticMethodCall{Class: class, Method: name, Args: args}
	} else if inst.Op == OP_INVOKE_SUPER || inst.Op == OP_INVOKE_SUPER_RANGE {
		call = &ir.MethodCall{Object: &ir.SuperExpr{}, Name: name, Args: args}
	} else {
		var obj ir.Expr
		if objectReg >= 0 {
			obj = d.getRegister(objectReg)
		}
		call = &ir.MethodCall{Object: obj, Name: name, Args: args}
	}

	returnDesc := ""
	if proto != nil {
		returnDesc = d.dex.GetTypeDesc(proto.ReturnTypeIdx)
	}
	if returnDesc == "V" || returnDesc == "" {
		*out = append(*out, &ir.ExprStmt{Expr: call})
		return
	}
	d.pending = call
	d.pendingDesc = returnDesc
}

// invokeArgs maps an invoke's raw register list to argument expressions,
// honoring wide (long/double) parameters that occupy two registers.
func (d *DalvikToIR) invokeArgs(proto *ProtoId, regs []int, static bool) []ir.Expr {
	var params []uint32
	if proto != nil {
		params = d.dex.GetParameters(*proto)
	}

	args := make([]ir.Expr, 0, len(params))
	idx := 0
	if !static && len(regs) > 0 {
		idx = 1 // skip receiver
	}
	for _, typeIdx := range params {
		if idx >= len(regs) {
			break
		}
		desc := d.dex.GetTypeDesc(typeIdx)
		args = append(args, d.getRegister(regs[idx]))
		idx += TypeDescWidth(desc)
	}
	return args
}

// coerceRefArgs renders a register holding a zero constant as null when it
// is passed for an object parameter, which is how Dalvik encodes null.
func (d *DalvikToIR) coerceRefArgs(args []ir.Expr, proto *ProtoId, out []ir.Stmt) []ir.Expr {
	if proto == nil {
		return args
	}
	params := d.dex.GetParameters(*proto)
	for i := range args {
		if i >= len(params) || !IsRefDesc(d.dex.GetTypeDesc(params[i])) {
			continue
		}
		lv, ok := args[i].(*ir.LocalVar)
		if !ok {
			continue
		}
		for j := len(out) - 1; j >= 0; j-- {
			as, ok := out[j].(*ir.AssignStmt)
			if !ok {
				continue
			}
			if tlv, ok := as.Target.(*ir.LocalVar); ok && tlv == lv {
				if lit, ok := as.Value.(*ir.IntLit); ok && lit.Value == 0 {
					args[i] = &ir.NullLit{}
				}
				break
			}
		}
	}
	return args
}

// convertInstruction converts one non-invoke, non-branch instruction.
func (d *DalvikToIR) convertInstruction(inst *Instruction) []ir.Stmt {
	switch inst.Op {
	// Moves
	case OP_MOVE, OP_MOVE_FROM16, OP_MOVE_16,
		OP_MOVE_WIDE, OP_MOVE_WIDE_FROM16, OP_MOVE_WIDE_16,
		OP_MOVE_OBJECT, OP_MOVE_OBJECT_FROM16, OP_MOVE_OBJECT_16:
		return assign(d.getRegister(inst.A), d.getRegister(inst.B))

	case OP_MOVE_EXCEPTION:
		return assign(d.getRegister(inst.A), &ir.LocalVar{Name: "exception"})

	// Constants
	case OP_CONST_4, OP_CONST_16, OP_CONST, OP_CONST_HIGH_16:
		return assign(d.getRegister(inst.A), &ir.IntLit{Value: inst.Literal})
	case OP_CONST_WIDE_16, OP_CONST_WIDE_32, OP_CONST_WIDE, OP_CONST_WIDE_HIGH_16:
		return assign(d.getRegister(inst.A), &ir.LongLit{Value: inst.Literal})
	case OP_CONST_STRING, OP_CONST_STRING_JUMBO:
		return assign(d.getRegister(inst.A), &ir.StringLit{Value: d.dex.GetString(inst.Ref)})
	case OP_CONST_CLASS:
		return assign(d.getRegister(inst.A), &ir.ClassLiteral{
			Type: JavaClassName(d.dex.GetTypeDesc(inst.Ref)) + ".class",
		})

	// Type operations
	case OP_CHECK_CAST:
		t := TypeFromDesc(d.dex.GetTypeDesc(inst.Ref))
		return assign(d.getRegister(inst.A), &ir.CastExpr{Type: t, Expr: d.getRegister(inst.A)})
	case OP_INSTANCE_OF:
		t := TypeFromDesc(d.dex.GetTypeDesc(inst.Ref))
		return assign(d.getRegister(inst.A), &ir.BinaryExpr{
			Op: "instanceof", Left: d.getRegister(inst.B), Right: &ir.ClassType{Name: fmt.Sprint(t)},
		})
	case OP_ARRAY_LENGTH:
		return assign(d.getRegister(inst.A), &ir.FieldAccess{
			Object: d.getRegister(inst.B), Name: "length",
		})

	// Object creation
	case OP_NEW_INSTANCE:
		return assign(d.getRegister(inst.A), &ir.NewExpr{Type: JavaClassName(d.dex.GetTypeDesc(inst.Ref))})
	case OP_NEW_ARRAY:
		return assign(d.getRegister(inst.A), &ir.NewArrayExpr{
			ElemType: TypeFromDesc(d.dex.GetTypeDesc(inst.Ref)),
			Size:     d.getRegister(inst.B),
		})
	case OP_FILLED_NEW_ARRAY, OP_FILLED_NEW_ARRAY_RANGE:
		elemDesc := d.dex.GetTypeDesc(inst.Ref)
		elems := make([]ir.Expr, 0, len(inst.Regs))
		for _, r := range inst.Regs {
			elems = append(elems, d.getRegister(r))
		}
		d.pending = &ir.ArrayInitExpr{ElemType: TypeFromDesc(elemDesc), Elems: elems}
		d.pendingDesc = elemDesc
		return nil
	case OP_FILL_ARRAY_DATA:
		if inst.ArrayData == nil {
			return nil
		}
		var stmts []ir.Stmt
		arr := d.getRegister(inst.A)
		for i, raw := range inst.ArrayData.Elements {
			var lit ir.Expr
			if inst.ArrayData.ElementWidth > 4 {
				lit = &ir.LongLit{Value: int64(raw)}
			} else {
				lit = &ir.IntLit{Value: int64(int32(raw))}
			}
			stmts = append(stmts, &ir.AssignStmt{
				Target: &ir.ArrayAccess{Array: arr, Index: &ir.IntLit{Value: int64(i)}},
				Value:  lit,
			})
		}
		return stmts

	// Field access
	case OP_IGET, OP_IGET_WIDE, OP_IGET_OBJECT, OP_IGET_BOOLEAN,
		OP_IGET_BYTE, OP_IGET_CHAR, OP_IGET_SHORT:
		return assign(d.getRegister(inst.A), &ir.FieldAccess{
			Object: d.getRegister(inst.B), Name: d.dex.GetFieldName(inst.Ref),
		})
	case OP_IPUT, OP_IPUT_WIDE, OP_IPUT_OBJECT, OP_IPUT_BOOLEAN,
		OP_IPUT_BYTE, OP_IPUT_CHAR, OP_IPUT_SHORT:
		return []ir.Stmt{&ir.AssignStmt{
			Target: &ir.FieldAccess{Object: d.getRegister(inst.B), Name: d.dex.GetFieldName(inst.Ref)},
			Value:  d.coerceFieldValue(d.getRegister(inst.A), inst.Ref),
		}}
	case OP_SGET, OP_SGET_WIDE, OP_SGET_OBJECT, OP_SGET_BOOLEAN,
		OP_SGET_BYTE, OP_SGET_CHAR, OP_SGET_SHORT:
		return assign(d.getRegister(inst.A), d.staticFieldExpr(inst.Ref))
	case OP_SPUT, OP_SPUT_WIDE, OP_SPUT_OBJECT, OP_SPUT_BOOLEAN,
		OP_SPUT_BYTE, OP_SPUT_CHAR, OP_SPUT_SHORT:
		return []ir.Stmt{&ir.AssignStmt{
			Target: d.staticFieldExpr(inst.Ref),
			Value:  d.coerceFieldValue(d.getRegister(inst.A), inst.Ref),
		}}

	// Array access
	case OP_AGET, OP_AGET_WIDE, OP_AGET_OBJECT, OP_AGET_BOOLEAN,
		OP_AGET_BYTE, OP_AGET_CHAR, OP_AGET_SHORT:
		return assign(d.getRegister(inst.A), &ir.ArrayAccess{
			Array: d.getRegister(inst.B), Index: d.getRegister(inst.C),
		})
	case OP_APUT, OP_APUT_WIDE, OP_APUT_OBJECT, OP_APUT_BOOLEAN,
		OP_APUT_BYTE, OP_APUT_CHAR, OP_APUT_SHORT:
		return []ir.Stmt{&ir.AssignStmt{
			Target: &ir.ArrayAccess{Array: d.getRegister(inst.B), Index: d.getRegister(inst.C)},
			Value:  d.getRegister(inst.A),
		}}

	// Unary operations
	case OP_NEG_INT, OP_NEG_LONG, OP_NEG_FLOAT, OP_NEG_DOUBLE:
		return assign(d.getRegister(inst.A), &ir.UnaryExpr{Op: "-", Expr: d.getRegister(inst.B)})
	case OP_NOT_INT, OP_NOT_LONG:
		return assign(d.getRegister(inst.A), &ir.UnaryExpr{Op: "~", Expr: d.getRegister(inst.B)})

	// Conversions
	case OP_INT_TO_LONG, OP_INT_TO_FLOAT, OP_INT_TO_DOUBLE, OP_INT_TO_BYTE,
		OP_INT_TO_CHAR, OP_INT_TO_SHORT, OP_LONG_TO_INT, OP_LONG_TO_FLOAT,
		OP_LONG_TO_DOUBLE, OP_FLOAT_TO_INT, OP_FLOAT_TO_LONG, OP_FLOAT_TO_DOUBLE,
		OP_DOUBLE_TO_INT, OP_DOUBLE_TO_LONG, OP_DOUBLE_TO_FLOAT:
		return assign(d.getRegister(inst.A), &ir.CastExpr{
			Type: TypeFromDesc(conversionDesc(inst.Op)),
			Expr: d.getRegister(inst.B),
		})

	// Binary arithmetic (23x)
	case OP_ADD_INT, OP_SUB_INT, OP_MUL_INT, OP_DIV_INT, OP_REM_INT,
		OP_AND_INT, OP_OR_INT, OP_XOR_INT, OP_SHL_INT, OP_SHR_INT, OP_USHR_INT,
		OP_ADD_LONG, OP_SUB_LONG, OP_MUL_LONG, OP_DIV_LONG, OP_REM_LONG,
		OP_AND_LONG, OP_OR_LONG, OP_XOR_LONG, OP_SHL_LONG, OP_SHR_LONG, OP_USHR_LONG,
		OP_ADD_FLOAT, OP_SUB_FLOAT, OP_MUL_FLOAT, OP_DIV_FLOAT, OP_REM_FLOAT,
		OP_ADD_DOUBLE, OP_SUB_DOUBLE, OP_MUL_DOUBLE, OP_DIV_DOUBLE, OP_REM_DOUBLE:
		return assign(d.getRegister(inst.A), &ir.BinaryExpr{
			Op: binOpFor(inst.Op), Left: d.getRegister(inst.B), Right: d.getRegister(inst.C),
		})

	// Binary arithmetic (12x /2addr)
	case OP_ADD_INT_2ADDR, OP_SUB_INT_2ADDR, OP_MUL_INT_2ADDR, OP_DIV_INT_2ADDR,
		OP_REM_INT_2ADDR, OP_AND_INT_2ADDR, OP_OR_INT_2ADDR, OP_XOR_INT_2ADDR,
		OP_SHL_INT_2ADDR, OP_SHR_INT_2ADDR, OP_USHR_INT_2ADDR,
		OP_ADD_LONG_2ADDR, OP_SUB_LONG_2ADDR, OP_MUL_LONG_2ADDR, OP_DIV_LONG_2ADDR,
		OP_REM_LONG_2ADDR, OP_AND_LONG_2ADDR, OP_OR_LONG_2ADDR, OP_XOR_LONG_2ADDR,
		OP_SHL_LONG_2ADDR, OP_SHR_LONG_2ADDR, OP_USHR_LONG_2ADDR,
		OP_ADD_FLOAT_2ADDR, OP_SUB_FLOAT_2ADDR, OP_MUL_FLOAT_2ADDR, OP_DIV_FLOAT_2ADDR,
		OP_REM_FLOAT_2ADDR, OP_ADD_DOUBLE_2ADDR, OP_SUB_DOUBLE_2ADDR,
		OP_MUL_DOUBLE_2ADDR, OP_DIV_DOUBLE_2ADDR, OP_REM_DOUBLE_2ADDR:
		return assign(d.getRegister(inst.A), &ir.BinaryExpr{
			Op: binOpFor(inst.Op), Left: d.getRegister(inst.A), Right: d.getRegister(inst.B),
		})

	// Literal arithmetic (rsub computes literal - register)
	case OP_RSUB_INT_LIT8, OP_RSUB_INT:
		return assign(d.getRegister(inst.A), &ir.BinaryExpr{
			Op:    "-",
			Left:  &ir.IntLit{Value: inst.Literal},
			Right: d.getRegister(inst.B),
		})
	case OP_ADD_INT_LIT8, OP_MUL_INT_LIT8, OP_DIV_INT_LIT8,
		OP_REM_INT_LIT8, OP_AND_INT_LIT8, OP_OR_INT_LIT8, OP_XOR_INT_LIT8,
		OP_SHL_INT_LIT8, OP_SHR_INT_LIT8, OP_USHR_INT_LIT8,
		OP_ADD_INT_LIT16, OP_MUL_INT_LIT16, OP_DIV_INT_LIT16,
		OP_REM_INT_LIT16, OP_AND_INT_LIT16, OP_OR_INT_LIT16, OP_XOR_INT_LIT16:
		return assign(d.getRegister(inst.A), &ir.BinaryExpr{
			Op:    binOpFor(inst.Op),
			Left:  d.getRegister(inst.B),
			Right: &ir.IntLit{Value: inst.Literal},
		})

	// Comparisons return an int (-1/0/1)
	case OP_CMPL_FLOAT, OP_CMPG_FLOAT:
		return assign(d.getRegister(inst.A), &ir.StaticMethodCall{
			Class: "java.lang.Float", Method: "compare",
			Args: []ir.Expr{d.getRegister(inst.B), d.getRegister(inst.C)},
		})
	case OP_CMPL_DOUBLE, OP_CMPG_DOUBLE:
		return assign(d.getRegister(inst.A), &ir.StaticMethodCall{
			Class: "java.lang.Double", Method: "compare",
			Args: []ir.Expr{d.getRegister(inst.B), d.getRegister(inst.C)},
		})
	case OP_CMP_LONG:
		return assign(d.getRegister(inst.A), &ir.StaticMethodCall{
			Class: "java.lang.Long", Method: "compare",
			Args: []ir.Expr{d.getRegister(inst.B), d.getRegister(inst.C)},
		})

	// Returns
	case OP_RETURN_VOID:
		return []ir.Stmt{&ir.ReturnStmt{}}
	case OP_RETURN, OP_RETURN_WIDE, OP_RETURN_OBJECT:
		return []ir.Stmt{&ir.ReturnStmt{Value: d.getRegister(inst.A)}}

	case OP_THROW:
		return []ir.Stmt{&ir.ThrowStmt{Value: d.getRegister(inst.A)}}

	case OP_MONITOR_ENTER:
		return []ir.Stmt{&ir.ExprStmt{Expr: &ir.MethodCall{
			Object: d.getRegister(inst.A), Name: "monitorEnter",
		}}}
	case OP_MONITOR_EXIT:
		return []ir.Stmt{&ir.ExprStmt{Expr: &ir.MethodCall{
			Object: d.getRegister(inst.A), Name: "monitorExit",
		}}}

	case OP_NOP:
		return nil
	}

	return nil
}

// coerceFieldValue converts an int constant into a boolean literal when
// storing into a boolean field, so the generated Java type-checks.
func (d *DalvikToIR) coerceFieldValue(v ir.Expr, ref uint32) ir.Expr {
	fid := d.dex.GetFieldId(ref)
	if fid == nil || d.dex.GetTypeDesc(uint32(fid.TypeIdx)) != "Z" {
		return v
	}
	if lit, ok := v.(*ir.IntLit); ok {
		return &ir.BoolLit{Value: lit.Value != 0}
	}
	return v
}

func (d *DalvikToIR) staticFieldExpr(ref uint32) ir.Expr {
	fid := d.dex.GetFieldId(ref)
	if fid == nil {
		return &ir.FieldAccess{Name: d.dex.GetFieldName(ref)}
	}
	return &ir.FieldAccess{
		Object: &ir.ClassType{Name: JavaClassName(d.dex.GetTypeDesc(uint32(fid.ClassIdx)))},
		Name:   d.dex.GetFieldName(ref),
	}
}

func assign(target, value ir.Expr) []ir.Stmt {
	return []ir.Stmt{&ir.AssignStmt{Target: target, Value: value}}
}

// binOpFor maps an arithmetic opcode to its Java operator.
func binOpFor(op byte) string {
	switch {
	case op >= OP_ADD_INT && op <= OP_USHR_INT:
		return intBinOps[op-OP_ADD_INT]
	case op >= OP_ADD_LONG && op <= OP_USHR_LONG:
		return intBinOps[op-OP_ADD_LONG]
	case op >= OP_ADD_FLOAT && op <= OP_REM_FLOAT:
		return floatBinOps[op-OP_ADD_FLOAT]
	case op >= OP_ADD_DOUBLE && op <= OP_REM_DOUBLE:
		return floatBinOps[op-OP_ADD_DOUBLE]
	case op >= OP_ADD_INT_2ADDR && op <= OP_USHR_INT_2ADDR:
		return intBinOps[op-OP_ADD_INT_2ADDR]
	case op >= OP_ADD_LONG_2ADDR && op <= OP_USHR_LONG_2ADDR:
		return intBinOps[op-OP_ADD_LONG_2ADDR]
	case op >= OP_ADD_FLOAT_2ADDR && op <= OP_REM_FLOAT_2ADDR:
		return floatBinOps[op-OP_ADD_FLOAT_2ADDR]
	case op >= OP_ADD_DOUBLE_2ADDR && op <= OP_REM_DOUBLE_2ADDR:
		return floatBinOps[op-OP_ADD_DOUBLE_2ADDR]
	case op >= OP_ADD_INT_LIT8 && op <= OP_USHR_INT_LIT8:
		return intBinOps[op-OP_ADD_INT_LIT8]
	case op >= OP_ADD_INT_LIT16 && op <= OP_XOR_INT_LIT16:
		return lit16BinOps[op-OP_ADD_INT_LIT16]
	}
	return "+"
}

var intBinOps = []string{"+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", ">>>"}
var floatBinOps = []string{"+", "-", "*", "/", "%"}
var lit16BinOps = []string{"+", "-", "*", "/", "%", "&", "|", "^"}

// conversionDesc maps an int/long/float/double conversion opcode to the
// destination type descriptor.
func conversionDesc(op byte) string {
	switch op {
	case OP_INT_TO_LONG, OP_FLOAT_TO_LONG, OP_DOUBLE_TO_LONG:
		return "J"
	case OP_INT_TO_FLOAT, OP_LONG_TO_FLOAT, OP_DOUBLE_TO_FLOAT:
		return "F"
	case OP_INT_TO_DOUBLE, OP_LONG_TO_DOUBLE, OP_FLOAT_TO_DOUBLE:
		return "D"
	case OP_LONG_TO_INT, OP_FLOAT_TO_INT, OP_DOUBLE_TO_INT:
		return "I"
	case OP_INT_TO_BYTE:
		return "B"
	case OP_INT_TO_CHAR:
		return "C"
	case OP_INT_TO_SHORT:
		return "S"
	}
	return "I"
}

// buildCond builds an expression that is true when the conditional branch is
// taken.
func (d *DalvikToIR) buildCond(inst *Instruction) ir.Expr {
	if inst.Op >= OP_IF_EQ && inst.Op <= OP_IF_LE {
		return &ir.BinaryExpr{
			Op:    cmpOpFor(inst.Op),
			Left:  d.getRegister(inst.A),
			Right: d.getRegister(inst.B),
		}
	}
	if inst.Op >= OP_IF_EQZ && inst.Op <= OP_IF_LEZ {
		reg := d.getRegister(inst.A)
		desc := d.regTypes[inst.A]
		if desc == "Z" {
			if inst.Op == OP_IF_EQZ {
				return &ir.UnaryExpr{Op: "!", Expr: reg}
			}
			if inst.Op == OP_IF_NEZ {
				return reg
			}
		}
		var zero ir.Expr = &ir.IntLit{Value: 0}
		if IsRefDesc(desc) {
			zero = &ir.NullLit{}
		}
		return &ir.BinaryExpr{
			Op:    cmpOpFor(inst.Op),
			Left:  reg,
			Right: zero,
		}
	}
	return &ir.BoolLit{Value: false}
}

func cmpOpFor(op byte) string {
	switch op {
	case OP_IF_EQ, OP_IF_EQZ:
		return "=="
	case OP_IF_NE, OP_IF_NEZ:
		return "!="
	case OP_IF_LT, OP_IF_LTZ:
		return "<"
	case OP_IF_GE, OP_IF_GEZ:
		return ">="
	case OP_IF_GT, OP_IF_GTZ:
		return ">"
	case OP_IF_LE, OP_IF_LEZ:
		return "<="
	}
	return "=="
}

// negate returns an expression that is the logical negation of e.
func negateExpr(e ir.Expr) ir.Expr {
	if u, ok := e.(*ir.UnaryExpr); ok && u.Op == "!" {
		return u.Expr
	}
	if b, ok := e.(*ir.BinaryExpr); ok {
		switch b.Op {
		case "==":
			return &ir.BinaryExpr{Op: "!=", Left: b.Left, Right: b.Right}
		case "!=":
			return &ir.BinaryExpr{Op: "==", Left: b.Left, Right: b.Right}
		case "<":
			return &ir.BinaryExpr{Op: ">=", Left: b.Left, Right: b.Right}
		case ">":
			return &ir.BinaryExpr{Op: "<=", Left: b.Left, Right: b.Right}
		case "<=":
			return &ir.BinaryExpr{Op: ">", Left: b.Left, Right: b.Right}
		case ">=":
			return &ir.BinaryExpr{Op: "<", Left: b.Left, Right: b.Right}
		}
	}
	return &ir.UnaryExpr{Op: "!", Expr: e}
}
