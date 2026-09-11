package dex

// Dalvik opcodes. Names follow the official Dalvik bytecode listing.
const (
	OP_NOP                    = 0x00
	OP_MOVE                   = 0x01
	OP_MOVE_FROM16            = 0x02
	OP_MOVE_16                = 0x03
	OP_MOVE_WIDE              = 0x04
	OP_MOVE_WIDE_FROM16       = 0x05
	OP_MOVE_WIDE_16           = 0x06
	OP_MOVE_OBJECT            = 0x07
	OP_MOVE_OBJECT_FROM16     = 0x08
	OP_MOVE_OBJECT_16         = 0x09
	OP_MOVE_RESULT            = 0x0a
	OP_MOVE_RESULT_WIDE       = 0x0b
	OP_MOVE_RESULT_OBJECT     = 0x0c
	OP_MOVE_EXCEPTION         = 0x0d
	OP_RETURN_VOID            = 0x0e
	OP_RETURN                 = 0x0f
	OP_RETURN_WIDE            = 0x10
	OP_RETURN_OBJECT          = 0x11
	OP_CONST_4                = 0x12
	OP_CONST_16               = 0x13
	OP_CONST                  = 0x14
	OP_CONST_HIGH_16          = 0x15
	OP_CONST_WIDE_16          = 0x16
	OP_CONST_WIDE_32          = 0x17
	OP_CONST_WIDE             = 0x18
	OP_CONST_WIDE_HIGH_16     = 0x19
	OP_CONST_STRING           = 0x1a
	OP_CONST_STRING_JUMBO     = 0x1b
	OP_CONST_CLASS            = 0x1c
	OP_MONITOR_ENTER          = 0x1d
	OP_MONITOR_EXIT           = 0x1e
	OP_CHECK_CAST             = 0x1f
	OP_INSTANCE_OF            = 0x20
	OP_ARRAY_LENGTH           = 0x21
	OP_NEW_INSTANCE           = 0x22
	OP_NEW_ARRAY              = 0x23
	OP_FILLED_NEW_ARRAY       = 0x24
	OP_FILLED_NEW_ARRAY_RANGE = 0x25
	OP_FILL_ARRAY_DATA        = 0x26
	OP_THROW                  = 0x27
	OP_GOTO                   = 0x28
	OP_GOTO_16                = 0x29
	OP_GOTO_32                = 0x2a
	OP_PACKED_SWITCH          = 0x2b
	OP_SPARSE_SWITCH          = 0x2c
	OP_CMPL_FLOAT             = 0x2d
	OP_CMPG_FLOAT             = 0x2e
	OP_CMPL_DOUBLE            = 0x2f
	OP_CMPG_DOUBLE            = 0x30
	OP_CMP_LONG               = 0x31
	OP_IF_EQ                  = 0x32
	OP_IF_NE                  = 0x33
	OP_IF_LT                  = 0x34
	OP_IF_GE                  = 0x35
	OP_IF_GT                  = 0x36
	OP_IF_LE                  = 0x37
	OP_IF_EQZ                 = 0x38
	OP_IF_NEZ                 = 0x39
	OP_IF_LTZ                 = 0x3a
	OP_IF_GEZ                 = 0x3b
	OP_IF_GTZ                 = 0x3c
	OP_IF_LEZ                 = 0x3d
	OP_AGET                   = 0x44
	OP_AGET_WIDE              = 0x45
	OP_AGET_OBJECT            = 0x46
	OP_AGET_BOOLEAN           = 0x47
	OP_AGET_BYTE              = 0x48
	OP_AGET_CHAR              = 0x49
	OP_AGET_SHORT             = 0x4a
	OP_APUT                   = 0x4b
	OP_APUT_WIDE              = 0x4c
	OP_APUT_OBJECT            = 0x4d
	OP_APUT_BOOLEAN           = 0x4e
	OP_APUT_BYTE              = 0x4f
	OP_APUT_CHAR              = 0x50
	OP_APUT_SHORT             = 0x51
	OP_IGET                   = 0x52
	OP_IGET_WIDE              = 0x53
	OP_IGET_OBJECT            = 0x54
	OP_IGET_BOOLEAN           = 0x55
	OP_IGET_BYTE              = 0x56
	OP_IGET_CHAR              = 0x57
	OP_IGET_SHORT             = 0x58
	OP_IPUT                   = 0x59
	OP_IPUT_WIDE              = 0x5a
	OP_IPUT_OBJECT            = 0x5b
	OP_IPUT_BOOLEAN           = 0x5c
	OP_IPUT_BYTE              = 0x5d
	OP_IPUT_CHAR              = 0x5e
	OP_IPUT_SHORT             = 0x5f
	OP_SGET                   = 0x60
	OP_SGET_WIDE              = 0x61
	OP_SGET_OBJECT            = 0x62
	OP_SGET_BOOLEAN           = 0x63
	OP_SGET_BYTE              = 0x64
	OP_SGET_CHAR              = 0x65
	OP_SGET_SHORT             = 0x66
	OP_SPUT                   = 0x67
	OP_SPUT_WIDE              = 0x68
	OP_SPUT_OBJECT            = 0x69
	OP_SPUT_BOOLEAN           = 0x6a
	OP_SPUT_BYTE              = 0x6b
	OP_SPUT_CHAR              = 0x6c
	OP_SPUT_SHORT             = 0x6d
	OP_INVOKE_VIRTUAL         = 0x6e
	OP_INVOKE_SUPER           = 0x6f
	OP_INVOKE_DIRECT          = 0x70
	OP_INVOKE_STATIC          = 0x71
	OP_INVOKE_INTERFACE       = 0x72
	OP_INVOKE_VIRTUAL_RANGE   = 0x74
	OP_INVOKE_SUPER_RANGE     = 0x75
	OP_INVOKE_DIRECT_RANGE    = 0x76
	OP_INVOKE_STATIC_RANGE    = 0x77
	OP_INVOKE_INTERFACE_RANGE = 0x78
	OP_NEG_INT                = 0x7b
	OP_NOT_INT                = 0x7c
	OP_NEG_LONG               = 0x7d
	OP_NOT_LONG               = 0x7e
	OP_NEG_FLOAT              = 0x7f
	OP_NEG_DOUBLE             = 0x80
	OP_INT_TO_LONG            = 0x81
	OP_INT_TO_FLOAT           = 0x82
	OP_INT_TO_DOUBLE          = 0x83
	OP_LONG_TO_INT            = 0x84
	OP_LONG_TO_FLOAT          = 0x85
	OP_LONG_TO_DOUBLE         = 0x86
	OP_FLOAT_TO_INT           = 0x87
	OP_FLOAT_TO_LONG          = 0x88
	OP_FLOAT_TO_DOUBLE        = 0x89
	OP_DOUBLE_TO_INT          = 0x8a
	OP_DOUBLE_TO_LONG         = 0x8b
	OP_DOUBLE_TO_FLOAT        = 0x8c
	OP_INT_TO_BYTE            = 0x8d
	OP_INT_TO_CHAR            = 0x8e
	OP_INT_TO_SHORT           = 0x8f
	OP_ADD_INT                = 0x90
	OP_SUB_INT                = 0x91
	OP_MUL_INT                = 0x92
	OP_DIV_INT                = 0x93
	OP_REM_INT                = 0x94
	OP_AND_INT                = 0x95
	OP_OR_INT                 = 0x96
	OP_XOR_INT                = 0x97
	OP_SHL_INT                = 0x98
	OP_SHR_INT                = 0x99
	OP_USHR_INT               = 0x9a
	OP_ADD_LONG               = 0x9b
	OP_SUB_LONG               = 0x9c
	OP_MUL_LONG               = 0x9d
	OP_DIV_LONG               = 0x9e
	OP_REM_LONG               = 0x9f
	OP_AND_LONG               = 0xa0
	OP_OR_LONG                = 0xa1
	OP_XOR_LONG               = 0xa2
	OP_SHL_LONG               = 0xa3
	OP_SHR_LONG               = 0xa4
	OP_USHR_LONG              = 0xa5
	OP_ADD_FLOAT              = 0xa6
	OP_SUB_FLOAT              = 0xa7
	OP_MUL_FLOAT              = 0xa8
	OP_DIV_FLOAT              = 0xa9
	OP_REM_FLOAT              = 0xaa
	OP_ADD_DOUBLE             = 0xab
	OP_SUB_DOUBLE             = 0xac
	OP_MUL_DOUBLE             = 0xad
	OP_DIV_DOUBLE             = 0xae
	OP_REM_DOUBLE             = 0xaf
	OP_ADD_INT_2ADDR          = 0xb0
	OP_SUB_INT_2ADDR          = 0xb1
	OP_MUL_INT_2ADDR          = 0xb2
	OP_DIV_INT_2ADDR          = 0xb3
	OP_REM_INT_2ADDR          = 0xb4
	OP_AND_INT_2ADDR          = 0xb5
	OP_OR_INT_2ADDR           = 0xb6
	OP_XOR_INT_2ADDR          = 0xb7
	OP_SHL_INT_2ADDR          = 0xb8
	OP_SHR_INT_2ADDR          = 0xb9
	OP_USHR_INT_2ADDR         = 0xba
	OP_ADD_LONG_2ADDR         = 0xbb
	OP_SUB_LONG_2ADDR         = 0xbc
	OP_MUL_LONG_2ADDR         = 0xbd
	OP_DIV_LONG_2ADDR         = 0xbe
	OP_REM_LONG_2ADDR         = 0xbf
	OP_AND_LONG_2ADDR         = 0xc0
	OP_OR_LONG_2ADDR          = 0xc1
	OP_XOR_LONG_2ADDR         = 0xc2
	OP_SHL_LONG_2ADDR         = 0xc3
	OP_SHR_LONG_2ADDR         = 0xc4
	OP_USHR_LONG_2ADDR        = 0xc5
	OP_ADD_FLOAT_2ADDR        = 0xc6
	OP_SUB_FLOAT_2ADDR        = 0xc7
	OP_MUL_FLOAT_2ADDR        = 0xc8
	OP_DIV_FLOAT_2ADDR        = 0xc9
	OP_REM_FLOAT_2ADDR        = 0xca
	OP_ADD_DOUBLE_2ADDR       = 0xcb
	OP_SUB_DOUBLE_2ADDR       = 0xcc
	OP_MUL_DOUBLE_2ADDR       = 0xcd
	OP_DIV_DOUBLE_2ADDR       = 0xce
	OP_REM_DOUBLE_2ADDR       = 0xcf
	OP_ADD_INT_LIT16          = 0xd0
	OP_RSUB_INT               = 0xd1
	OP_MUL_INT_LIT16          = 0xd2
	OP_DIV_INT_LIT16          = 0xd3
	OP_REM_INT_LIT16          = 0xd4
	OP_AND_INT_LIT16          = 0xd5
	OP_OR_INT_LIT16           = 0xd6
	OP_XOR_INT_LIT16          = 0xd7
	OP_ADD_INT_LIT8           = 0xd8
	OP_RSUB_INT_LIT8          = 0xd9
	OP_MUL_INT_LIT8           = 0xda
	OP_DIV_INT_LIT8           = 0xdb
	OP_REM_INT_LIT8           = 0xdc
	OP_AND_INT_LIT8           = 0xdd
	OP_OR_INT_LIT8            = 0xde
	OP_XOR_INT_LIT8           = 0xdf
	OP_SHL_INT_LIT8           = 0xe0
	OP_SHR_INT_LIT8           = 0xe1
	OP_USHR_INT_LIT8          = 0xe2

	// Newer standard opcodes (ART invoke-polymorphic/custom and
	// method handle/type constants).
	OP_INVOKE_POLYMORPHIC       = 0xfa
	OP_INVOKE_POLYMORPHIC_RANGE = 0xfb
	OP_INVOKE_CUSTOM            = 0xfc
	OP_INVOKE_CUSTOM_RANGE      = 0xfd
	OP_CONST_METHOD_HANDLE      = 0xfe
	OP_CONST_METHOD_TYPE        = 0xff
)

// Pseudo-instruction identifiers (found at switch/fill-array-data targets).
const (
	pseudoPackedSwitch  = 0x0100
	pseudoSparseSwitch  = 0x0200
	pseudoFillArrayData = 0x0300
)

// Format describes an instruction's operand encoding.
type Format uint8

const (
	FormatUnknown Format = iota
	F10x
	F12x
	F11x
	F11n
	F10t
	F20t
	F22x
	F21c
	F21ih
	F21lh
	F21s
	F21t
	F22b
	F22c
	F22s
	F22t
	F23x
	F30t
	F31c
	F31i
	F31t
	F32x
	F35c
	F3rc
	F51l
	F45cc
	F4rcc
)

var (
	opNames   [256]string
	opFormats [256]Format
)

func defOp(op byte, name string, format Format) {
	opNames[op] = name
	opFormats[op] = format
}

func init() {
	defOp(OP_NOP, "nop", F10x)
	defOp(OP_MOVE, "move", F12x)
	defOp(OP_MOVE_FROM16, "move/from16", F22x)
	defOp(OP_MOVE_16, "move/16", F32x)
	defOp(OP_MOVE_WIDE, "move-wide", F12x)
	defOp(OP_MOVE_WIDE_FROM16, "move-wide/from16", F22x)
	defOp(OP_MOVE_WIDE_16, "move-wide/16", F32x)
	defOp(OP_MOVE_OBJECT, "move-object", F12x)
	defOp(OP_MOVE_OBJECT_FROM16, "move-object/from16", F22x)
	defOp(OP_MOVE_OBJECT_16, "move-object/16", F32x)
	defOp(OP_MOVE_RESULT, "move-result", F11x)
	defOp(OP_MOVE_RESULT_WIDE, "move-result-wide", F11x)
	defOp(OP_MOVE_RESULT_OBJECT, "move-result-object", F11x)
	defOp(OP_MOVE_EXCEPTION, "move-exception", F11x)
	defOp(OP_RETURN_VOID, "return-void", F10x)
	defOp(OP_RETURN, "return", F11x)
	defOp(OP_RETURN_WIDE, "return-wide", F11x)
	defOp(OP_RETURN_OBJECT, "return-object", F11x)
	defOp(OP_CONST_4, "const/4", F11n)
	defOp(OP_CONST_16, "const/16", F21s)
	defOp(OP_CONST, "const", F31i)
	defOp(OP_CONST_HIGH_16, "const/high16", F21ih)
	defOp(OP_CONST_WIDE_16, "const-wide/16", F21s)
	defOp(OP_CONST_WIDE_32, "const-wide/32", F31i)
	defOp(OP_CONST_WIDE, "const-wide", F51l)
	defOp(OP_CONST_WIDE_HIGH_16, "const-wide/high16", F21lh)
	defOp(OP_CONST_STRING, "const-string", F21c)
	defOp(OP_CONST_STRING_JUMBO, "const-string/jumbo", F31c)
	defOp(OP_CONST_CLASS, "const-class", F21c)
	defOp(OP_MONITOR_ENTER, "monitor-enter", F11x)
	defOp(OP_MONITOR_EXIT, "monitor-exit", F11x)
	defOp(OP_CHECK_CAST, "check-cast", F21c)
	defOp(OP_INSTANCE_OF, "instance-of", F22c)
	defOp(OP_ARRAY_LENGTH, "array-length", F12x)
	defOp(OP_NEW_INSTANCE, "new-instance", F21c)
	defOp(OP_NEW_ARRAY, "new-array", F22c)
	defOp(OP_FILLED_NEW_ARRAY, "filled-new-array", F35c)
	defOp(OP_FILLED_NEW_ARRAY_RANGE, "filled-new-array/range", F3rc)
	defOp(OP_FILL_ARRAY_DATA, "fill-array-data", F31t)
	defOp(OP_THROW, "throw", F11x)
	defOp(OP_GOTO, "goto", F10t)
	defOp(OP_GOTO_16, "goto/16", F20t)
	defOp(OP_GOTO_32, "goto/32", F30t)
	defOp(OP_PACKED_SWITCH, "packed-switch", F31t)
	defOp(OP_SPARSE_SWITCH, "sparse-switch", F31t)
	defOp(OP_CMPL_FLOAT, "cmpl-float", F23x)
	defOp(OP_CMPG_FLOAT, "cmpg-float", F23x)
	defOp(OP_CMPL_DOUBLE, "cmpl-double", F23x)
	defOp(OP_CMPG_DOUBLE, "cmpg-double", F23x)
	defOp(OP_CMP_LONG, "cmp-long", F23x)
	defOp(OP_IF_EQ, "if-eq", F22t)
	defOp(OP_IF_NE, "if-ne", F22t)
	defOp(OP_IF_LT, "if-lt", F22t)
	defOp(OP_IF_GE, "if-ge", F22t)
	defOp(OP_IF_GT, "if-gt", F22t)
	defOp(OP_IF_LE, "if-le", F22t)
	defOp(OP_IF_EQZ, "if-eqz", F21t)
	defOp(OP_IF_NEZ, "if-nez", F21t)
	defOp(OP_IF_LTZ, "if-ltz", F21t)
	defOp(OP_IF_GEZ, "if-gez", F21t)
	defOp(OP_IF_GTZ, "if-gtz", F21t)
	defOp(OP_IF_LEZ, "if-lez", F21t)
	defOp(OP_AGET, "aget", F23x)
	defOp(OP_AGET_WIDE, "aget-wide", F23x)
	defOp(OP_AGET_OBJECT, "aget-object", F23x)
	defOp(OP_AGET_BOOLEAN, "aget-boolean", F23x)
	defOp(OP_AGET_BYTE, "aget-byte", F23x)
	defOp(OP_AGET_CHAR, "aget-char", F23x)
	defOp(OP_AGET_SHORT, "aget-short", F23x)
	defOp(OP_APUT, "aput", F23x)
	defOp(OP_APUT_WIDE, "aput-wide", F23x)
	defOp(OP_APUT_OBJECT, "aput-object", F23x)
	defOp(OP_APUT_BOOLEAN, "aput-boolean", F23x)
	defOp(OP_APUT_BYTE, "aput-byte", F23x)
	defOp(OP_APUT_CHAR, "aput-char", F23x)
	defOp(OP_APUT_SHORT, "aput-short", F23x)
	defOp(OP_IGET, "iget", F22c)
	defOp(OP_IGET_WIDE, "iget-wide", F22c)
	defOp(OP_IGET_OBJECT, "iget-object", F22c)
	defOp(OP_IGET_BOOLEAN, "iget-boolean", F22c)
	defOp(OP_IGET_BYTE, "iget-byte", F22c)
	defOp(OP_IGET_CHAR, "iget-char", F22c)
	defOp(OP_IGET_SHORT, "iget-short", F22c)
	defOp(OP_IPUT, "iput", F22c)
	defOp(OP_IPUT_WIDE, "iput-wide", F22c)
	defOp(OP_IPUT_OBJECT, "iput-object", F22c)
	defOp(OP_IPUT_BOOLEAN, "iput-boolean", F22c)
	defOp(OP_IPUT_BYTE, "iput-byte", F22c)
	defOp(OP_IPUT_CHAR, "iput-char", F22c)
	defOp(OP_IPUT_SHORT, "iput-short", F22c)
	defOp(OP_SGET, "sget", F21c)
	defOp(OP_SGET_WIDE, "sget-wide", F21c)
	defOp(OP_SGET_OBJECT, "sget-object", F21c)
	defOp(OP_SGET_BOOLEAN, "sget-boolean", F21c)
	defOp(OP_SGET_BYTE, "sget-byte", F21c)
	defOp(OP_SGET_CHAR, "sget-char", F21c)
	defOp(OP_SGET_SHORT, "sget-short", F21c)
	defOp(OP_SPUT, "sput", F21c)
	defOp(OP_SPUT_WIDE, "sput-wide", F21c)
	defOp(OP_SPUT_OBJECT, "sput-object", F21c)
	defOp(OP_SPUT_BOOLEAN, "sput-boolean", F21c)
	defOp(OP_SPUT_BYTE, "sput-byte", F21c)
	defOp(OP_SPUT_CHAR, "sput-char", F21c)
	defOp(OP_SPUT_SHORT, "sput-short", F21c)
	defOp(OP_INVOKE_VIRTUAL, "invoke-virtual", F35c)
	defOp(OP_INVOKE_SUPER, "invoke-super", F35c)
	defOp(OP_INVOKE_DIRECT, "invoke-direct", F35c)
	defOp(OP_INVOKE_STATIC, "invoke-static", F35c)
	defOp(OP_INVOKE_INTERFACE, "invoke-interface", F35c)
	defOp(OP_INVOKE_VIRTUAL_RANGE, "invoke-virtual/range", F3rc)
	defOp(OP_INVOKE_SUPER_RANGE, "invoke-super/range", F3rc)
	defOp(OP_INVOKE_DIRECT_RANGE, "invoke-direct/range", F3rc)
	defOp(OP_INVOKE_STATIC_RANGE, "invoke-static/range", F3rc)
	defOp(OP_INVOKE_INTERFACE_RANGE, "invoke-interface/range", F3rc)
	defOp(OP_NEG_INT, "neg-int", F12x)
	defOp(OP_NOT_INT, "not-int", F12x)
	defOp(OP_NEG_LONG, "neg-long", F12x)
	defOp(OP_NOT_LONG, "not-long", F12x)
	defOp(OP_NEG_FLOAT, "neg-float", F12x)
	defOp(OP_NEG_DOUBLE, "neg-double", F12x)
	defOp(OP_INT_TO_LONG, "int-to-long", F12x)
	defOp(OP_INT_TO_FLOAT, "int-to-float", F12x)
	defOp(OP_INT_TO_DOUBLE, "int-to-double", F12x)
	defOp(OP_INT_TO_BYTE, "int-to-byte", F12x)
	defOp(OP_INT_TO_CHAR, "int-to-char", F12x)
	defOp(OP_INT_TO_SHORT, "int-to-short", F12x)
	defOp(OP_LONG_TO_INT, "long-to-int", F12x)
	defOp(OP_LONG_TO_FLOAT, "long-to-float", F12x)
	defOp(OP_LONG_TO_DOUBLE, "long-to-double", F12x)
	defOp(OP_FLOAT_TO_INT, "float-to-int", F12x)
	defOp(OP_FLOAT_TO_LONG, "float-to-long", F12x)
	defOp(OP_FLOAT_TO_DOUBLE, "float-to-double", F12x)
	defOp(OP_DOUBLE_TO_INT, "double-to-int", F12x)
	defOp(OP_DOUBLE_TO_LONG, "double-to-long", F12x)
	defOp(OP_DOUBLE_TO_FLOAT, "double-to-float", F12x)
	defOp(OP_ADD_INT, "add-int", F23x)
	defOp(OP_SUB_INT, "sub-int", F23x)
	defOp(OP_MUL_INT, "mul-int", F23x)
	defOp(OP_DIV_INT, "div-int", F23x)
	defOp(OP_REM_INT, "rem-int", F23x)
	defOp(OP_AND_INT, "and-int", F23x)
	defOp(OP_OR_INT, "or-int", F23x)
	defOp(OP_XOR_INT, "xor-int", F23x)
	defOp(OP_SHL_INT, "shl-int", F23x)
	defOp(OP_SHR_INT, "shr-int", F23x)
	defOp(OP_USHR_INT, "ushr-int", F23x)
	defOp(OP_ADD_LONG, "add-long", F23x)
	defOp(OP_SUB_LONG, "sub-long", F23x)
	defOp(OP_MUL_LONG, "mul-long", F23x)
	defOp(OP_DIV_LONG, "div-long", F23x)
	defOp(OP_REM_LONG, "rem-long", F23x)
	defOp(OP_AND_LONG, "and-long", F23x)
	defOp(OP_OR_LONG, "or-long", F23x)
	defOp(OP_XOR_LONG, "xor-long", F23x)
	defOp(OP_SHL_LONG, "shl-long", F23x)
	defOp(OP_SHR_LONG, "shr-long", F23x)
	defOp(OP_USHR_LONG, "ushr-long", F23x)
	defOp(OP_ADD_FLOAT, "add-float", F23x)
	defOp(OP_SUB_FLOAT, "sub-float", F23x)
	defOp(OP_MUL_FLOAT, "mul-float", F23x)
	defOp(OP_DIV_FLOAT, "div-float", F23x)
	defOp(OP_REM_FLOAT, "rem-float", F23x)
	defOp(OP_ADD_DOUBLE, "add-double", F23x)
	defOp(OP_SUB_DOUBLE, "sub-double", F23x)
	defOp(OP_MUL_DOUBLE, "mul-double", F23x)
	defOp(OP_DIV_DOUBLE, "div-double", F23x)
	defOp(OP_REM_DOUBLE, "rem-double", F23x)
	defOp(OP_ADD_INT_2ADDR, "add-int/2addr", F12x)
	defOp(OP_SUB_INT_2ADDR, "sub-int/2addr", F12x)
	defOp(OP_MUL_INT_2ADDR, "mul-int/2addr", F12x)
	defOp(OP_DIV_INT_2ADDR, "div-int/2addr", F12x)
	defOp(OP_REM_INT_2ADDR, "rem-int/2addr", F12x)
	defOp(OP_AND_INT_2ADDR, "and-int/2addr", F12x)
	defOp(OP_OR_INT_2ADDR, "or-int/2addr", F12x)
	defOp(OP_XOR_INT_2ADDR, "xor-int/2addr", F12x)
	defOp(OP_SHL_INT_2ADDR, "shl-int/2addr", F12x)
	defOp(OP_SHR_INT_2ADDR, "shr-int/2addr", F12x)
	defOp(OP_USHR_INT_2ADDR, "ushr-int/2addr", F12x)
	defOp(OP_ADD_LONG_2ADDR, "add-long/2addr", F12x)
	defOp(OP_SUB_LONG_2ADDR, "sub-long/2addr", F12x)
	defOp(OP_MUL_LONG_2ADDR, "mul-long/2addr", F12x)
	defOp(OP_DIV_LONG_2ADDR, "div-long/2addr", F12x)
	defOp(OP_REM_LONG_2ADDR, "rem-long/2addr", F12x)
	defOp(OP_AND_LONG_2ADDR, "and-long/2addr", F12x)
	defOp(OP_OR_LONG_2ADDR, "or-long/2addr", F12x)
	defOp(OP_XOR_LONG_2ADDR, "xor-long/2addr", F12x)
	defOp(OP_SHL_LONG_2ADDR, "shl-long/2addr", F12x)
	defOp(OP_SHR_LONG_2ADDR, "shr-long/2addr", F12x)
	defOp(OP_USHR_LONG_2ADDR, "ushr-long/2addr", F12x)
	defOp(OP_ADD_FLOAT_2ADDR, "add-float/2addr", F12x)
	defOp(OP_SUB_FLOAT_2ADDR, "sub-float/2addr", F12x)
	defOp(OP_MUL_FLOAT_2ADDR, "mul-float/2addr", F12x)
	defOp(OP_DIV_FLOAT_2ADDR, "div-float/2addr", F12x)
	defOp(OP_REM_FLOAT_2ADDR, "rem-float/2addr", F12x)
	defOp(OP_ADD_DOUBLE_2ADDR, "add-double/2addr", F12x)
	defOp(OP_SUB_DOUBLE_2ADDR, "sub-double/2addr", F12x)
	defOp(OP_MUL_DOUBLE_2ADDR, "mul-double/2addr", F12x)
	defOp(OP_DIV_DOUBLE_2ADDR, "div-double/2addr", F12x)
	defOp(OP_REM_DOUBLE_2ADDR, "rem-double/2addr", F12x)
	defOp(OP_ADD_INT_LIT8, "add-int/lit8", F22b)
	defOp(OP_RSUB_INT_LIT8, "rsub-int/lit8", F22b)
	defOp(OP_MUL_INT_LIT8, "mul-int/lit8", F22b)
	defOp(OP_DIV_INT_LIT8, "div-int/lit8", F22b)
	defOp(OP_REM_INT_LIT8, "rem-int/lit8", F22b)
	defOp(OP_AND_INT_LIT8, "and-int/lit8", F22b)
	defOp(OP_OR_INT_LIT8, "or-int/lit8", F22b)
	defOp(OP_XOR_INT_LIT8, "xor-int/lit8", F22b)
	defOp(OP_SHL_INT_LIT8, "shl-int/lit8", F22b)
	defOp(OP_SHR_INT_LIT8, "shr-int/lit8", F22b)
	defOp(OP_USHR_INT_LIT8, "ushr-int/lit8", F22b)
	defOp(OP_ADD_INT_LIT16, "add-int/lit16", F22s)
	defOp(OP_RSUB_INT, "rsub-int", F22s)
	defOp(OP_MUL_INT_LIT16, "mul-int/lit16", F22s)
	defOp(OP_DIV_INT_LIT16, "div-int/lit16", F22s)
	defOp(OP_REM_INT_LIT16, "rem-int/lit16", F22s)
	defOp(OP_AND_INT_LIT16, "and-int/lit16", F22s)
	defOp(OP_OR_INT_LIT16, "or-int/lit16", F22s)
	defOp(OP_XOR_INT_LIT16, "xor-int/lit16", F22s)

	defOp(OP_INVOKE_POLYMORPHIC, "invoke-polymorphic", F45cc)
	defOp(OP_INVOKE_POLYMORPHIC_RANGE, "invoke-polymorphic/range", F4rcc)
	defOp(OP_INVOKE_CUSTOM, "invoke-custom", F35c)
	defOp(OP_INVOKE_CUSTOM_RANGE, "invoke-custom/range", F3rc)
	defOp(OP_CONST_METHOD_HANDLE, "const-method-handle", F21c)
	defOp(OP_CONST_METHOD_TYPE, "const-method-type", F21c)
}

// OpcodeName returns the name of a Dalvik opcode.
func OpcodeName(op byte) string {
	if name := opNames[op]; name != "" {
		return name
	}
	return "unknown"
}

// OpcodeFormat returns the encoding format of a Dalvik opcode.
func OpcodeFormat(op byte) Format { return opFormats[op] }

// SwitchPayload is the decoded payload of a packed-switch or sparse-switch.
type SwitchPayload struct {
	Packed   bool
	FirstKey int32
	Keys     []int32 // sparse only
	Targets  []int32 // relative to the switch instruction
}

// ArrayData is the decoded payload of a fill-array-data instruction.
type ArrayData struct {
	ElementWidth int
	Elements     []uint64
}

// Instruction is a decoded Dalvik instruction.
type Instruction struct {
	Offset int // code-unit offset from the start of the method's insns
	Size   int // size in code units
	Op     byte
	Name   string
	Format Format

	A, B, C, D, E, F, G int // register operands / counts, format-dependent
	Literal             int64
	Ref                 uint32 // string/type/field/method index
	Ref2                uint32 // secondary reference (proto index for 45cc/4rcc)
	Target              int    // absolute code-unit branch target
	Regs                []int  // register list for 35c/3rc formats
	Switch              *SwitchPayload
	ArrayData           *ArrayData
}

func readU16(code []byte, unit int) uint16 {
	i := unit * 2
	if i < 0 || i+2 > len(code) {
		return 0
	}
	return uint16(code[i]) | uint16(code[i+1])<<8
}

func readU32(code []byte, unit int) uint32 {
	i := unit * 2
	if i < 0 || i+4 > len(code) {
		return 0
	}
	return uint32(code[i]) | uint32(code[i+1])<<8 | uint32(code[i+2])<<16 | uint32(code[i+3])<<24
}

func readU64(code []byte, unit int) uint64 {
	i := unit * 2
	if i < 0 || i+8 > len(code) {
		return 0
	}
	var v uint64
	for k := 0; k < 8; k++ {
		v |= uint64(code[i+k]) << (8 * k)
	}
	return v
}

// DecodeInstructions decodes a method's bytecode (raw bytes, little-endian
// code units) into instructions. Pseudo-instructions (switch and
// fill-array-data payloads) are skipped but attached to the instruction that
// references them.
func DecodeInstructions(code []byte) []Instruction {
	insns, _ := decodeInstructions(code)
	return insns
}

// decodeInstructions also reports how many code units were consumed,
// including skipped payloads.
func decodeInstructions(code []byte) ([]Instruction, int) {
	return decodeInstructionsMode(code, false, 0)
}

// decodeInstructionsFor decodes a method body, falling back to the compact
// 23x encoding some packers emit when the standard decoding either
// overruns the instruction stream or references registers outside the
// method's register file.
func decodeInstructionsFor(code []byte, registersSize int) ([]Instruction, int) {
	insns, consumed := decodeInstructionsMode(code, false, registersSize)
	if consumed == len(code)/2 && registersInRange(insns, registersSize) {
		return insns, consumed
	}
	if registersSize > 0 {
		compact, compactConsumed := decodeInstructionsMode(code, true, registersSize)
		if compactConsumed == len(code)/2 && registersInRange(compact, registersSize) {
			return compact, compactConsumed
		}
	}
	return insns, consumed
}

// registersInRange reports whether every instruction's register operands fit
// in a method with registersSize registers (0 disables the check).
func registersInRange(insns []Instruction, registersSize int) bool {
	if registersSize <= 0 {
		return true
	}
	for i := range insns {
		if maxRegister(&insns[i]) >= registersSize {
			return false
		}
	}
	return true
}

// maxRegister returns the highest register index referenced by an
// instruction, or -1 if it references none.
func maxRegister(inst *Instruction) int {
	max := -1
	reg := func(r int) {
		if r > max {
			max = r
		}
	}
	switch inst.Format {
	case F10x, F10t, F30t:
		// no registers
	case F12x, F11n, F22b, F22c, F22s, F22t, F11x:
		reg(inst.A)
		reg(inst.B)
	case F21c, F21ih, F21lh, F21s, F21t, F31c, F31i, F31t, F51l:
		reg(inst.A)
	case F22x, F32x:
		reg(inst.A)
		reg(inst.B)
	case F23x:
		reg(inst.A)
		reg(inst.B)
		reg(inst.C)
	case F35c, F45cc:
		for _, r := range inst.Regs {
			reg(r)
		}
	case F3rc, F4rcc:
		for _, r := range inst.Regs {
			reg(r)
		}
	}
	return max
}

func decodeInstructionsMode(code []byte, compact23x bool, registersSize int) ([]Instruction, int) {
	payloads := make(map[int]*SwitchPayload)
	arrays := make(map[int]*ArrayData)

	// payloadKind records offsets that a preceding 31t instruction points
	// at. Only those offsets are pseudo-instructions; matching units
	// elsewhere (e.g. a nop encoded as 0x0100) are real instructions.
	payloadKind := make(map[int]byte)

	n := len(code) / 2
	out := make([]Instruction, 0, n)
	consumed := 0

	for off := 0; off < n; {
		if kind, ok := payloadKind[off]; ok {
			delete(payloadKind, off)
			var size int
			switch kind {
			case OP_FILL_ARRAY_DATA:
				a, s := parseArrayPayload(code, off)
				arrays[off] = a
				size = s
			default:
				p, s := parseSwitchPayload(code, off)
				payloads[off] = p
				size = s
			}
			if size <= 0 {
				size = 1
			}
			if off+size > n {
				size = n - off
			}
			off += size
			consumed += size
			continue
		}

		inst := decodeInstructionMode(code, off, compact23x)
		if inst.Size <= 0 {
			inst.Size = 1
		}
		if off+inst.Size > n {
			// Truncated instruction: stop rather than read past the end.
			consumed = n
			break
		}
		switch inst.Op {
		case OP_PACKED_SWITCH, OP_SPARSE_SWITCH, OP_FILL_ARRAY_DATA:
			if inst.Target > off && inst.Target < n {
				payloadKind[inst.Target] = inst.Op
			}
		}
		out = append(out, inst)
		off += inst.Size
		consumed += inst.Size
	}

	// Attach payloads to the instructions that reference them.
	for i := range out {
		inst := &out[i]
		switch inst.Op {
		case OP_PACKED_SWITCH, OP_SPARSE_SWITCH:
			if p, ok := payloads[inst.Target]; ok {
				inst.Switch = p
			}
		case OP_FILL_ARRAY_DATA:
			if a, ok := arrays[inst.Target]; ok {
				inst.ArrayData = a
			}
		}
	}

	return out, consumed
}

func decodeInstruction(code []byte, off int) Instruction {
	return decodeInstructionMode(code, off, false)
}

func decodeInstructionMode(code []byte, off int, compact23x bool) Instruction {
	unit := readU16(code, off)
	op := byte(unit)
	inst := Instruction{
		Offset: off,
		Op:     op,
		Name:   OpcodeName(op),
		Format: opFormats[op],
	}

	switch inst.Format {
	case F10x:
		inst.Size = 1

	case F12x:
		inst.Size = 1
		inst.A = int((unit >> 8) & 0xf)
		inst.B = int((unit >> 12) & 0xf)

	case F11x:
		inst.Size = 1
		inst.A = int((unit >> 8) & 0xff)

	case F11n:
		inst.Size = 1
		inst.A = int((unit >> 8) & 0xf)
		lit := int(unit>>12) & 0xf
		if lit >= 8 {
			lit -= 16
		}
		inst.Literal = int64(lit)

	case F10t:
		inst.Size = 1
		inst.Target = off + int(int8(unit>>8))

	case F20t:
		inst.Size = 2
		inst.Target = off + int(int16(readU16(code, off+1)))

	case F22x:
		inst.Size = 2
		inst.A = int(unit >> 8)
		inst.B = int(readU16(code, off+1))

	case F21c:
		inst.Size = 2
		inst.A = int(unit >> 8)
		inst.Ref = uint32(readU16(code, off+1))

	case F21ih:
		inst.Size = 2
		inst.A = int(unit >> 8)
		inst.Literal = int64(int32(int16(readU16(code, off+1))) << 16)

	case F21lh:
		inst.Size = 2
		inst.A = int(unit >> 8)
		inst.Literal = int64(int16(readU16(code, off+1))) << 48

	case F21s:
		inst.Size = 2
		inst.A = int(unit >> 8)
		inst.Literal = int64(int16(readU16(code, off+1)))

	case F21t:
		inst.Size = 2
		inst.A = int(unit >> 8)
		inst.Target = off + int(int16(readU16(code, off+1)))

	case F22b:
		inst.Size = 2
		inst.A = int(unit >> 8)
		i := off * 2
		if i+4 <= len(code) {
			inst.B = int(code[i+2])
			inst.Literal = int64(int8(code[i+3]))
		}

	case F22c:
		inst.Size = 2
		inst.A = int((unit >> 8) & 0xf)
		inst.B = int((unit >> 12) & 0xf)
		inst.Ref = uint32(readU16(code, off+1))

	case F22s:
		inst.Size = 2
		inst.A = int((unit >> 8) & 0xf)
		inst.B = int((unit >> 12) & 0xf)
		inst.Literal = int64(int16(readU16(code, off+1)))

	case F22t:
		inst.Size = 2
		inst.A = int((unit >> 8) & 0xf)
		inst.B = int((unit >> 12) & 0xf)
		inst.Target = off + int(int16(readU16(code, off+1)))

	case F23x:
		if compact23x {
			// Some packers rewrite 23x instructions into a compact
			// 4-byte form with 8-bit register operands:
			// op AA BB CC.
			inst.Size = 2
			inst.A = int(unit >> 8)
			i := off * 2
			if i+4 <= len(code) {
				inst.B = int(code[i+2])
				inst.C = int(code[i+3])
			}
			break
		}
		inst.Size = 3
		inst.A = int(unit >> 8)
		inst.B = int(readU16(code, off+1))
		inst.C = int(readU16(code, off+2))

	case F30t:
		inst.Size = 3
		inst.Target = off + int(int32(readU32(code, off+1)))

	case F31c:
		inst.Size = 3
		inst.A = int(unit >> 8)
		inst.Ref = readU32(code, off+1)

	case F31i:
		inst.Size = 3
		inst.A = int(unit >> 8)
		inst.Literal = int64(int32(readU32(code, off+1)))

	case F31t:
		inst.Size = 3
		inst.A = int(unit >> 8)
		inst.Target = off + int(int32(readU32(code, off+1)))

	case F32x:
		inst.Size = 3
		inst.A = int(readU16(code, off+1))
		inst.B = int(readU16(code, off+2))

	case F35c:
		inst.Size = 3
		inst.A = int((unit >> 12) & 0xf) // argument word count
		inst.G = int((unit >> 8) & 0xf)
		inst.Ref = uint32(readU16(code, off+1))
		third := readU16(code, off+2)
		inst.C = int(third & 0xf)
		inst.D = int((third >> 4) & 0xf)
		inst.E = int((third >> 8) & 0xf)
		inst.F = int((third >> 12) & 0xf)
		regs := []int{inst.C, inst.D, inst.E, inst.F}
		if inst.A == 5 {
			regs = append(regs, inst.G)
		}
		if inst.A < len(regs) {
			regs = regs[:inst.A]
		}
		inst.Regs = regs

	case F3rc:
		inst.Size = 3
		inst.A = int(unit >> 8) // argument word count
		inst.Ref = uint32(readU16(code, off+1))
		inst.C = int(readU16(code, off+2))
		regs := make([]int, 0, inst.A)
		for i := 0; i < inst.A; i++ {
			regs = append(regs, inst.C+i)
		}
		inst.Regs = regs

	case F51l:
		inst.Size = 5
		inst.A = int(unit >> 8)
		inst.Literal = int64(readU64(code, off+1))

	case F45cc:
		inst.Size = 4
		inst.A = int((unit >> 12) & 0xf)
		inst.G = int((unit >> 8) & 0xf)
		inst.Ref = uint32(readU16(code, off+1))
		third := readU16(code, off+2)
		inst.C = int(third & 0xf)
		inst.D = int((third >> 4) & 0xf)
		inst.E = int((third >> 8) & 0xf)
		inst.F = int((third >> 12) & 0xf)
		inst.Ref2 = uint32(readU16(code, off+3))
		regs := []int{inst.C, inst.D, inst.E, inst.F}
		if inst.A == 5 {
			regs = append(regs, inst.G)
		}
		if inst.A < len(regs) {
			regs = regs[:inst.A]
		}
		inst.Regs = regs

	case F4rcc:
		inst.Size = 4
		inst.A = int(unit >> 8)
		inst.Ref = uint32(readU16(code, off+1))
		inst.C = int(readU16(code, off+2))
		inst.Ref2 = uint32(readU16(code, off+3))
		regs := make([]int, 0, inst.A)
		for i := 0; i < inst.A; i++ {
			regs = append(regs, inst.C+i)
		}
		inst.Regs = regs

	default:
		// Unknown/optimized opcode: skip a single code unit so we don't
		// lose sync with the rest of the stream.
		inst.Size = 1
		inst.Name = "unknown"
	}

	return inst
}

// parseSwitchPayload decodes a packed-switch or sparse-switch payload,
// returning it and its size in code units.
func parseSwitchPayload(code []byte, off int) (*SwitchPayload, int) {
	ident := readU16(code, off)
	size := int(readU16(code, off+1))
	if size < 0 || size > 1<<20 {
		size = 0
	}

	if ident == pseudoPackedSwitch {
		p := &SwitchPayload{Packed: true, FirstKey: int32(readU32(code, off+2))}
		p.Targets = make([]int32, size)
		for i := 0; i < size; i++ {
			p.Targets[i] = int32(readU32(code, off+4+i*2))
		}
		return p, 4 + size*2
	}

	// sparse-switch: keys then targets
	p := &SwitchPayload{}
	p.Keys = make([]int32, size)
	p.Targets = make([]int32, size)
	for i := 0; i < size; i++ {
		p.Keys[i] = int32(readU32(code, off+2+i*2))
	}
	base := off + 2 + size*2
	for i := 0; i < size; i++ {
		p.Targets[i] = int32(readU32(code, base+i*2))
	}
	return p, 2 + size*4
}

// parseArrayPayload decodes a fill-array-data payload, returning it and its
// size in code units.
func parseArrayPayload(code []byte, off int) (*ArrayData, int) {
	width := int(readU16(code, off+1))
	size := int(readU32(code, off+2))
	if size < 0 || size > 1<<20 {
		size = 0
	}
	if width <= 0 || width > 8 {
		width = 1
	}

	a := &ArrayData{ElementWidth: width}
	if size > 0 {
		a.Elements = make([]uint64, size)
		base := off*2 + 8
		for i := 0; i < size; i++ {
			start := base + i*width
			if start+width > len(code) {
				break
			}
			var v uint64
			for k := 0; k < width; k++ {
				v |= uint64(code[start+k]) << (8 * k)
			}
			a.Elements[i] = v
		}
	}

	dataUnits := (size*width + 1) / 2
	return a, 4 + dataUnits
}
