package native

/*
#cgo CFLAGS: -I${SRCDIR}/../../third_party/capstone/../../capstone-6.0.0-Alpha10/include -DCAPSTONE_AARCH64_COMPAT_HEADER
#cgo LDFLAGS: -L${SRCDIR}/../../third_party/capstone/build -lcapstone
#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// Version-stable accessors around Capstone structs. Go never performs
// arithmetic on cs_insn or indexes it; every read of a Capstone struct
// happens here, compiled against whatever header libcapstone was built
// from. If Capstone's layout changes, only this block changes - the
// Go-visible ABI (scalars + ds_arm64_operand) stays fixed.
//
// All functions validate (insns != NULL, i < count) before touching memory.

static bool ds_insn_address(const cs_insn *insns, size_t count, size_t i,
                            uint64_t *out) {
    if (!insns || i >= count || !out)
        return false;
    *out = insns[i].address;
    return true;
}

static bool ds_insn_size(const cs_insn *insns, size_t count, size_t i,
                         uint16_t *out) {
    if (!insns || i >= count || !out)
        return false;
    *out = insns[i].size;
    return true;
}

// Bounded copy from a fixed-size char[] field; the copy is limited by both
// the real field size (sizeof, evaluated here) and the caller's cap, and is
// always NUL-terminated.
static bool ds_copy_cstr(const char *src, size_t src_cap, char *out,
                         size_t cap, size_t *out_len) {
    size_t n;
    if (!src || !out || cap == 0)
        return false;
    n = strnlen(src, src_cap);
    if (n > cap - 1)
        n = cap - 1;
    memcpy(out, src, n);
    out[n] = '\0';
    if (out_len)
        *out_len = n;
    return true;
}

static bool ds_insn_mnemonic(const cs_insn *insns, size_t count, size_t i,
                             char *out, size_t cap, size_t *out_len) {
    if (!insns || i >= count)
        return false;
    return ds_copy_cstr(insns[i].mnemonic, sizeof(insns[i].mnemonic), out, cap,
                        out_len);
}

static bool ds_insn_op_str(const cs_insn *insns, size_t count, size_t i,
                           char *out, size_t cap, size_t *out_len) {
    if (!insns || i >= count)
        return false;
    return ds_copy_cstr(insns[i].op_str, sizeof(insns[i].op_str), out, cap,
                        out_len);
}

static bool ds_insn_bytes(const cs_insn *insns, size_t count, size_t i,
                          uint8_t *out, size_t cap, size_t *out_len) {
    size_t n;
    if (!insns || i >= count || (!out && cap > 0))
        return false;
    n = insns[i].size;
    if (n > sizeof(insns[i].bytes))
        n = sizeof(insns[i].bytes);
    if (n > cap)
        n = cap;
    if (n && out)
        memcpy(out, insns[i].bytes, n);
    if (out_len)
        *out_len = n;
    return true;
}

// ARM64 detail. The arch union member is named arm64 under Capstone's
// AArch64 compatibility header and aarch64 otherwise; handle both so this
// block does not depend on -DCAPSTONE_AARCH64_COMPAT_HEADER.
#ifdef CAPSTONE_AARCH64_COMPAT_HEADER
#define ds_arm64_detail(det) (&(det)->arm64)
#else
#define ds_arm64_detail(det) (&(det)->aarch64)
#endif

static bool ds_insn_has_detail(const cs_insn *insns, size_t count, size_t i,
                               bool *out) {
    if (!insns || i >= count || !out)
        return false;
    *out = insns[i].detail != NULL;
    return true;
}

static bool ds_insn_arm64_update_flags(const cs_insn *insns, size_t count,
                                       size_t i, bool *out) {
    const cs_detail *det;
    if (!insns || i >= count || !out)
        return false;
    det = insns[i].detail;
    if (!det)
        return false;
    *out = ds_arm64_detail(det)->update_flags;
    return true;
}

static bool ds_insn_arm64_op_count(const cs_insn *insns, size_t count,
                                   size_t i, uint8_t *out) {
    const cs_detail *det;
    uint8_t n;
    if (!insns || i >= count || !out)
        return false;
    det = insns[i].detail;
    if (!det)
        return false;
    n = ds_arm64_detail(det)->op_count;
    if (n > NUM_AARCH64_OPS)
        n = NUM_AARCH64_OPS;
    *out = n;
    return true;
}

// Operand layout owned by DeStruct; independent of cs_arm64_op /
// aarch64_op_mem and of cgo's generated representation of the anonymous
// union (formerly reached as op.anon0 in Go).
typedef struct ds_arm64_operand {
    int32_t op_type;   // ARM64_OP_* discriminator (0 == invalid)
    int32_t reg;       // ARM64_OP_REG
    int64_t imm;       // ARM64_OP_IMM
    double fp;         // ARM64_OP_FP
    int32_t mem_base;  // ARM64_OP_MEM
    int32_t mem_index; // ARM64_OP_MEM
    int64_t mem_disp;  // ARM64_OP_MEM
} ds_arm64_operand;

static bool ds_insn_arm64_operand(const cs_insn *insns, size_t count,
                                  size_t i, size_t j, ds_arm64_operand *out) {
    const cs_detail *det;
    const cs_aarch64 *a64;
    const cs_aarch64_op *op;
    if (!insns || i >= count || !out)
        return false;
    det = insns[i].detail;
    if (!det)
        return false;
    a64 = ds_arm64_detail(det);
    if (j >= (size_t)a64->op_count || j >= NUM_AARCH64_OPS)
        return false;
    op = &a64->operands[j];
    memset(out, 0, sizeof(*out));
    out->op_type = (int32_t)op->type;
    switch (op->type) {
    case AARCH64_OP_REG:
        out->reg = (int32_t)op->reg;
        break;
    case AARCH64_OP_IMM:
        out->imm = op->imm;
        break;
    case AARCH64_OP_FP:
        out->fp = op->fp;
        break;
    case AARCH64_OP_MEM:
        out->mem_base = (int32_t)op->mem.base;
        out->mem_index = (int32_t)op->mem.index;
        out->mem_disp = op->mem.disp;
        break;
    default:
        break;
    }
    return true;
}

// Idempotent close: no-op for NULL or already-zeroed handles; forces
// *handle back to 0 after cs_close so a stale handle can never reach a
// freed struct. Callers serialize against concurrent use.
static cs_err ds_close(csh *handle) {
    cs_err err;
    if (handle == NULL || *handle == 0)
        return CS_ERR_OK;
    err = cs_close(handle);
    *handle = 0;
    return err;
}
*/
import "C"
import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// Buffer sizes for reading C strings/byte arrays out of a cs_insn. They are
// deliberately larger than Capstone 6's fields (mnemonic 32, op_str 160,
// bytes 24); the C helpers clamp to the real field size via sizeof and
// return the exact byte count, so over-sized Go buffers are safe. If a
// future Capstone grows a field past these, the copy truncates rather than
// reading out of bounds.
const (
	maxMnemonicBytes  = 64
	maxOpStrBytes     = 256
	maxInstructionLen = 64
)

// errDisassemblerClosed is returned by Disassemble/DisassembleDetailed when
// the underlying Capstone handle has already been released by Close.
var errDisassemblerClosed = errors.New("native: disassembler is closed")

// Disassembler wraps Capstone's disassembly engine.
//
// Thread safety: a single *Disassembler serializes Disassemble,
// DisassembleDetailed and Close internally, so those methods may be called
// from multiple goroutines without external locking. This is deliberate:
// Capstone handles are not safe to share between threads - cs_disasm and
// cs_option mutate per-handle state (last error, instruction cache, detail
// flag), so the engine expects one handle per concurrent user. The internal
// lock supplies that serialization. For parallel lifting, prefer one
// Disassembler per goroutine over sharing one. Values returned by
// Disassemble/DisassembleDetailed are Go copies and are safe to read
// concurrently once returned.
type Disassembler struct {
	mu     sync.Mutex
	handle C.csh
	arch   int
	mode   int
	closed bool
}

// Instruction represents a disassembled instruction
type Instruction struct {
	Address  uint64
	Size     uint32
	Mnemonic string
	OpStr    string
	Bytes    []byte
}

// OperandType identifies what kind of value an Operand holds.
type OperandType int

const (
	OperandInvalid OperandType = iota
	OperandReg
	OperandImm
	OperandMem
	OperandFP
)

// MemOperand is a memory-addressing operand: [base, index, #disp] (ARM64
// syntax "[base, index]" or "[base, #disp]" - Index and Disp are
// mutually exclusive in practice for the instructions a lifter cares
// about, but both are exposed since Capstone always populates both
// fields).
type MemOperand struct {
	Base  string // register name, e.g. "sp", "x0" ("" if none)
	Index string // register name for register-indexed addressing ("" if none)
	Disp  int32  // constant displacement, e.g. the 12 in "[sp, #12]"
}

// Operand is one structured instruction operand - exactly one of Reg,
// Imm, Mem, or FP is meaningful, per Type.
type Operand struct {
	Type OperandType
	Reg  string     // register name, e.g. "w0", "x1", "sp" (Type == OperandReg)
	Imm  int64      // immediate value (Type == OperandImm)
	Mem  MemOperand // memory operand (Type == OperandMem)
	FP   float64    // floating-point immediate (Type == OperandFP)
}

// DetailedInstruction is an Instruction plus its structured operands -
// what an actual instruction lifter needs, as opposed to Instruction's
// plain Mnemonic/OpStr text (kept separate, and Instruction/Disassemble/
// DisassembleAll unchanged, so existing callers like the ELF text
// listing aren't affected by turning on Capstone's detail mode, which
// has a small but real performance cost).
type DetailedInstruction struct {
	Address  uint64
	Size     uint32
	Mnemonic string
	OpStr    string
	Bytes    []byte
	Operands []Operand
	// WritesFlags is true if this instruction updates the condition
	// flags (NZCV) - needed to know whether a following b.cond/csel/etc.
	// is testing the result of THIS instruction or something earlier.
	WritesFlags bool
}

// NewDisassembler creates a new Capstone disassembler for the given architecture
func NewDisassembler(arch, mode int) (*Disassembler, error) {
	var handle C.csh
	ret := C.cs_open(C.cs_arch(arch), C.cs_mode(mode), &handle)
	if ret != C.CS_ERR_OK {
		return nil, fmt.Errorf("cs_open failed: %v", C.GoString(C.cs_strerror(ret)))
	}

	return &Disassembler{
		handle: handle,
		arch:   arch,
		mode:   mode,
	}, nil
}

// Close releases the underlying Capstone handle. It is idempotent: calling
// it more than once, on a zero-value Disassembler, or on a nil receiver is
// safe and does nothing after the first call. Close serializes with
// in-flight Disassemble/DisassembleDetailed calls, so once it returns no
// further work is running on the handle.
func (d *Disassembler) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	C.ds_close(&d.handle)
}

// insnCommon holds the fields shared by Instruction and
// DetailedInstruction, read through the version-stable C accessors.
type insnCommon struct {
	Address  uint64
	Size     uint32
	Mnemonic string
	OpStr    string
	Bytes    []byte
}

// readInsnCommon copies instruction i's text/bytes fields out of the
// cs_disasm result. All bounds checks happen in C; a failure here means the
// C helper rejected the index, which indicates a lost invariant rather than
// bad input.
func readInsnCommon(insns *C.cs_insn, count C.size_t, i C.size_t) (insnCommon, error) {
	var (
		addr C.uint64_t
		size C.uint16_t
		mnem [maxMnemonicBytes]C.char
		op   [maxOpStrBytes]C.char
		raw  [maxInstructionLen]C.uint8_t
		mlen C.size_t
		olen C.size_t
		blen C.size_t
	)
	if !C.ds_insn_address(insns, count, i, &addr) {
		return insnCommon{}, fmt.Errorf("disasm: address read failed at instruction %d", int(i))
	}
	if !C.ds_insn_size(insns, count, i, &size) {
		return insnCommon{}, fmt.Errorf("disasm: size read failed at instruction %d", int(i))
	}
	if !C.ds_insn_mnemonic(insns, count, i, &mnem[0], C.size_t(len(mnem)), &mlen) {
		return insnCommon{}, fmt.Errorf("disasm: mnemonic read failed at instruction %d", int(i))
	}
	if !C.ds_insn_op_str(insns, count, i, &op[0], C.size_t(len(op)), &olen) {
		return insnCommon{}, fmt.Errorf("disasm: op_str read failed at instruction %d", int(i))
	}
	if !C.ds_insn_bytes(insns, count, i, &raw[0], C.size_t(len(raw)), &blen) {
		return insnCommon{}, fmt.Errorf("disasm: bytes read failed at instruction %d", int(i))
	}
	return insnCommon{
		Address:  uint64(addr),
		Size:     uint32(size),
		Mnemonic: C.GoStringN(&mnem[0], C.int(mlen)),
		OpStr:    C.GoStringN(&op[0], C.int(olen)),
		Bytes:    C.GoBytes(unsafe.Pointer(&raw[0]), C.int(blen)),
	}, nil
}

// Disassemble disassembles the given code bytes
func (d *Disassembler) Disassemble(code []byte, address uint64, count int) ([]Instruction, error) {
	if d == nil {
		return nil, errDisassemblerClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errDisassemblerClosed
	}
	if len(code) == 0 {
		return nil, nil
	}

	var insn *C.cs_insn
	cCode := (*C.uint8_t)(unsafe.Pointer(&code[0]))
	n := C.cs_disasm(d.handle, cCode, C.size_t(len(code)), C.uint64_t(address), C.size_t(count), &insn)
	if n == 0 {
		errCode := C.cs_errno(d.handle)
		if errCode != C.CS_ERR_OK {
			return nil, fmt.Errorf("cs_disasm failed: %v", C.GoString(C.cs_strerror(errCode)))
		}
		return nil, nil
	}
	defer C.cs_free(insn, n)

	result := make([]Instruction, int(n))
	for i := 0; i < int(n); i++ {
		common, err := readInsnCommon(insn, n, C.size_t(i))
		if err != nil {
			return nil, err
		}
		result[i] = Instruction{
			Address:  common.Address,
			Size:     common.Size,
			Mnemonic: common.Mnemonic,
			OpStr:    common.OpStr,
			Bytes:    common.Bytes,
		}
	}
	return result, nil
}

// DisassembleDetailed disassembles code with Capstone's detail mode
// enabled, returning structured operands (register/immediate/memory)
// instead of only text - what an actual instruction lifter needs.
// Currently only implemented for ARM64; calling this on a Disassembler
// configured for another architecture returns an error.
//
// Like the other methods, it is serialized against Close and concurrent
// disassembly on the same Disassembler.
func (d *Disassembler) DisassembleDetailed(code []byte, address uint64) ([]DetailedInstruction, error) {
	if d == nil {
		return nil, errDisassemblerClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errDisassemblerClosed
	}
	if len(code) == 0 {
		return nil, nil
	}
	if d.arch != ArchARM64 {
		return nil, fmt.Errorf("DisassembleDetailed: only ARM64 is currently supported")
	}

	// NOTE: Capstone 6.0.0-Alpha10 implements CS_OPT_DETAIL as
	// `handle->detail_opt |= value` (cs.c), so CS_OPT_OFF (0) below is a
	// no-op: once enabled, detail mode stays on for this handle. Kept as-is
	// deliberately; decision tracked in TODOS.md.
	if ret := C.cs_option(d.handle, C.CS_OPT_DETAIL, C.CS_OPT_ON); ret != C.CS_ERR_OK {
		return nil, fmt.Errorf("cs_option(CS_OPT_DETAIL) failed: %v", C.GoString(C.cs_strerror(ret)))
	}
	defer C.cs_option(d.handle, C.CS_OPT_DETAIL, C.CS_OPT_OFF)

	var insn *C.cs_insn
	cCode := (*C.uint8_t)(unsafe.Pointer(&code[0]))
	n := C.cs_disasm(d.handle, cCode, C.size_t(len(code)), C.uint64_t(address), C.size_t(0), &insn)
	if n == 0 {
		errCode := C.cs_errno(d.handle)
		if errCode != C.CS_ERR_OK {
			return nil, fmt.Errorf("cs_disasm failed: %v", C.GoString(C.cs_strerror(errCode)))
		}
		return nil, nil
	}
	defer C.cs_free(insn, n)

	result := make([]DetailedInstruction, int(n))
	for i := 0; i < int(n); i++ {
		common, err := readInsnCommon(insn, n, C.size_t(i))
		if err != nil {
			return nil, err
		}
		di := DetailedInstruction{
			Address:  common.Address,
			Size:     common.Size,
			Mnemonic: common.Mnemonic,
			OpStr:    common.OpStr,
			Bytes:    common.Bytes,
		}

		var hasDetail C.bool
		if !C.ds_insn_has_detail(insn, n, C.size_t(i), &hasDetail) {
			return nil, fmt.Errorf("disasm: detail probe failed at instruction %d", i)
		}
		if bool(hasDetail) {
			var updateFlags C.bool
			if !C.ds_insn_arm64_update_flags(insn, n, C.size_t(i), &updateFlags) {
				return nil, fmt.Errorf("disasm: update_flags read failed at instruction %d", i)
			}
			di.WritesFlags = bool(updateFlags)

			var opCount C.uint8_t
			if !C.ds_insn_arm64_op_count(insn, n, C.size_t(i), &opCount) {
				return nil, fmt.Errorf("disasm: op_count read failed at instruction %d", i)
			}
			di.Operands = make([]Operand, int(opCount))
			for j := 0; j < int(opCount); j++ {
				var op C.ds_arm64_operand
				if !C.ds_insn_arm64_operand(insn, n, C.size_t(i), C.size_t(j), &op) {
					return nil, fmt.Errorf("disasm: operand %d read failed at instruction %d", j, i)
				}
				di.Operands[j] = convertARM64Operand(d.handle, op)
			}
		}

		result[i] = di
	}

	return result, nil
}

// convertARM64Operand translates one ARM64 operand - already copied into our
// version-stable ds_arm64_operand layout by ds_insn_arm64_operand - into the
// architecture-neutral Operand type.
func convertARM64Operand(handle C.csh, op C.ds_arm64_operand) Operand {
	switch op.op_type {
	case C.ARM64_OP_REG:
		return Operand{Type: OperandReg, Reg: regName(handle, C.uint(op.reg))}
	case C.ARM64_OP_IMM:
		return Operand{Type: OperandImm, Imm: int64(op.imm)}
	case C.ARM64_OP_FP:
		return Operand{Type: OperandFP, FP: float64(op.fp)}
	case C.ARM64_OP_MEM:
		m := MemOperand{Disp: int32(op.mem_disp)}
		if op.mem_base != C.ARM64_REG_INVALID {
			m.Base = regName(handle, C.uint(op.mem_base))
		}
		if op.mem_index != C.ARM64_REG_INVALID {
			m.Index = regName(handle, C.uint(op.mem_index))
		}
		return Operand{Type: OperandMem, Mem: m}
	default:
		return Operand{Type: OperandInvalid}
	}
}

func regName(handle C.csh, reg C.uint) string {
	if reg == 0 {
		return ""
	}
	cName := C.cs_reg_name(handle, reg)
	if cName == nil {
		return ""
	}
	return C.GoString(cName)
}

// Architecture constants
const (
	ArchARM   = int(C.CS_ARCH_ARM)
	ArchARM64 = int(C.CS_ARCH_ARM64)
	ArchX86   = int(C.CS_ARCH_X86)
	ArchMIPS  = int(C.CS_ARCH_MIPS)
)

// Mode constants
const (
	ModeARM           = int(C.CS_MODE_ARM)
	ModeTHUMB         = int(C.CS_MODE_THUMB)
	ModeARM64         = int(C.CS_MODE_ARM)
	Mode32            = int(C.CS_MODE_32)
	Mode64            = int(C.CS_MODE_64)
	ModeLITTLE_ENDIAN = int(C.CS_MODE_LITTLE_ENDIAN)
)

// NewDisassemblerForMachine returns a Capstone disassembler for the
// ELF machine type. It covers the architectures DeStruct's ELF parser
// already recognizes (ARM, AArch64, x86, x86-64).
func NewDisassemblerForMachine(machine uint16) (*Disassembler, error) {
	switch machine {
	case EM_AARCH64:
		return NewARM64Disassembler()
	case EM_ARM:
		return NewARMDisassembler()
	case EM_386:
		return NewX86_32Disassembler()
	case EM_X86_64:
		return NewX86_64Disassembler()
	default:
		return nil, fmt.Errorf("unsupported machine type: %d", machine)
	}
}

// NewARM64Disassembler creates a disassembler for ARM64
func NewARM64Disassembler() (*Disassembler, error) {
	return NewDisassembler(ArchARM64, ModeARM64|ModeLITTLE_ENDIAN)
}

// NewARMDisassembler creates a disassembler for ARM (32-bit)
func NewARMDisassembler() (*Disassembler, error) {
	return NewDisassembler(ArchARM, ModeARM|ModeLITTLE_ENDIAN)
}

// NewThumbDisassembler creates a disassembler for ARM Thumb mode
func NewThumbDisassembler() (*Disassembler, error) {
	return NewDisassembler(ArchARM, ModeTHUMB|ModeLITTLE_ENDIAN)
}

// NewX86_32Disassembler creates a disassembler for x86 (32-bit)
func NewX86_32Disassembler() (*Disassembler, error) {
	return NewDisassembler(ArchX86, Mode32)
}

// NewX86_64Disassembler creates a disassembler for x86 (64-bit)
func NewX86_64Disassembler() (*Disassembler, error) {
	return NewDisassembler(ArchX86, Mode64)
}

// DisassembleAll disassembles all bytes and returns all instructions
func (d *Disassembler) DisassembleAll(code []byte, address uint64) ([]Instruction, error) {
	return d.Disassemble(code, address, 0)
}

// GetArchName returns the name of the architecture
func GetArchName(arch int) string {
	switch arch {
	case ArchARM:
		return "ARM"
	case ArchARM64:
		return "ARM64"
	case ArchX86:
		return "x86"
	case ArchMIPS:
		return "MIPS"
	default:
		return "Unknown"
	}
}
