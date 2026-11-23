// Package emulate runs original machine code for analysis: function-level
// emulation, oracle checks against decompiled C, and context recovery for
// outlined blocks. The concrete CPU backend is optional and supplied by the
// `unicorn` build tag; the rest of DeStruct builds and runs without it.
package emulate

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/destruct/destruct/internal/native"
)

// ErrUnavailable is returned when DeStruct was built without the optional
// Unicorn backend.
var ErrUnavailable = errors.New("emulation backend not built in; run `make unicorn build-unicorn` (Unicorn is GPLv2)")

// Arch selects the emulated instruction set.
type Arch int

const (
	ArchARM64 Arch = iota
)

// Memory protection bits for Backend.Map.
const (
	ProtRead  = 1
	ProtWrite = 2
	ProtExec  = 4
)

// Backend is the minimal CPU/memory interface the high-level Machine needs.
// Register names are architecture-specific lowercase names ("x0", "sp",
// "pc", "nzcv" for AArch64).
type Backend interface {
	Map(addr, size uint64, prot int) error
	Write(addr uint64, data []byte) error
	Read(addr, size uint64) ([]byte, error)
	Reg(name string) (int, error)
	RegWrite(reg int, value uint64) error
	RegRead(reg int) (uint64, error)
	Start(begin, until uint64, timeout time.Duration, count uint64) error
	Close() error
}

var newBackend func(arch Arch) (Backend, error)

// Available reports whether an emulation backend was compiled in.
func Available() bool { return newBackend != nil }

// Config controls stack placement and execution limits.
type Config struct {
	StackBase uint64
	StackSize uint64
	Timeout   time.Duration
	MaxInsns  uint64
}

// DefaultConfig is suitable for ordinary function-level emulation.
func DefaultConfig() Config {
	return Config{
		StackBase: 0x700000000000,
		StackSize: 1 << 20,
		Timeout:   5 * time.Second,
		MaxInsns:  10_000_000,
	}
}

const (
	emuStubBase = 0x6fffff000000
	emuZeroBase = 0x6ffffe000000
	// emuTLSBase is a dedicated zero-filled TLS block. TPIDR_EL0 points at
	// its middle so both positive (canary at 0x28) and negative (errno)
	// thread-local offsets stay mapped.
	emuTLSBase = 0x6ffffd000000
	emuTLSSize = 0x10000
)

// Machine is one emulated process image plus a stack and return sentinel.
type Machine struct {
	backend Backend
	cfg     Config

	imageBase uint64
	imageSize uint64
	stackTop  uint64
	sentinel  uint64
	prepared  bool
	stubReady bool
}

// NewMachine creates a backend and a stack. It does not load an ELF yet.
func NewMachine(arch Arch, cfg Config) (*Machine, error) {
	if newBackend == nil {
		return nil, ErrUnavailable
	}
	if cfg.StackSize == 0 {
		cfg.StackSize = DefaultConfig().StackSize
	}
	if cfg.StackBase == 0 {
		cfg.StackBase = DefaultConfig().StackBase
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultConfig().Timeout
	}
	if cfg.MaxInsns == 0 {
		cfg.MaxInsns = DefaultConfig().MaxInsns
	}
	b, err := newBackend(arch)
	if err != nil {
		return nil, err
	}
	return &Machine{backend: b, cfg: cfg}, nil
}

// Close releases the backend.
func (m *Machine) Close() error {
	if m == nil || m.backend == nil {
		return nil
	}
	return m.backend.Close()
}

// LoadELF maps the ELF's allocated image at its link-time virtual
// addresses, so PC-relative code, absolute data references and PLT/GOT
// slots all see the original bytes.
func (m *Machine) LoadELF(elf *native.ELFParser) error {
	base, img, err := elf.LoadImage()
	if err != nil {
		return err
	}
	if len(img) == 0 {
		return fmt.Errorf("empty ELF image")
	}
	mappedBase := base &^ 0xfff
	offset := base - mappedBase
	size := alignUp(uint64(len(img))+offset, 0x1000)
	if err := m.backend.Map(mappedBase, size, ProtRead|ProtWrite|ProtExec); err != nil {
		return fmt.Errorf("map ELF image at 0x%x: %w", mappedBase, err)
	}
	if err := m.backend.Write(base, img); err != nil {
		return fmt.Errorf("write ELF image: %w", err)
	}
	m.imageBase = base
	m.imageSize = uint64(len(img))
	if err := m.ensureStubPages(); err != nil {
		return err
	}
	if err := m.patchImports(elf); err != nil {
		return err
	}
	return nil
}

// ensureStubPages maps the external-call trampoline and the zero page used
// for imported data objects.
func (m *Machine) ensureStubPages() error {
	if m.stubReady {
		return nil
	}
	if err := m.backend.Map(emuStubBase, 0x1000, ProtRead|ProtWrite|ProtExec); err != nil {
		return fmt.Errorf("map import stub: %w", err)
	}
	// mov x0, #0; ret
	if err := m.backend.Write(emuStubBase, []byte{0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6}); err != nil {
		return fmt.Errorf("write import stub: %w", err)
	}
	if err := m.backend.Map(emuZeroBase, 0x10000, ProtRead|ProtWrite); err != nil {
		return fmt.Errorf("map import data page: %w", err)
	}
	m.stubReady = true
	return nil
}

// patchImports applies dynamic relocations and redirects imported
// functions to a "return 0" trampoline, so ordinary library calls do not
// fault during function-level emulation.
func (m *Machine) patchImports(elf *native.ELFParser) error {
	ctx := context.Background()
	dynsyms := elf.DynamicSymbols(ctx)
	writeSlot := func(slot, value uint64) error {
		if m.imageSize == 0 || slot < m.imageBase || slot+8 > m.imageBase+m.imageSize {
			return nil
		}
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], value)
		return m.backend.Write(slot, buf[:])
	}

	for _, rel := range elf.DynamicRelocations(ctx) {
		switch uint32(rel.Info & 0xffffffff) {
		case 1027: // R_AARCH64_RELATIVE
			if err := writeSlot(rel.Offset, uint64(rel.Addend)); err != nil {
				return err
			}
		case 1025, 257: // GLOB_DAT / ABS64
			idx := rel.SymbolIndex()
			if int(idx) >= len(dynsyms) {
				continue
			}
			sym := dynsyms[idx]
			target := uint64(emuZeroBase)
			if sym.Info&0xf == 2 { // STT_FUNC
				target = uint64(emuStubBase)
			}
			if err := writeSlot(rel.Offset, target); err != nil {
				return err
			}
		}
	}
	for _, rel := range elf.PLTRelocations(ctx) {
		if uint32(rel.Info&0xffffffff) != 1026 { // R_AARCH64_JUMP_SLOT
			continue
		}
		if err := writeSlot(rel.Offset, emuStubBase); err != nil {
			return err
		}
	}
	return nil
}

// Prepare maps the stack and return sentinel. Safe to call more than once.
func (m *Machine) Prepare() error {
	if m.prepared {
		return nil
	}
	stackBase := m.cfg.StackBase
	stackSize := alignUp(m.cfg.StackSize, 0x1000)
	// Keep the stack clear of the loaded image on unusual layouts.
	if m.imageSize > 0 && stackBase < m.imageBase+m.imageSize {
		stackBase = alignUp(m.imageBase+m.imageSize, 0x1000) + 0x100000
	}
	if err := m.backend.Map(stackBase, stackSize, ProtRead|ProtWrite); err != nil {
		return fmt.Errorf("map stack: %w", err)
	}
	m.stackTop = stackBase + stackSize
	m.sentinel = m.stackTop + 0x1000
	if err := m.backend.Map(m.sentinel, 0x1000, ProtRead|ProtWrite|ProtExec); err != nil {
		return fmt.Errorf("map return sentinel: %w", err)
	}
	// AArch64 "ret".
	if err := m.backend.Write(m.sentinel, []byte{0xc0, 0x03, 0x5f, 0xd6}); err != nil {
		return fmt.Errorf("write return sentinel: %w", err)
	}
	if err := m.backend.Map(emuTLSBase, emuTLSSize, ProtRead|ProtWrite); err != nil {
		return fmt.Errorf("map TLS block: %w", err)
	}
	m.prepared = true
	return nil
}

// Result captures the post-execution register state.
type Result struct {
	X      [31]uint64 `json:"x"`
	SP     uint64     `json:"sp"`
	PC     uint64     `json:"pc"`
	NZCV   uint64     `json:"nzcv"`
	Return uint64     `json:"return"`
	// Stopped reports whether execution reached the sentinel (a normal
	// return) rather than the instruction/timeout limit or an error.
	Stopped bool `json:"stopped"`
}

// Call runs the function at addr with args in x0..x7. It returns the final
// register state even when emulation stops early or faults.
func (m *Machine) Call(addr uint64, args []uint64) (*Result, error) {
	if err := m.Prepare(); err != nil {
		return nil, err
	}
	for i := 0; i < 31; i++ {
		var val uint64
		if i < len(args) {
			val = args[i]
		}
		if err := m.setReg(fmt.Sprintf("x%d", i), val); err != nil {
			return nil, err
		}
	}
	if err := m.setReg("sp", m.stackTop-0x100); err != nil {
		return nil, err
	}
	if err := m.setReg("lr", m.sentinel); err != nil {
		return nil, err
	}
	if err := m.setReg("pc", addr); err != nil {
		return nil, err
	}
	if err := m.setReg("nzcv", 0); err != nil {
		return nil, err
	}
	// Each Call starts the way a fresh host process does: zeroed TLS.
	// TPIDR_EL0 is the AArch64 user thread pointer used by Android code
	// for the stack canary and thread-local variables.
	if err := m.backend.Write(emuTLSBase, make([]byte, emuTLSSize)); err != nil {
		return nil, fmt.Errorf("reset TLS block: %w", err)
	}
	if err := m.setReg("tpidr_el0", emuTLSBase+emuTLSSize/2); err != nil {
		return nil, err
	}

	runErr := m.backend.Start(addr, m.sentinel, m.cfg.Timeout, m.cfg.MaxInsns)
	res := &Result{}
	for i := 0; i < 31; i++ {
		v, err := m.getReg(fmt.Sprintf("x%d", i))
		if err == nil {
			res.X[i] = v
		}
	}
	res.SP, _ = m.getReg("sp")
	res.PC, _ = m.getReg("pc")
	res.NZCV, _ = m.getReg("nzcv")
	res.Return = res.X[0]
	res.Stopped = runErr == nil && res.PC == m.sentinel
	if runErr != nil {
		return res, fmt.Errorf("emulation stopped at pc=0x%x: %w", res.PC, runErr)
	}
	return res, nil
}

func (m *Machine) setReg(name string, value uint64) error {
	id, err := m.backend.Reg(name)
	if err != nil {
		return err
	}
	return m.backend.RegWrite(id, value)
}

func (m *Machine) getReg(name string) (uint64, error) {
	id, err := m.backend.Reg(name)
	if err != nil {
		return 0, err
	}
	return m.backend.RegRead(id)
}

func alignUp(v, align uint64) uint64 {
	return (v + align - 1) &^ (align - 1)
}
