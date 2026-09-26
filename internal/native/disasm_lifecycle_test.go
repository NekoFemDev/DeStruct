package native

import (
	"errors"
	"sync"
	"testing"
)

// ret (AArch64): 0xD65F03C0, little-endian.
var retInsn = []byte{0xC0, 0x03, 0x5F, 0xD6}

// add x0, x1, x2 (AArch64): 0x8B020020, little-endian.
var addInsn = []byte{0x20, 0x00, 0x02, 0x8B}

func newTestDisassembler(t *testing.T) *Disassembler {
	t.Helper()
	d, err := NewARM64Disassembler()
	if err != nil {
		t.Fatalf("NewARM64Disassembler: %v", err)
	}
	return d
}

// Close must be idempotent: double close is a no-op, not a double free.
func TestDisassemblerCloseTwice(t *testing.T) {
	d := newTestDisassembler(t)
	d.Close()
	d.Close()
}

// Close on a zero-value handle (never opened) must not panic.
func TestDisassemblerCloseZeroValue(t *testing.T) {
	var d Disassembler
	d.Close()
	d.Close()
}

// Close on a nil receiver must not panic.
func TestDisassemblerCloseNilReceiver(t *testing.T) {
	var d *Disassembler
	d.Close()
}

// Concurrent Close calls must not race or double-free; run with -race.
func TestDisassemblerCloseConcurrent(t *testing.T) {
	d := newTestDisassembler(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Close()
		}()
	}
	wg.Wait()
	d.Close()
}

// Use after Close must return errDisassemblerClosed, not touch the freed
// handle or panic.
func TestDisassemblerUseAfterClose(t *testing.T) {
	d := newTestDisassembler(t)
	d.Close()

	if _, err := d.DisassembleAll(retInsn, 0x1000); !errors.Is(err, errDisassemblerClosed) {
		t.Fatalf("DisassembleAll after Close: got err %v, want %v", err, errDisassemblerClosed)
	}
	if _, err := d.DisassembleDetailed(retInsn, 0x1000); !errors.Is(err, errDisassemblerClosed) {
		t.Fatalf("DisassembleDetailed after Close: got err %v, want %v", err, errDisassemblerClosed)
	}
}

// Methods on a nil receiver must fail cleanly rather than panic.
func TestDisassemblerNilReceiverUse(t *testing.T) {
	var d *Disassembler
	if _, err := d.DisassembleAll(retInsn, 0x1000); !errors.Is(err, errDisassemblerClosed) {
		t.Fatalf("nil receiver DisassembleAll: got err %v, want %v", err, errDisassemblerClosed)
	}
}

// Concurrent disassembly and Close must not race; each Disassemble either
// completes before the close or fails with errDisassemblerClosed. Run with
// -race.
func TestDisassemblerConcurrentUseAndClose(t *testing.T) {
	d := newTestDisassembler(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = d.DisassembleAll(retInsn, 0x1000)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.Close()
	}()
	wg.Wait()
}

// Sanity: the helper-based read path still decodes text fields.
func TestDisassembleTextStillWorks(t *testing.T) {
	d := newTestDisassembler(t)
	defer d.Close()

	insns, err := d.DisassembleAll(retInsn, 0x1000)
	if err != nil {
		t.Fatalf("DisassembleAll: %v", err)
	}
	if len(insns) != 1 {
		t.Fatalf("DisassembleAll: got %d instructions, want 1", len(insns))
	}
	if insns[0].Mnemonic != "ret" {
		t.Errorf("Mnemonic = %q, want %q", insns[0].Mnemonic, "ret")
	}
	if insns[0].Address != 0x1000 || insns[0].Size != 4 {
		t.Errorf("Address/Size = 0x%x/%d, want 0x1000/4", insns[0].Address, insns[0].Size)
	}
	if len(insns[0].Bytes) != 4 {
		t.Errorf("Bytes length = %d, want 4", len(insns[0].Bytes))
	}
}

// Sanity: the helper-based operand path still decodes register operands.
func TestDisassembleDetailedOperandsStillWork(t *testing.T) {
	d := newTestDisassembler(t)
	defer d.Close()

	insns, err := d.DisassembleDetailed(addInsn, 0)
	if err != nil {
		t.Fatalf("DisassembleDetailed: %v", err)
	}
	if len(insns) != 1 {
		t.Fatalf("DisassembleDetailed: got %d instructions, want 1", len(insns))
	}
	if insns[0].Mnemonic != "add" {
		t.Errorf("Mnemonic = %q, want %q", insns[0].Mnemonic, "add")
	}
	if len(insns[0].Operands) != 3 {
		t.Fatalf("Operands = %d, want 3", len(insns[0].Operands))
	}
	for i, want := range []string{"x0", "x1", "x2"} {
		if insns[0].Operands[i].Type != OperandReg || insns[0].Operands[i].Reg != want {
			t.Errorf("Operands[%d] = %+v, want reg %s", i, insns[0].Operands[i], want)
		}
	}
}

// Sanity: memory operands still resolve base/index/disp through the new
// helper path. `ldr x0, [x1, #8]` encodes as 0xF9400420.
func TestDisassembleDetailedMemoryOperand(t *testing.T) {
	d := newTestDisassembler(t)
	defer d.Close()

	insns, err := d.DisassembleDetailed([]byte{0x20, 0x04, 0x40, 0xF9}, 0)
	if err != nil {
		t.Fatalf("DisassembleDetailed: %v", err)
	}
	if len(insns) != 1 || len(insns[0].Operands) != 2 {
		t.Fatalf("got %d instructions with %d operands, want 1 with 2", len(insns), len(insns[0].Operands))
	}
	mem := insns[0].Operands[1]
	if mem.Type != OperandMem || mem.Mem.Base != "x1" || mem.Mem.Disp != 8 {
		t.Errorf("memory operand = %+v, want [x1, #8]", mem)
	}
}
