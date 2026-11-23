//go:build unicorn

package emulate

import (
	"encoding/binary"
	"testing"
)

func writeWords(t *testing.T, m *Machine, addr uint64, words ...uint32) {
	t.Helper()
	buf := make([]byte, len(words)*4)
	for i, w := range words {
		binary.LittleEndian.PutUint32(buf[i*4:], w)
	}
	if err := m.backend.Write(addr, buf); err != nil {
		t.Fatalf("write code: %v", err)
	}
}

func TestARM64Add(t *testing.T) {
	m, err := NewMachine(ArchARM64, DefaultConfig())
	if err != nil {
		t.Fatalf("NewMachine: %v", err)
	}
	defer m.Close()
	if err := m.backend.Map(0x1000, 0x1000, ProtRead|ProtWrite|ProtExec); err != nil {
		t.Fatalf("map code: %v", err)
	}
	writeWords(t, m, 0x1000, 0x8b010000, 0xd65f03c0) // add x0,x0,x1; ret

	res, err := m.Call(0x1000, []uint64{7, 5})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !res.Stopped {
		t.Fatalf("execution did not reach the sentinel: pc=0x%x", res.PC)
	}
	if res.Return != 12 {
		t.Fatalf("return = %d, want 12", res.Return)
	}
}

func TestARM64LoadAndStore(t *testing.T) {
	m, err := NewMachine(ArchARM64, DefaultConfig())
	if err != nil {
		t.Fatalf("NewMachine: %v", err)
	}
	defer m.Close()
	if err := m.backend.Map(0x1000, 0x2000, ProtRead|ProtWrite|ProtExec); err != nil {
		t.Fatalf("map: %v", err)
	}
	// ldr x0, [x1]; str x0, [x2]; ret
	writeWords(t, m, 0x1000, 0xf9400020, 0xf9000040, 0xd65f03c0)
	if err := m.backend.Write(0x2000, []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}); err != nil {
		t.Fatalf("write data: %v", err)
	}

	res, err := m.Call(0x1000, []uint64{0, 0x2000, 0x2100})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Return != 0x1122334455667788 {
		t.Fatalf("return = 0x%x", res.Return)
	}
	out, err := m.backend.Read(0x2100, 8)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	for i, b := range []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11} {
		if out[i] != b {
			t.Fatalf("stored bytes = %x", out)
		}
	}
}
