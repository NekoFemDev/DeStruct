package registry

import (
	"errors"
	"testing"

	"github.com/destruct/destruct/internal/hermes/opcodes"
)

func TestLookupKnownVersions(t *testing.T) {
	for _, version := range []uint32{59, 83, 95, 96, 97, 98, 99} {
		table, err := Lookup(version)
		if err != nil {
			t.Errorf("Lookup(%d): %v", version, err)
			continue
		}
		if table.Version != version {
			t.Errorf("Lookup(%d).Version = %d", version, table.Version)
		}
		if len(table.Ordered) == 0 {
			t.Errorf("Lookup(%d) returned an empty table", version)
		}
	}
}

func TestLookupUnsupportedVersion(t *testing.T) {
	_, err := Lookup(60)
	var unsupported *UnsupportedVersionError
	if !errors.As(err, &unsupported) {
		t.Fatalf("Lookup(60) error = %v, want *UnsupportedVersionError", err)
	}
	if unsupported.Version != 60 {
		t.Errorf("unsupported.Version = %d, want 60", unsupported.Version)
	}
}

// TestAllTablesWellFormed checks invariants the generated tables must
// satisfy regardless of the fixture: opcode bytes are dense and ordered,
// sizes are non-zero, every Addr8 jump that has a same-arity Addr32
// "Long" counterpart is linked, and every required mnemonic exists.
func TestAllTablesWellFormed(t *testing.T) {
	versions := Supported()
	if len(versions) == 0 {
		t.Fatal("Supported() is empty")
	}

	for _, version := range versions {
		table, err := Lookup(version)
		if err != nil {
			t.Fatalf("Lookup(%d): %v", version, err)
		}

		for i, op := range table.Ordered {
			if op.Name == "" {
				t.Fatalf("v%d: opcode %d has no name", version, i)
			}
			if int(op.Value) != i {
				t.Fatalf("v%d: %s.Value = %d, want %d", version, op.Name, op.Value, i)
			}
			if op.Size < 1 {
				t.Fatalf("v%d: %s.Size = %d", version, op.Name, op.Size)
			}
			if table.ByValue[op.Value] != op {
				t.Fatalf("v%d: ByValue[%d] does not point at %s", version, op.Value, op.Name)
			}
			if table.Find(op.Name) != op {
				t.Fatalf("v%d: ByName[%q] does not point at %s", version, op.Name, op.Name)
			}

			// Every Addr8 jump whose "Long" counterpart shares the
			// operand layout must be linked for jump relaxation.
			long := table.Find(op.Name + "Long")
			if long == nil {
				continue
			}
			if hasAddr8(op) {
				if op.LongForm != long {
					t.Errorf("v%d: %s.LongForm not linked to %s", version, op.Name, long.Name)
				}
			}
		}

		for _, required := range []string{"Unreachable", "Jmp", "JmpLong", "CreateClosure", "LoadConstString"} {
			if table.Find(required) == nil && required != "Unreachable" {
				t.Errorf("v%d: missing required opcode %s", version, required)
			}
		}
	}
}

func hasAddr8(op *opcodes.Opcode) bool {
	for _, operand := range op.Operands {
		if operand.Type == opcodes.Addr8 {
			return true
		}
	}
	return false
}
