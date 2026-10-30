package hermes

import (
	"context"
	"errors"
	"io"

	"github.com/destruct/destruct/internal/hermes/ir"
)

// The Hermes decompiler is frozen for the duration of the internal/hermes
// refactor. The old implementation was built on the previous byte-level
// data model (the per-version HBCFile/HBCReader structures); that model
// no longer exists, and a replacement will be built on ir.Module. Until
// then this stub keeps the public entry points compiling and makes the
// disablement explicit instead of silently degrading.
//
// Scope decision: --decompile for Hermes returns ErrDecompilerDisabled;
// use the hermes-dec exact disassembly (Disassemble / disasm package)
// instead.

// ErrDecompilerDisabled is returned by every Decompiler entry point while
// the decompiler is frozen.
var ErrDecompilerDisabled = errors.New("decompiler disabled during refactor")

// Decompiler is a placeholder bound to a parsed module.
type Decompiler struct {
	Module *ir.Module
}

// NewDecompiler creates a decompiler bound to an already-parsed module.
func NewDecompiler(m *ir.Module) *Decompiler {
	return &Decompiler{Module: m}
}

// DecompileAllContext always fails with ErrDecompilerDisabled.
func (d *Decompiler) DecompileAllContext(ctx context.Context, w io.Writer) error {
	return ErrDecompilerDisabled
}

// DecompileAll always fails with ErrDecompilerDisabled.
func (d *Decompiler) DecompileAll(w io.Writer) error {
	return ErrDecompilerDisabled
}
