package arm64lift

// liftopts.go collects the optional inputs the ARM64 lifter accepts on
// top of its original (instructions, resolver, ...) entry points. The
// zero LiftOptions reproduces the original behavior exactly, so the
// legacy LiftFunction / LiftFunctionWithData wrappers stay bit-for-bit
// compatible with every existing caller.

// MetadataProvider supplies IL2CPP managed-metadata facts the lifter
// can't recover from machine code alone: which managed method a lifted
// function implements (and therefore its declaring type and parameter
// names), and which field of a known type lives at a given byte
// offset. It is deliberately a tiny consumer-side interface - the
// dumper that produces the data lives in a separate project; a caller
// adapts its output to these two lookups.
type MetadataProvider interface {
	// MethodAtRVA maps a function's entry address to its declaring
	// class (full dump name), parameter names (without the implicit
	// `this`) and static-ness. ok is false for addresses that aren't
	// managed method entries.
	MethodAtRVA(rva uint64) (typeName string, params []string, isStatic bool, ok bool)

	// FieldAtOffset returns the name and type of the field of typeName
	// (or of a base class, when the implementing provider can walk
	// one) whose byte offset from the object base is offset - the same
	// number an IL2CPP `ldr xN, [xM, #off]` carries.
	FieldAtOffset(typeName string, offset uint64) (fieldName, fieldType string, ok bool)
}

// LiftOptions configures LiftFunctionWithOptions. All fields default to
// the original lifter behavior.
type LiftOptions struct {
	// Simplify runs CFG simplification before structural lifting (the
	// --simplify-cfg pipeline option); LiftFunctionWithData already
	// passes this explicitly.
	Simplify bool

	// RegsAsVars renames the placeholder variables the lifter emits for
	// registers it never assigned (the `xN` in `x9.field_952`) into a
	// stable per-register variable name: AAPCS64 argument registers
	// x0-x7/w0-w7 become arg0..arg7 (unless a real parameter name was
	// supplied), every other integer register becomes var_N, and SIMD
	// registers (q/d/s/h/b0-31) become fvar_N from a separate counter,
	// so float state never mixes with integer state. Each physical
	// register keeps one name for the whole function, regardless of how
	// many times it is overwritten.
	RegsAsVars bool

	// Metadata, when non-nil, binds the lifted function's entry address
	// to its managed method (seeding real parameter names and the
	// declaring type of `this`) and resolves field accesses on `this`
	// to their IL2CPP field names.
	Metadata MetadataProvider
}
