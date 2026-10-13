package hexedit

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/destruct/destruct/internal/arm64lift"
	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/native"
)

const (
	// sttFunc is ELF STT_FUNC, the symbol type for function entries.
	sttFunc = 2
	// maxFunctionBytes caps a single lift: symbol sizes can be zero or
	// wrong, and a bogus boundary must not launch a giant decompile.
	maxFunctionBytes = 64 * 1024
	// maxNameMatches caps how many ambiguous name matches are listed.
	maxNameMatches = 10
)

// Function is one entry in the lazily built function index used by
// decompile: a boundary plus the best name available for it.
type Function struct {
	Addr uint64
	Size uint64
	Name string
}

// requireAArch64ELF enforces the v0.1 decompiler scope and points the
// user at the right subcommand for everything else.
func (s *Session) requireAArch64ELF() error {
	img := s.img
	if img.elf == nil {
		if img.ELFError() != nil {
			return fmt.Errorf("decompilation requires an AArch64 ELF binary (ELF header parse failed: %v)", img.ELFError())
		}
		return fmt.Errorf("decompilation requires an AArch64 ELF binary (this file is %s); %s", img.Format, formatSubcommandHint(img.Format))
	}
	if img.Machine != native.EM_AARCH64 {
		return fmt.Errorf("decompilation is AArch64-only (this ELF is %s); use destruct elf for plain disassembly of this architecture", native.GetArchName(img.Arch))
	}
	return nil
}

// formatSubcommandHint maps a detected format to the subcommand that
// actually handles it.
func formatSubcommandHint(f Format) string {
	switch f {
	case FormatDEX:
		return "use destruct dex for .dex/.apk files"
	case FormatClass:
		return "use destruct jvm for .class/.jar files"
	case FormatZIP:
		return "use destruct jvm for .jar or destruct dex for .apk"
	case FormatHermes:
		return "use destruct hermes for Hermes bytecode"
	default:
		return "use destruct jvm, destruct dex or destruct hermes for those formats; destruct elf handles ELF binaries"
	}
}

// functions returns the session's function index, building it on first
// use. STT_FUNC symbols provide names and real sizes; .eh_frame_hdr
// boundaries are always merged in as well, because a stripped shared
// library's .dynsym typically covers only the exported functions while
// users point at arbitrary .text addresses. Duplicate addresses keep
// the named entry; zero/oversized sizes are inferred from the next
// boundary and capped at maxFunctionBytes.
func (s *Session) functions(ctx context.Context) ([]Function, error) {
	if s.funcsBuilt {
		return s.funcs, s.funcsErr
	}
	s.funcsBuilt = true

	elf := s.img.elf
	if elf == nil {
		s.funcsErr = fmt.Errorf("no ELF metadata")
		return nil, s.funcsErr
	}

	var funcs []Function
	for _, sym := range elf.Symbols {
		if sym.Info&0xf != sttFunc || sym.Value == 0 {
			continue
		}
		name := elf.GetSymbolName(sym)
		if name == "" {
			name = fmt.Sprintf("sub_%x", sym.Value)
		}
		size := sym.Size
		if size > maxFunctionBytes {
			size = maxFunctionBytes
		}
		funcs = append(funcs, Function{Addr: sym.Value, Size: size, Name: name})
	}

	if discovered, err := elf.DiscoverFunctionsContext(ctx); err == nil {
		for _, d := range discovered {
			size := d.Size
			if size > maxFunctionBytes {
				size = maxFunctionBytes
			}
			funcs = append(funcs, Function{Addr: d.Addr, Size: size, Name: fmt.Sprintf("sub_%x", d.Addr)})
		}
	} else if len(funcs) == 0 {
		s.funcsErr = fmt.Errorf("no function information: no STT_FUNC symbols and .eh_frame_hdr discovery failed (%v)", err)
		return nil, s.funcsErr
	}

	sort.Slice(funcs, func(i, j int) bool {
		if funcs[i].Addr != funcs[j].Addr {
			return funcs[i].Addr < funcs[j].Addr
		}
		iSub := strings.HasPrefix(funcs[i].Name, "sub_")
		jSub := strings.HasPrefix(funcs[j].Name, "sub_")
		if iSub != jSub {
			return !iSub // keep the named entry
		}
		return funcs[i].Name < funcs[j].Name
	})

	// Collapse duplicate addresses (aliases, symbol/eh_frame overlap)
	// and infer zero sizes from the next boundary.
	out := funcs[:0]
	for _, f := range funcs {
		if n := len(out); n > 0 && out[n-1].Addr == f.Addr {
			continue
		}
		out = append(out, f)
	}
	for i := range out {
		if out[i].Size == 0 || out[i].Size > maxFunctionBytes {
			if i+1 < len(out) && out[i+1].Addr > out[i].Addr {
				out[i].Size = out[i+1].Addr - out[i].Addr
			}
			if out[i].Size == 0 || out[i].Size > maxFunctionBytes {
				out[i].Size = maxFunctionBytes
			}
		}
	}

	// A function's bytes never cross a section boundary. The inference
	// above uses the next boundary in the whole binary, and a zero-size
	// symbol at the end of .text would otherwise absorb everything up
	// to the next indexed entry - e.g. the whole following .plt. Clamp
	// each entry to the section it starts in so functionContaining can
	// never match an address in the next section.
	for i := range out {
		off, ok := s.img.VAToFile(out[i].Addr)
		if !ok {
			continue
		}
		sec, ok := s.img.SectionAtFile(off)
		if !ok {
			continue
		}
		if end := sec.Addr + sec.Size; end > out[i].Addr && out[i].Addr+out[i].Size > end {
			out[i].Size = end - out[i].Addr
		}
	}

	s.funcs = out
	return s.funcs, nil
}

func functionContaining(funcs []Function, va uint64) (Function, bool) {
	for _, f := range funcs {
		if va >= f.Addr && va-f.Addr < f.Size {
			return f, true
		}
	}
	return Function{}, false
}

// functionAt resolves the entry to decompile for a virtual address: the
// indexed function containing va, or a disasm-only pseudo-function
// starting at va when executable instructions exist there but neither
// the symbol table nor .eh_frame_hdr covers them (the ELF entry point,
// .plt stubs, cold code between discovered boundaries). ok is false only
// when va is not inside an executable section at all.
//
// A single-instruction unconditional-branch entry is followed to the
// function indexed at addr+4 when there is one: that shape is a linker
// veneer / trampoline symbol, and the fallthrough function is the body.
func (s *Session) functionAt(funcs []Function, va uint64) (Function, bool) {
	if found, ok := functionContaining(funcs, va); ok {
		return s.followBranchStub(funcs, found), true
	}
	return s.pseudoFunction(funcs, va)
}

// pseudoFunction synthesizes the index entry for executable code both
// discovery sources missed. The window runs from va to the next indexed
// boundary (while that boundary is still inside the same section) or to
// the containing section's end, capped like every other entry.
func (s *Session) pseudoFunction(funcs []Function, va uint64) (Function, bool) {
	off, ok := s.img.VAToFile(va)
	if !ok {
		return Function{}, false
	}
	sec, ok := s.img.CodeSectionAtFile(off)
	if !ok {
		return Function{}, false
	}
	end := sec.Addr + sec.Size
	for _, f := range funcs {
		if f.Addr > va {
			if f.Addr < end {
				end = f.Addr
			}
			break
		}
	}
	if end <= va {
		return Function{}, false
	}
	size := end - va
	if size > maxFunctionBytes {
		size = maxFunctionBytes
	}
	return Function{Addr: va, Size: size, Name: fmt.Sprintf("sub_%x", va)}, true
}

// followBranchStub redirects a 4-byte unconditional "b" entry to the
// function indexed at addr+4 when one starts there and is larger: the
// stub is a trampoline, not the body the user wants decompiled.
func (s *Session) followBranchStub(funcs []Function, f Function) Function {
	if f.Size > 4 {
		return f
	}
	off, ok := s.img.VAToFile(f.Addr)
	if !ok {
		return f
	}
	d, err := s.disassembler()
	if err != nil {
		return f
	}
	insns, err := d.DisassembleDetailed(s.view(int64(off), int(f.Size)), f.Addr)
	if err != nil || len(insns) != 1 || insns[0].Mnemonic != "b" {
		return f
	}
	next, ok := functionContaining(funcs, f.Addr+4)
	if !ok || next.Addr != f.Addr+4 || next.Size <= f.Size {
		return f
	}
	return next
}

// functionsNamed returns functions whose name matches q: exact matches
// first, then case-insensitive exact matches, then unique
// namespace-suffix matches ("Bar" for "Foo::Bar").
func functionsNamed(funcs []Function, q string) []Function {
	var exact []Function
	for _, f := range funcs {
		if f.Name == q {
			exact = append(exact, f)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	for _, f := range funcs {
		if strings.EqualFold(f.Name, q) {
			exact = append(exact, f)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	for _, f := range funcs {
		if strings.HasSuffix(f.Name, "::"+q) {
			exact = append(exact, f)
		}
	}
	return exact
}

// cmdDecompile lifts one function to C-like pseudocode. The argument is
// an address (f:/v:, or a bare number, meaning the function CONTAINING
// that address) or a function name.
func (s *Session) cmdDecompile(ctx context.Context, rest string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fields := strings.Fields(rest)
	if len(fields) != 1 {
		return fmt.Errorf("usage: decompile <func|addr>")
	}
	if err := s.requireAArch64ELF(); err != nil {
		return err
	}
	funcs, err := s.functions(ctx)
	if err != nil {
		return err
	}
	if len(funcs) == 0 {
		return fmt.Errorf("no functions found")
	}

	arg := fields[0]
	var target Function

	if a, perr := ParseAddr(arg); perr == nil {
		var va uint64
		switch a.Space {
		case SpaceVirtual:
			if _, err := s.ResolveAddr(a); err != nil {
				return err
			}
			va = a.Value
		default:
			off, err := s.ResolveAddr(a)
			if err != nil {
				return err
			}
			mapped, ok := s.img.FileToVA(uint64(off))
			if !ok {
				return fmt.Errorf("%s is not inside any file-backed section, so it cannot be mapped to a function", a)
			}
			va = mapped
			s.SetCursor(Addr{Value: va, Space: SpaceVirtual})
		}
		found, ok := s.functionAt(funcs, va)
		if !ok {
			return fmt.Errorf("no function contains v:0x%08x and it is not inside an executable section (use 'info' or 'disasm' to find code)", va)
		}
		target = found
	} else {
		matches := functionsNamed(funcs, arg)
		if len(matches) == 0 {
			return fmt.Errorf("function %q not found (try 'info', or decompile by address)", arg)
		}
		if len(matches) > 1 {
			s.printfln("multiple functions match %q:", arg)
			for i, f := range matches {
				if i >= maxNameMatches {
					s.printfln("  ... %d more", len(matches)-maxNameMatches)
					break
				}
				line := fmt.Sprintf("  v:0x%08x", f.Addr)
				if off, ok := s.img.VAToFile(f.Addr); ok {
					line += fmt.Sprintf(" (f:0x%08x)", off)
				}
				s.printfln("%s  %s", line, f.Name)
			}
			return fmt.Errorf("ambiguous function name %q (%d matches)", arg, len(matches))
		}
		target = matches[0]
	}

	off, ok := s.img.VAToFile(target.Addr)
	if !ok {
		return fmt.Errorf("v:0x%08x does not map to any file-backed section", target.Addr)
	}

	// Clamp the lift window to the section, EOF and the size cap.
	size := target.Size
	if sec, ok := s.img.SectionAtFile(off); ok {
		if end := sec.Offset + sec.Size; off+size > end {
			size = end - off
		}
	}
	if size > uint64(s.img.Size)-uint64(off) {
		size = uint64(s.img.Size) - uint64(off)
	}
	if size > maxFunctionBytes {
		size = maxFunctionBytes
	}
	if size == 0 {
		return fmt.Errorf("function %s at v:0x%08x has no bytes to lift", target.Name, target.Addr)
	}

	d, err := s.disassembler()
	if err != nil {
		return err
	}
	code := s.view(int64(off), int(size))
	insns, err := d.DisassembleDetailed(code, target.Addr)
	if err != nil {
		return fmt.Errorf("disassemble %s: %w", target.Name, err)
	}

	s.printfln("// %s @ v:0x%08x (f:0x%08x, %d bytes)", arm64lift.Demangle(target.Name), target.Addr, off, size)
	if s.stagedMask(int64(off), int(size)) != nil {
		s.printfln("// note: staged bytes in this range are lifted as instructions; string/table reads still come from the original file")
	}
	if len(insns) == 0 {
		s.printfln("// (nothing to lift - no decodable instructions)")
		return nil
	}

	elf := s.img.elf
	resolver := s.symbolResolver()
	strResolver := func(addr uint64) (string, bool) { return elf.ReadCString(addr) }
	dataReader := elf.DataReader()

	var stmts []ir.Stmt
	liftErr := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("lift failed: %v", r)
			}
		}()
		stmts = arm64lift.LiftFunctionWithData(insns, nil, resolver, strResolver, dataReader, false)
		return nil
	}()
	if liftErr != nil {
		return liftErr
	}
	if len(stmts) == 0 {
		s.printfln("// (nothing lifted - empty function or no recognized statements)")
		return nil
	}
	arm64lift.RenderStmts(s.out, stmts, 0)
	s.printfln("")
	return nil
}
