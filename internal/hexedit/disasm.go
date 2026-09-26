package hexedit

import (
	"context"
	"fmt"
	"strings"

	"github.com/destruct/destruct/internal/native"
)

const (
	defaultDisasmCount = 16
	maxDisasmCount     = 4096
)

// disassembler returns the session's Capstone handle, creating it on
// first use. Disassembly needs an ELF machine type; the error names the
// format the file actually looks like so the user can pick the right
// subcommand instead of guessing.
func (s *Session) disassembler() (*native.Disassembler, error) {
	if s.dis != nil {
		return s.dis, nil
	}
	if s.img.elf == nil {
		if s.img.ELFError() != nil {
			return nil, fmt.Errorf("disassembly requires a parseable ELF binary (ELF header parse failed: %v)", s.img.ELFError())
		}
		return nil, fmt.Errorf("disassembly requires an ELF binary (this file is %s); hexedit only disassembles ELF - for JVM/DEX/Hermes inputs use destruct jvm, destruct dex or destruct hermes", s.img.Format)
	}
	d, err := native.NewDisassemblerForMachine(s.img.Machine)
	if err != nil {
		return nil, fmt.Errorf("unsupported ELF machine type 0x%x", s.img.Machine)
	}
	s.dis = d
	return d, nil
}

// symbolResolver returns the session's ELF symbol resolver, building it
// on first use. Non-ELF sessions get a resolver that resolves nothing.
func (s *Session) symbolResolver() func(uint64) (string, bool) {
	if s.resolver == nil {
		if s.img.elf == nil {
			s.resolver = func(uint64) (string, bool) { return "", false }
		} else {
			s.resolver = s.img.elf.SymbolResolver()
		}
	}
	return s.resolver
}

// maxInstructionBytes is the window sizing factor per instruction:
// fixed 4-byte ARM/AArch64 encodings vs x86's 15-byte maximum.
func maxInstructionBytes(machine uint16) int {
	switch machine {
	case native.EM_AARCH64, native.EM_ARM:
		return 4
	default:
		return 15
	}
}

// cmdDisasm disassembles count instructions at addr (default: cursor,
// 16 instructions), staying inside the containing executable section.
// Capstone is addressed with virtual addresses so PC-relative operands
// resolve correctly; rows print v: addresses, matching `destruct elf`.
func (s *Session) cmdDisasm(ctx context.Context, rest string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fields := strings.Fields(rest)
	if len(fields) > 2 {
		return fmt.Errorf("usage: disasm [addr] [count]")
	}

	off, err := s.ResolveAddr(s.cursor)
	if err != nil {
		return err
	}
	if len(fields) >= 1 {
		a, err := ParseAddr(fields[0])
		if err != nil {
			return err
		}
		off, err = s.ResolveAddr(a)
		if err != nil {
			return err
		}
		s.SetCursor(a)
	}

	count := defaultDisasmCount
	if len(fields) == 2 {
		if count, err = parseCount(fields[1]); err != nil {
			return err
		}
	}
	if count <= 0 {
		return fmt.Errorf("disassembly count must be positive")
	}
	if count > maxDisasmCount {
		return fmt.Errorf("disassembly count %d exceeds the maximum of %d instructions", count, maxDisasmCount)
	}

	d, err := s.disassembler()
	if err != nil {
		return err
	}

	sec, ok := s.img.CodeSectionAtFile(uint64(off))
	if !ok {
		return fmt.Errorf("f:0x%08x is not inside an executable section (use 'info' to list sections)", off)
	}
	va, _ := s.img.FileToVA(uint64(off))

	if s.img.Machine == native.EM_AARCH64 && va%4 != 0 {
		s.printfln("; warning: v:0x%08x is not 4-byte aligned; ARM64 decoding will be misaligned garbage", va)
	}

	// Window: exactly enough bytes for count instructions, never past
	// the section or EOF.
	remaining := int64(sec.Offset+sec.Size) - off
	window := int64(count * maxInstructionBytes(s.img.Machine))
	if window > remaining {
		window = remaining
	}
	code := s.img.Bytes()[off : off+window]

	insns, err := d.DisassembleDetailed(code, va)
	if err != nil {
		return fmt.Errorf("disassemble: %w", err)
	}
	if len(insns) > count {
		insns = insns[:count]
	}

	name := s.img.elf.SectionName(sec)
	if name == "" {
		name = "<unnamed>"
	}
	s.printfln("; %s f:0x%08x v:0x%08x", name, off, va)

	if len(insns) == 0 {
		s.printfln("; no instructions decoded")
		return nil
	}

	resolver := s.symbolResolver()
	width := maxInstructionBytes(s.img.Machine)*3 - 1
	lastSym := ""
	for _, in := range insns {
		if sym, ok := resolver(in.Address); ok && sym != "" && sym != lastSym {
			s.printfln("; %s:", sym)
			lastSym = sym
		}

		var hexBytes strings.Builder
		for i, b := range in.Bytes {
			if i > 0 {
				hexBytes.WriteByte(' ')
			}
			fmt.Fprintf(&hexBytes, "%02x", b)
		}

		line := fmt.Sprintf("v:0x%08x  %-*s  %-8s %s",
			in.Address, width, hexBytes.String(), in.Mnemonic, in.OpStr)
		if target := branchTarget(resolver, in); target != "" {
			line += " ; " + target
		}
		s.printfln("%s", line)
	}
	return nil
}

// branchTarget resolves a direct branch's immediate operand to a
// symbol name, for bl/b (calls and tail calls) annotations.
func branchTarget(resolver func(uint64) (string, bool), in native.DetailedInstruction) string {
	switch in.Mnemonic {
	case "bl", "b":
	default:
		return ""
	}
	if len(in.Operands) == 0 || in.Operands[0].Type != native.OperandImm {
		return ""
	}
	name, ok := resolver(uint64(in.Operands[0].Imm))
	if !ok {
		return ""
	}
	return name
}
