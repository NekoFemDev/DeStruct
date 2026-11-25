package pipeline

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/destruct/destruct/internal/arm64lift"
	"github.com/destruct/destruct/internal/native"
)

// computeOutlinedContexts finds outlined entries that read caller state.
// A "bti j" landing pad is always treated as a jump-table case; other
// entries are accepted when they inherit callee-saved registers or address
// sp/x29 without establishing their own frame.
func computeOutlinedContexts(
	candidates []funcCandidate,
	elf *native.ELFParser,
	d *native.Disassembler,
) map[uint64]arm64lift.OutlinedContext {
	if d == nil {
		return nil
	}
	out := make(map[uint64]arm64lift.OutlinedContext)
	// bti j: d503249f, little-endian.
	btiJ := []byte{0x9f, 0x24, 0x03, 0xd5}
	for _, c := range candidates {
		code, ok := readFunctionCode(c, elf)
		if !ok || len(code) < len(btiJ) {
			continue
		}
		isBtiJ := code[0] == btiJ[0] && code[1] == btiJ[1] &&
			code[2] == btiJ[2] && code[3] == btiJ[3]
		insns, err := d.DisassembleDetailed(code, c.addr)
		if err != nil || len(insns) == 0 {
			continue
		}
		// A `bti j` landing pad is a trusted jump-table case. For other
		// candidates, inspect only up to the first `ret`: a coarse
		// candidate may contain several real functions, and a later
		// prologue must not make the first function look outlined.
		prefix := insns
		if !isBtiJ {
			for i, in := range insns {
				if in.Mnemonic == "ret" {
					prefix = insns[:i]
					break
				}
			}
			if len(prefix) == 0 || arm64lift.OwnsFrame(prefix) {
				continue
			}
		}
		regs := arm64lift.CallerContextRegs(prefix)
		stack := arm64lift.CallerStackUsed(prefix)
		if len(regs) > 0 || stack {
			out[c.addr] = arm64lift.OutlinedContext{Regs: regs, Stack: stack}
		}
	}
	return out
}

// directBranchTarget returns the destination of an unconditional
// "b #imm" (Capstone resolves the PC-relative immediate).
func directBranchTarget(in native.DetailedInstruction) (uint64, bool) {
	if in.Mnemonic == "b" && len(in.Operands) > 0 && in.Operands[0].Type == native.OperandImm {
		return uint64(in.Operands[0].Imm), true
	}
	return 0, false
}

// splitCoarseFunctions refines gap-based .eh_frame function boundaries.
//
// DiscoverFunctions infers a function's size as the distance to the next
// unwind entry. That is exact for compiler-emitted FDEs, but a binary can
// contain many functions with no FDE at all (assembly, outlined helpers,
// stripped/hand-written code); those end up inside the preceding
// function's gap and are decompiled as one giant body. Direct BL targets,
// prologue shapes and function pointers from writable relative relocations
// are independent evidence of a real entry point, so use them to split the
// gaps into separate decompilation units.
//
// Runs only for the no-symbol-table path; symbol sizes are authoritative.
func splitCoarseFunctions(
	ctx context.Context,
	candidates []funcCandidate,
	elf *native.ELFParser,
	d *native.Disassembler,
	resolver func(uint64) (string, bool),
) ([]funcCandidate, func(uint64) (string, bool), int) {
	if len(candidates) == 0 || d == nil {
		return candidates, resolver, 0
	}

	relTargets := relocationFunctionTargets(ctx, elf)
	byAddr := make(map[uint64]funcCandidate, len(candidates))
	for _, c := range candidates {
		byAddr[c.addr] = c
	}

	addedNames := make(map[uint64]string)
	totalAdded := 0

	for pass := 0; pass < 8; pass++ {
		if err := ctx.Err(); err != nil {
			break
		}
		list := make([]funcCandidate, 0, len(byAddr))
		for _, c := range byAddr {
			list = append(list, c)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].addr < list[j].addr })
		assignFunctionSizes(list, elf)

		callCounts := make(map[uint64]int)
		var structuralTargets []uint64
		type branchSite struct {
			caller, target uint64
		}
		var crossBranches []branchSite
		for _, c := range list {
			code, ok := readFunctionCode(c, elf)
			if !ok || c.size == 0 {
				continue
			}
			insns, err := d.DisassembleDetailed(code, c.addr)
			if err != nil {
				continue
			}
			for i, in := range insns {
				if target, ok := callTarget(in); ok {
					if target != c.addr {
						if _, known := byAddr[target]; !known && inExecutableText(elf, target) && target%4 == 0 {
							callCounts[target]++
						}
					}
				}
				switch in.Mnemonic {
				case "b":
					if target, ok := directBranchTarget(in); ok {
						structuralTargets = append(structuralTargets, target)
						crossBranches = append(crossBranches, branchSite{caller: c.addr, target: target})
					}
				case "ret":
					// A return immediately followed by a fresh prologue is a
					// function boundary even without an FDE or direct call.
					if i+1 < len(insns) {
						structuralTargets = append(structuralTargets, insns[i+1].Address)
					}
				}
			}
		}

		var newAddrs []uint64
		for target := range callCounts {
			if _, ok := byAddr[target]; ok {
				continue
			}
			if _, resolved := resolver(target); resolved {
				continue
			}
			newAddrs = append(newAddrs, target)
		}
		for _, target := range structuralTargets {
			if target%4 != 0 || !inExecutableText(elf, target) {
				continue
			}
			if _, ok := byAddr[target]; ok {
				continue
			}
			if _, resolved := resolver(target); resolved {
				continue
			}
			if entryScore(elf, d, target) >= 2 {
				newAddrs = append(newAddrs, target)
			}
		}
		for _, site := range crossBranches {
			target := site.target
			if target%4 != 0 || !inExecutableText(elf, target) {
				continue
			}
			if _, ok := byAddr[target]; ok {
				continue
			}
			if _, resolved := resolver(target); resolved {
				continue
			}
			// Only tail branches into a DIFFERENT candidate's body: those
			// are alias/outlined entries that C cannot express as a local
			// goto. Intra-function branches stay inside their function.
			if containingCandidate(list, target) == site.caller || containingCandidate(list, target) == 0 {
				continue
			}
			// A cross-branch into a candidate that has no prologue shape is
			// usually not a real entry point: coarse .eh_frame gaps and
			// split fragments make one function look like several
			// candidates, and a loop/switch branch between them would
			// otherwise be emitted as a context-less standalone function.
			// Keep such targets inside their surrounding function so the
			// register/stack state that reaches them is preserved.
			if entryScore(elf, d, target) < 2 {
				continue
			}
			newAddrs = append(newAddrs, target)
		}
		for target := range relTargets {
			if _, ok := byAddr[target]; ok {
				continue
			}
			if _, resolved := resolver(target); resolved {
				continue
			}
			// A relative pointer into .text may target a local label or
			// landing pad, not a function entry; require a prologue shape.
			if entryScore(elf, d, target) >= 2 {
				newAddrs = append(newAddrs, target)
			}
		}
		if len(newAddrs) == 0 {
			break
		}
		sort.Slice(newAddrs, func(i, j int) bool { return newAddrs[i] < newAddrs[j] })
		for _, addr := range newAddrs {
			if _, ok := byAddr[addr]; ok {
				continue
			}
			name := fmt.Sprintf("sub_%x", addr)
			byAddr[addr] = funcCandidate{addr: addr, name: name}
			addedNames[addr] = name
			totalAdded++
		}
	}

	list := make([]funcCandidate, 0, len(byAddr))
	for _, c := range byAddr {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].addr < list[j].addr })
	assignFunctionSizes(list, elf)

	if len(addedNames) > 0 {
		base := resolver
		resolver = func(addr uint64) (string, bool) {
			if name, ok := addedNames[addr]; ok {
				return name, true
			}
			return base(addr)
		}
	}
	return list, resolver, totalAdded
}

// assignFunctionSizes bounds each candidate by the next candidate in the
// same executable section, or by that section's end for the last one.
func assignFunctionSizes(list []funcCandidate, elf *native.ELFParser) {
	for i := range list {
		end := textSectionEnd(elf, list[i].addr)
		if i+1 < len(list) && list[i+1].addr < end && list[i+1].addr > list[i].addr {
			if textSectionEnd(elf, list[i+1].addr) == end {
				end = list[i+1].addr
			}
		}
		if end > list[i].addr {
			list[i].size = end - list[i].addr
		}
	}
}

// containingCandidate returns the start address of the candidate whose
// [addr, addr+size) range contains target, or 0.
func containingCandidate(list []funcCandidate, target uint64) uint64 {
	i := sort.Search(len(list), func(i int) bool { return list[i].addr > target }) - 1
	if i >= 0 && target < list[i].addr+list[i].size {
		return list[i].addr
	}
	return 0
}

// relocationFunctionTargets returns addends of relative relocations stored
// in writable data (vtables, init_array, function-pointer tables) that land
// in an executable section.
func relocationFunctionTargets(ctx context.Context, elf *native.ELFParser) map[uint64]bool {
	out := make(map[uint64]bool)
	for _, rel := range elf.DynamicRelocations(ctx) {
		if uint32(rel.Info&0xffffffff) != 1027 {
			continue
		}
		if !inWritableData(elf, rel.Offset) {
			continue
		}
		target := uint64(rel.Addend)
		if target%4 == 0 && inExecutableText(elf, target) {
			out[target] = true
		}
	}
	return out
}

func inWritableData(elf *native.ELFParser, addr uint64) bool {
	for _, s := range elf.Sections {
		if s.Size == 0 || addr < s.Addr || addr-s.Addr >= s.Size {
			continue
		}
		return s.Flags&native.SHF_WRITE != 0
	}
	return false
}

func inExecutableText(elf *native.ELFParser, addr uint64) bool {
	name := ""
	for _, s := range elf.Sections {
		if s.Size == 0 || s.Flags&native.SHF_EXECINSTR == 0 || addr < s.Addr || addr-s.Addr >= s.Size {
			continue
		}
		name = elf.SectionName(s)
		if strings.Contains(name, ".plt") {
			return false
		}
		return true
	}
	return false
}

func textSectionEnd(elf *native.ELFParser, addr uint64) uint64 {
	for _, s := range elf.Sections {
		if s.Size == 0 || s.Flags&native.SHF_EXECINSTR == 0 || strings.Contains(elf.SectionName(s), ".plt") {
			continue
		}
		if addr >= s.Addr && addr-s.Addr < s.Size {
			return s.Addr + s.Size
		}
	}
	return addr
}

// entryScore heuristically scores the first instructions at addr as a
// function entry. Prologues (BTI/PAC, frame setup, callee-saved spills) score
// higher than bare leaf-style starts.
func entryScore(elf *native.ELFParser, d *native.Disassembler, addr uint64) int {
	code, ok := readFunctionCode(funcCandidate{addr: addr, size: 16}, elf)
	if !ok {
		return 0
	}
	insns, err := d.DisassembleDetailed(code, addr)
	if err != nil || len(insns) == 0 {
		return 0
	}
	score := 0
	first := insns[0]
	op := first.OpStr
	switch first.Mnemonic {
	case "bti", "paciasp", "pacibsp":
		score += 3
	case "stp":
		if strings.Contains(op, "x29, x30") || strings.Contains(op, "x19, x20") ||
			strings.Contains(op, "x21, x22") || strings.Contains(op, "x23, x24") {
			score += 2
		} else {
			score++
		}
	case "str":
		if strings.Contains(op, "[sp, #-") {
			score++
		}
	case "sub":
		if strings.Contains(op, "sp, sp,") {
			score += 2
		}
	case "mov":
		if strings.Contains(op, "x29, sp") {
			score += 2
		}
	case "adrp", "adr", "cbz", "cbnz", "tbz", "tbnz", "ldr":
		score++
	}
	if len(insns) > 1 {
		second := insns[1]
		switch second.Mnemonic {
		case "paciasp", "pacibsp":
			score++
		case "sub":
			if strings.Contains(second.OpStr, "sp, sp,") {
				score++
			}
		case "stp":
			// FP/callee-saved spill following another prologue store.
			if first.Mnemonic == "stp" || first.Mnemonic == "str" || first.Mnemonic == "bti" {
				score++
			}
		}
	}
	return score
}
