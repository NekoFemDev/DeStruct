package pipeline

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/destruct/destruct/internal/native"
)

// xrefTarget is one end of a cross-reference edge (caller or callee).
type xrefTarget struct {
	addr uint64
	name string
}

// functionXrefs holds the call graph edges for one function.
type functionXrefs struct {
	addr     uint64
	size     uint64
	name     string
	calls    map[uint64]xrefTarget
	calledBy map[uint64]xrefTarget
}

// callTarget returns the destination address of a direct ARM64 call
// ("bl #imm"). Capstone already resolves the PC-relative immediate to
// an absolute address for ARM64 branch instructions, so the first
// immediate operand is the target.
func callTarget(in native.DetailedInstruction) (uint64, bool) {
	if in.Mnemonic == "bl" && len(in.Operands) > 0 && in.Operands[0].Type == native.OperandImm {
		return uint64(in.Operands[0].Imm), true
	}
	return 0, false
}

// nameForXref returns a human-readable name for an address used in an
// XREF comment or JSON entry. Real function candidates take priority,
// then the symbol resolver, then a synthetic "sub_<addr>" placeholder.
func nameForXref(addr uint64, candMap map[uint64]funcCandidate, resolver func(uint64) (string, bool)) string {
	if c, ok := candMap[addr]; ok && c.name != "" {
		return c.name
	}
	if name, ok := resolver(addr); ok && name != "" {
		return name
	}
	return fmt.Sprintf("sub_%x", addr)
}

// readFunctionCode extracts the raw machine code for a candidate from
// the ELF file. It mirrors the logic used during decompilation so that
// cross-reference analysis works on the exact same bytes the lifter sees.
func readFunctionCode(c funcCandidate, elf *native.ELFParser) ([]byte, bool) {
	var sec *native.SectionHeader
	for j := range elf.Sections {
		s := &elf.Sections[j]
		if c.addr >= s.Addr && c.addr < s.Addr+s.Size {
			sec = s
			break
		}
	}
	if sec == nil {
		return nil, false
	}
	fileOff := sec.Offset + (c.addr - sec.Addr)
	if fileOff+c.size > uint64(len(elf.Data)) {
		return nil, false
	}
	return elf.Data[fileOff : fileOff+c.size], true
}

// computeCrossReferences scans every function candidate for direct
// ARM64 calls ("bl #imm") and builds incoming/outgoing edges. It is a
// separate pre-pass so that every function knows its callers before
// anything is written to disk.
func computeCrossReferences(
	candidates []funcCandidate,
	elf *native.ELFParser,
	d *native.Disassembler,
	resolver func(uint64) (string, bool),
) map[uint64]*functionXrefs {
	candMap := make(map[uint64]funcCandidate, len(candidates))
	for _, c := range candidates {
		candMap[c.addr] = c
	}

	refs := make(map[uint64]*functionXrefs, len(candidates))
	for _, c := range candidates {
		refs[c.addr] = &functionXrefs{
			addr:     c.addr,
			size:     c.size,
			name:     c.name,
			calls:    make(map[uint64]xrefTarget),
			calledBy: make(map[uint64]xrefTarget),
		}
	}

	for _, c := range candidates {
		code, ok := readFunctionCode(c, elf)
		if !ok {
			continue
		}
		insns, err := d.DisassembleDetailed(code, c.addr)
		if err != nil || len(insns) == 0 {
			continue
		}
		for _, in := range insns {
			target, ok := callTarget(in)
			if !ok {
				continue
			}
			name := nameForXref(target, candMap, resolver)
			refs[c.addr].calls[target] = xrefTarget{addr: target, name: name}
			if _, known := candMap[target]; known {
				refs[target].calledBy[c.addr] = xrefTarget{addr: c.addr, name: c.name}
			}
		}
	}

	return refs
}

// sortedXrefTargets returns the map values sorted by address for stable output.
func sortedXrefTargets(m map[uint64]xrefTarget) []xrefTarget {
	addrs := make([]uint64, 0, len(m))
	for addr := range m {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	out := make([]xrefTarget, len(addrs))
	for i, addr := range addrs {
		out[i] = m[addr]
	}
	return out
}

// formatAddr returns a consistent hex string for an address.
func formatAddr(addr uint64) string {
	return fmt.Sprintf("0x%x", addr)
}

// formatXrefList formats a list of xref targets as "name @ 0x..., name @ 0x...".
func formatXrefList(targets map[uint64]xrefTarget) string {
	if len(targets) == 0 {
		return ""
	}
	var parts []string
	for _, t := range sortedXrefTargets(targets) {
		parts = append(parts, fmt.Sprintf("%s @ %s", t.name, formatAddr(t.addr)))
	}
	return strings.Join(parts, ", ")
}

// writeXrefComments emits concise "// XREF from/to: ..." comments for a
// function. It is written after the function header comment.
func writeXrefComments(w io.Writer, fx *functionXrefs) {
	if fx == nil {
		return
	}
	if from := formatXrefList(fx.calledBy); from != "" {
		fmt.Fprintf(w, "// XREF from: %s\n", from)
	}
	if to := formatXrefList(fx.calls); to != "" {
		fmt.Fprintf(w, "// XREF to: %s\n", to)
	}
}

// xrefJSON is the serializable shape of a function's cross-references.
type xrefJSON struct {
	Address  string      `json:"address"`
	Name     string      `json:"name"`
	Size     uint64      `json:"size"`
	Calls    []xrefEntry `json:"calls"`
	CalledBy []xrefEntry `json:"called_by"`
}

// xrefEntry is one caller/callee in the JSON output.
type xrefEntry struct {
	Address string `json:"address"`
	Name    string `json:"name"`
}

// toXrefJSON converts an internal functionXrefs record to its JSON form.
func toXrefJSON(fx *functionXrefs) xrefJSON {
	j := xrefJSON{
		Address:  formatAddr(fx.addr),
		Name:     fx.name,
		Size:     fx.size,
		Calls:    make([]xrefEntry, 0),
		CalledBy: make([]xrefEntry, 0),
	}
	for _, t := range sortedXrefTargets(fx.calls) {
		j.Calls = append(j.Calls, xrefEntry{Address: formatAddr(t.addr), Name: t.name})
	}
	for _, t := range sortedXrefTargets(fx.calledBy) {
		j.CalledBy = append(j.CalledBy, xrefEntry{Address: formatAddr(t.addr), Name: t.name})
	}
	return j
}

// writeXrefsJSON writes the global cross-reference index to disk.
func writeXrefsJSON(path string, refs map[uint64]*functionXrefs) error {
	addrs := make([]uint64, 0, len(refs))
	for addr := range refs {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })

	out := make([]xrefJSON, len(addrs))
	for i, addr := range addrs {
		out[i] = toXrefJSON(refs[addr])
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// xrefsOutputPath returns the appropriate path for the JSON index.
// In split-function mode the index lives inside the per-function directory;
// otherwise it sits next to the single .decompiled.c file.
func xrefsOutputPath(outputDir, baseName string, split bool) string {
	if split {
		return filepath.Join(outputDir, baseName+"_decompiled", "xrefs.json")
	}
	return filepath.Join(outputDir, baseName+".xrefs.json")
}
