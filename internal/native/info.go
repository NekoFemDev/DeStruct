package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// Additional ELF constants used only by the human-oriented info summary.
// They are kept here instead of ELFHeader's constant block because the
// parser itself never needs them.
const (
	PT_INTERP    = 3
	PT_GNU_STACK = 0x6474e551
	PT_GNU_RELRO = 0x6474e552
	DT_NEEDED    = 1
	DT_SONAME    = 14
	DT_RPATH     = 15
	DT_RUNPATH   = 29
	DT_FLAGS     = 30
	DT_FLAGS_1   = 0x6ffffffb
	DF_BIND_NOW  = 0x8
	DF_1_NOW     = 0x1
	DF_1_PIE     = 0x08000000
	SHN_UNDEF    = 0
	STB_GLOBAL   = 1
	STB_WEAK     = 2
)

// SectionInfo is one section row in an ELFInfo summary.
type SectionInfo struct {
	Index  int
	Name   string
	Type   string
	Flags  string
	Addr   uint64
	Offset uint64
	Size   uint64
}

// ELFInfo is a human-oriented summary of an ELF file: header facts,
// sections, dynamic dependencies, symbols, function counts and the
// basic hardening flags a triage pass usually wants.
type ELFInfo struct {
	Path string
	Size int64

	Class   string
	Data    string
	OSABI   string
	Type    string
	Machine string
	Entry   uint64

	ProgramHeaders int
	Sections       []SectionInfo
	SectionCount   int

	Interp  string
	Needed  []string
	SONAME  string
	RPATH   []string
	RUNPATH []string

	PIE      bool
	NX       bool
	GNUStack bool
	RELRO    bool
	BindNow  bool
	Canary   bool

	SymbolCount      int
	DefinedSymbols   int
	UndefinedSymbols int
	FunctionCount    int
	Imports          []string
	Exports          []string
	Stripped         bool
	DiscoveredFuncs  int
	FORTIFYFuncs     int
	DWARF            *DWARFSummary
}

type dynEntry struct {
	tag int64
	val uint64
}

// Info summarizes the parsed ELF. It never fails on optional data
// (missing dynamic section, missing symbols, missing eh_frame): those
// simply leave the corresponding fields zero/empty.
func (p *ELFParser) Info(ctx context.Context) (*ELFInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	info := &ELFInfo{
		Class:   elfClassName(p.Header.Class),
		Data:    elfDataName(p.Header.Data),
		OSABI:   elfOSABIName(p.Header.OSABI),
		Type:    elfTypeName(p.Header.Type),
		Machine: elfMachineName(p.Header.Machine),
		Entry:   p.Header.Entry,
	}

	for i, sec := range p.Sections {
		info.Sections = append(info.Sections, SectionInfo{
			Index:  i,
			Name:   p.getSectionName(sec),
			Type:   elfSectionTypeName(sec.Type),
			Flags:  elfSectionFlags(sec.Flags),
			Addr:   sec.Addr,
			Offset: sec.Offset,
			Size:   sec.Size,
		})
	}
	info.SectionCount = len(info.Sections)
	info.Stripped = true
	for _, sec := range p.Sections {
		if sec.Type == SHT_SYMTAB {
			info.Stripped = false
			break
		}
	}

	phdrs, err := p.parseProgramHeaders(ctx)
	if err == nil {
		info.ProgramHeaders = len(phdrs)
		var dynOff, dynSize uint64
		for _, ph := range phdrs {
			switch ph.Type {
			case PT_INTERP:
				info.Interp = p.readCStringAtOffset(ph.Offset)
			case PT_GNU_STACK:
				info.GNUStack = true
				info.NX = ph.Flags&PF_X == 0
			case PT_GNU_RELRO:
				info.RELRO = true
			case PT_DYNAMIC:
				dynOff, dynSize = ph.Offset, ph.FileSz
			}
		}
		if dynSize > 0 {
			p.fillDynamicInfo(info, p.parseDynamicList(ctx, dynOff, dynSize))
		}
	}

	info.PIE = info.PIE || (p.Header.Type == ET_DYN && info.Interp != "")

	p.fillSymbolInfo(info)

	if funcs, err := p.DiscoverFunctionsContext(ctx); err == nil {
		info.DiscoveredFuncs = len(funcs)
	}

	return info, nil
}

func (p *ELFParser) fillDynamicInfo(info *ELFInfo, entries []dynEntry) {
	var flags, flags1 uint64
	var strtab uint64
	haveStrtab := false
	for _, e := range entries {
		switch e.tag {
		case DT_STRTAB:
			strtab, haveStrtab = e.val, true
		case DT_FLAGS:
			flags = e.val
		case DT_FLAGS_1:
			flags1 = e.val
		}
	}

	// String-valued tags reference DT_STRTAB, which may appear later in
	// the dynamic array, so resolve them only after the first pass.
	for _, e := range entries {
		switch e.tag {
		case DT_NEEDED:
			if s := p.readDynString(strtab, haveStrtab, e.val); s != "" {
				info.Needed = append(info.Needed, s)
			}
		case DT_SONAME:
			if s := p.readDynString(strtab, haveStrtab, e.val); s != "" {
				info.SONAME = s
			}
		case DT_RPATH:
			if s := p.readDynString(strtab, haveStrtab, e.val); s != "" {
				info.RPATH = splitSearchPath(s)
			}
		case DT_RUNPATH:
			if s := p.readDynString(strtab, haveStrtab, e.val); s != "" {
				info.RUNPATH = splitSearchPath(s)
			}
		}
	}

	info.BindNow = flags&DF_BIND_NOW != 0 || flags1&DF_1_NOW != 0
	info.PIE = info.PIE || flags1&DF_1_PIE != 0
}

func (p *ELFParser) fillSymbolInfo(info *ELFInfo) {
	info.SymbolCount = len(p.Symbols)
	for _, sym := range p.Symbols {
		name := p.GetSymbolName(sym)
		if name == "" {
			continue
		}
		defined := sym.Shndx != SHN_UNDEF
		if defined {
			info.DefinedSymbols++
		} else {
			info.UndefinedSymbols++
			info.Imports = append(info.Imports, name)
		}
		if name == "__stack_chk_fail" || name == "__stack_chk_guard" {
			info.Canary = true
		}
		if strings.HasSuffix(name, "_chk") && !defined {
			info.FORTIFYFuncs++
		}
		if sym.Info&0xf != STT_FUNC {
			continue
		}
		if defined {
			info.FunctionCount++
			bind := sym.Info >> 4
			if bind == STB_GLOBAL || bind == STB_WEAK {
				info.Exports = append(info.Exports, name)
			}
		}
	}
	sort.Strings(info.Imports)
	sort.Strings(info.Exports)
	info.Imports = dedupeSorted(info.Imports)
	info.Exports = dedupeSorted(info.Exports)
}

func dedupeSorted(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

func splitSearchPath(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ":") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// parseDynamicList is parseDynamicEntries without the tag->value map:
// duplicate tags (notably DT_NEEDED) must be preserved.
func (p *ELFParser) parseDynamicList(ctx context.Context, off, size uint64) []dynEntry {
	var out []dynEntry
	if off >= uint64(len(p.Data)) {
		return out
	}
	entSize := uint64(16)
	if p.Header.Class != ELFCLASS64 {
		entSize = 8
	}
	if size > uint64(len(p.Data))-off {
		size = uint64(len(p.Data)) - off
	}
	end := off + size
	for pos := off; pos+entSize <= end; pos += entSize {
		if pos&0xFFF == 0 && ctx.Err() != nil {
			return out
		}
		var tag int64
		var val uint64
		if p.IsEndian {
			if p.Header.Class == ELFCLASS64 {
				tag = int64(binary.LittleEndian.Uint64(p.Data[pos : pos+8]))
				val = binary.LittleEndian.Uint64(p.Data[pos+8 : pos+16])
			} else {
				tag = int64(int32(binary.LittleEndian.Uint32(p.Data[pos : pos+4])))
				val = uint64(binary.LittleEndian.Uint32(p.Data[pos+4 : pos+8]))
			}
		} else {
			if p.Header.Class == ELFCLASS64 {
				tag = int64(binary.BigEndian.Uint64(p.Data[pos : pos+8]))
				val = binary.BigEndian.Uint64(p.Data[pos+8 : pos+16])
			} else {
				tag = int64(int32(binary.BigEndian.Uint32(p.Data[pos : pos+4])))
				val = uint64(binary.BigEndian.Uint32(p.Data[pos+4 : pos+8]))
			}
		}
		if tag == DT_NULL {
			break
		}
		out = append(out, dynEntry{tag: tag, val: val})
	}
	return out
}

func (p *ELFParser) readDynString(strtab uint64, haveStrtab bool, off uint64) string {
	if !haveStrtab || strtab == 0 {
		return ""
	}
	sec, ok := p.SectionForAddr(strtab)
	if !ok || off >= sec.Size || !p.elfRange(sec.Offset, sec.Size) {
		return ""
	}
	pos := sec.Offset + off
	if pos >= uint64(len(p.Data)) {
		return ""
	}
	end := bytes.IndexByte(p.Data[pos:], 0)
	if end < 0 || end > maxCStringLen {
		return ""
	}
	return string(p.Data[pos : pos+uint64(end)])
}

func (p *ELFParser) readCStringAtOffset(off uint64) string {
	if off >= uint64(len(p.Data)) {
		return ""
	}
	end := bytes.IndexByte(p.Data[off:], 0)
	if end < 0 || end > maxCStringLen {
		return ""
	}
	return string(p.Data[off : off+uint64(end)])
}

func elfClassName(c uint8) string {
	if c == ELFCLASS32 {
		return "ELF32"
	}
	return "ELF64"
}

func elfDataName(d uint8) string {
	if d == ELFDATA2LSB {
		return "little-endian"
	}
	return "big-endian"
}

func elfOSABIName(o uint8) string {
	switch o {
	case 0:
		return "System V"
	case 3:
		return "Linux"
	case 6:
		return "Solaris"
	case 9:
		return "FreeBSD"
	case 12:
		return "OpenBSD"
	default:
		return fmt.Sprintf("0x%x", o)
	}
}

func elfTypeName(t uint16) string {
	switch t {
	case 1:
		return "REL (relocatable)"
	case 2:
		return "EXEC (executable)"
	case 3:
		return "DYN (shared object/PIE)"
	case 4:
		return "CORE"
	default:
		return fmt.Sprintf("0x%x", t)
	}
}

func elfMachineName(m uint16) string {
	switch m {
	case EM_AARCH64:
		return "AArch64"
	case EM_ARM:
		return "ARM"
	case EM_386:
		return "x86"
	case EM_X86_64:
		return "x86-64"
	default:
		return fmt.Sprintf("machine 0x%x", m)
	}
}

func elfSectionTypeName(t uint32) string {
	switch t {
	case 0:
		return "NULL"
	case SHT_PROGBITS:
		return "PROGBITS"
	case SHT_SYMTAB:
		return "SYMTAB"
	case SHT_STRTAB:
		return "STRTAB"
	case SHT_RELA:
		return "RELA"
	case 9:
		return "REL"
	case SHT_HASH:
		return "HASH"
	case SHT_DYNAMIC:
		return "DYNAMIC"
	case 8:
		return "NOBITS"
	case SHT_DYNSYM:
		return "DYNSYM"
	case SHT_GNU_HASH:
		return "GNU_HASH"
	case 0x6ffffffd:
		return "VERDEF"
	case 0x6ffffffe:
		return "VERNEED"
	case 0x6fffffff:
		return "VERSYM"
	default:
		return fmt.Sprintf("0x%x", t)
	}
}

func elfSectionFlags(f uint64) string {
	var b strings.Builder
	if f&SHF_WRITE != 0 {
		b.WriteByte('W')
	}
	if f&SHF_ALLOC != 0 {
		b.WriteByte('A')
	}
	if f&SHF_EXECINSTR != 0 {
		b.WriteByte('X')
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}
