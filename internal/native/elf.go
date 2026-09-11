package native

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// ELF constants
const (
	ELF_MAGIC    = "\x7fELF"
	ELFCLASS32   = 1
	ELFCLASS64   = 2
	ELFDATA2LSB  = 1
	ELFDATA2MSB  = 2
	ET_EXEC      = 2
	ET_DYN       = 3
	EM_ARM       = 40
	EM_AARCH64   = 183
	EM_386       = 3
	EM_X86_64    = 62
	SHT_PROGBITS = 1
	SHT_SYMTAB   = 2
	SHT_STRTAB   = 3
	SHT_RELA     = 4
	SHT_HASH     = 5
	SHT_DYNAMIC  = 6
	SHT_DYNSYM   = 11
	SHT_GNU_HASH = 0x6ffffff6
	STT_FUNC     = 2

	// Section flags (sh_flags)
	SHF_WRITE     = 0x1
	SHF_ALLOC     = 0x2
	SHF_EXECINSTR = 0x4

	// Program header types (p_type)
	PT_LOAD         = 1
	PT_DYNAMIC      = 2
	PT_GNU_EH_FRAME = 0x6474e550

	// Program header flags (p_flags)
	PF_X = 0x1
	PF_W = 0x2
	PF_R = 0x4

	// Dynamic array tags (d_tag)
	DT_NULL     = 0
	DT_PLTRELSZ = 2
	DT_PLTGOT   = 3
	DT_HASH     = 4
	DT_STRTAB   = 5
	DT_SYMTAB   = 6
	DT_RELA     = 7
	DT_RELASZ   = 8
	DT_RELAENT  = 9
	DT_STRSZ    = 10
	DT_SYMENT   = 11
	DT_JMPREL   = 23
	DT_GNU_HASH = 0x6ffffef5
)

// ProgramHeader is one entry of the ELF program header table. Only the
// fields this parser needs are kept - see parseProgramSections' own doc
// comment for why program headers matter even when section headers don't
// exist.
type ProgramHeader struct {
	Type   uint32
	Flags  uint32
	Offset uint64
	Vaddr  uint64
	Paddr  uint64
	FileSz uint64
	MemSz  uint64
	Align  uint64
}

// ELF file structures
type ELFHeader struct {
	Magic     [4]byte
	Class     uint8
	Data      uint8
	Version   uint8
	OSABI     uint8
	Padding   [8]byte
	Type      uint16
	Machine   uint16
	Version2  uint32
	Entry     uint64
	PhOff     uint64
	ShOff     uint64
	Flags     uint32
	EhSize    uint16
	PhEntSize uint16
	PhNum     uint16
	ShEntSize uint16
	ShNum     uint16
	ShStrNdx  uint16
}

type SectionHeader struct {
	Name      uint32
	Type      uint32
	Flags     uint64
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	AddrAlign uint64
	EntSize   uint64
	// SynthName is a name for a section synthesized from a program
	// header/dynamic entry (see parseProgramSections) - such a section
	// has no backing entry in a section-name string table at all, so
	// this is checked first by getSectionName. Empty for every section
	// read from a real section header.
	SynthName string
}

type SymbolEntry struct {
	Name  uint32
	Info  uint8
	Other uint8
	Shndx uint16
	Value uint64
	Size  uint64
}

// ELFParser parses ELF files
type ELFParser struct {
	File     *os.File
	Data     []byte
	Header   ELFHeader
	Sections []SectionHeader
	Symbols  []SymbolEntry
	Arch     int
	Mode     int
	Bits     int
	IsEndian bool // true = little endian
	// SymStrTabNdx is the section index of the string table holding
	// symbol NAMES (as opposed to Header.ShStrNdx, which is the
	// string table for SECTION names - a different table entirely).
	// Captured from the symbol table section's own sh_link field when
	// parseSymbols runs, since that's the only correct way to find it
	// (there's no fixed/well-known index for it the way section names
	// always live at Header.ShStrNdx).
	SymStrTabNdx uint16
	// FromSegments is true when the file had no usable section header
	// table and p.Sections was synthesized from the program headers
	// instead (see parseProgramSections). Kept as an explicit flag
	// because callers like ReadCString need to know the usual section
	// granularity (separate .text/.rodata) isn't available.
	FromSegments bool
}

// NewELFParser creates a new ELF parser
func NewELFParser(path string) (*ELFParser, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	if len(data) < 16 {
		return nil, fmt.Errorf("file too small for ELF header")
	}

	if string(data[:4]) != ELF_MAGIC {
		return nil, fmt.Errorf("not an ELF file")
	}

	p := &ELFParser{
		Data: data,
	}

	if err := p.parseHeader(); err != nil {
		return nil, err
	}

	if err := p.parseSections(); err != nil {
		return nil, err
	}

	if len(p.Sections) == 0 {
		// e_shoff/e_shnum can legitimately be zeroed by a packer,
		// protector, or an aggressive strip even though the program
		// headers - which the kernel loader and dynamic linker actually
		// need - are all still present and complete. Rebuild an
		// equivalent section view from PT_LOAD/PT_DYNAMIC/
		// PT_GNU_EH_FRAME so every later stage (symbol parsing,
		// .eh_frame_hdr function discovery, code-section extraction,
		// string/GOT resolution) keeps working.
		if err := p.parseProgramSections(); err != nil {
			return nil, err
		}
	}

	if err := p.parseSymbols(); err != nil {
		// Symbols are optional
		fmt.Fprintf(os.Stderr, "warning: could not parse symbols: %v\n", err)
	}

	return p, nil
}

func (p *ELFParser) parseHeader() error {
	if len(p.Data) < 64 {
		return fmt.Errorf("ELF header too small")
	}

	p.Header.Class = p.Data[4]
	p.Header.Data = p.Data[5]

	// Determine endianness
	littleEndian := p.Header.Data == ELFDATA2LSB
	p.IsEndian = littleEndian

	var readUint32 func([]byte) uint32
	var readUint64 func([]byte) uint64

	if littleEndian {
		readUint32 = binary.LittleEndian.Uint32
		readUint64 = binary.LittleEndian.Uint64
	} else {
		readUint32 = binary.BigEndian.Uint32
		readUint64 = binary.BigEndian.Uint64
	}

	p.Header.Type = binary.LittleEndian.Uint16(p.Data[16:18])
	p.Header.Machine = binary.LittleEndian.Uint16(p.Data[18:20])
	p.Header.Version2 = readUint32(p.Data[20:24])

	if p.Header.Class == ELFCLASS64 {
		p.Header.Entry = readUint64(p.Data[24:32])
		p.Header.PhOff = readUint64(p.Data[32:40])
		p.Header.ShOff = readUint64(p.Data[40:48])
		p.Header.Flags = readUint32(p.Data[48:52])
		p.Header.EhSize = binary.LittleEndian.Uint16(p.Data[52:54])
		p.Header.PhEntSize = binary.LittleEndian.Uint16(p.Data[54:56])
		p.Header.PhNum = binary.LittleEndian.Uint16(p.Data[56:58])
		p.Header.ShEntSize = binary.LittleEndian.Uint16(p.Data[58:60])
		p.Header.ShNum = binary.LittleEndian.Uint16(p.Data[60:62])
		p.Header.ShStrNdx = binary.LittleEndian.Uint16(p.Data[62:64])
		p.Bits = 64
	} else {
		p.Header.Entry = uint64(readUint32(p.Data[24:28]))
		p.Header.PhOff = uint64(readUint32(p.Data[28:32]))
		p.Header.ShOff = uint64(readUint32(p.Data[32:36]))
		p.Header.Flags = readUint32(p.Data[36:40])
		p.Header.EhSize = binary.LittleEndian.Uint16(p.Data[40:42])
		p.Header.PhEntSize = binary.LittleEndian.Uint16(p.Data[42:44])
		p.Header.PhNum = binary.LittleEndian.Uint16(p.Data[44:46])
		p.Header.ShEntSize = binary.LittleEndian.Uint16(p.Data[46:48])
		p.Header.ShNum = binary.LittleEndian.Uint16(p.Data[48:50])
		p.Header.ShStrNdx = binary.LittleEndian.Uint16(p.Data[50:52])
		p.Bits = 32
	}

	// Set architecture
	switch p.Header.Machine {
	case EM_AARCH64:
		p.Arch = ArchARM64
		p.Mode = ModeARM64 | ModeLITTLE_ENDIAN
	case EM_ARM:
		p.Arch = ArchARM
		p.Mode = ModeARM | ModeLITTLE_ENDIAN
	case EM_386:
		p.Arch = ArchX86
		p.Mode = Mode32
	case EM_X86_64:
		p.Arch = ArchX86
		p.Mode = Mode64
	default:
		return fmt.Errorf("unsupported architecture: %d", p.Header.Machine)
	}

	return nil
}

func (p *ELFParser) parseSections() error {
	if p.Header.ShOff == 0 || p.Header.ShNum == 0 {
		return nil
	}

	var readUint32 func([]byte) uint32
	var readUint64 func([]byte) uint64

	if p.IsEndian {
		readUint32 = binary.LittleEndian.Uint32
		readUint64 = binary.LittleEndian.Uint64
	} else {
		readUint32 = binary.BigEndian.Uint32
		readUint64 = binary.BigEndian.Uint64
	}

	p.Sections = make([]SectionHeader, p.Header.ShNum)
	offset := p.Header.ShOff

	for i := 0; i < int(p.Header.ShNum); i++ {
		if offset+uint64(p.Header.ShEntSize) > uint64(len(p.Data)) {
			break
		}

		data := p.Data[offset:]
		s := SectionHeader{}

		if p.Header.Class == ELFCLASS64 {
			s.Name = readUint32(data[0:4])
			s.Type = readUint32(data[4:8])
			s.Flags = readUint64(data[8:16])
			s.Addr = readUint64(data[16:24])
			s.Offset = readUint64(data[24:32])
			s.Size = readUint64(data[32:40])
			s.Link = readUint32(data[40:44])
			s.Info = readUint32(data[44:48])
			s.AddrAlign = readUint64(data[48:56])
			s.EntSize = readUint64(data[56:64])
		} else {
			s.Name = readUint32(data[0:4])
			s.Type = readUint32(data[4:8])
			s.Flags = uint64(readUint32(data[8:12]))
			s.Addr = uint64(readUint32(data[12:16]))
			s.Offset = uint64(readUint32(data[16:20]))
			s.Size = uint64(readUint32(data[20:24]))
			s.Link = readUint32(data[24:28])
			s.Info = readUint32(data[28:32])
			s.AddrAlign = uint64(readUint32(data[32:36]))
			s.EntSize = uint64(readUint32(data[36:40]))
		}

		p.Sections[i] = s
		offset += uint64(p.Header.ShEntSize)
	}

	return nil
}

// parseProgramHeaders reads the ELF program header table. Program
// headers map the file onto memory for the kernel's loader and carry
// the dynamic linking metadata (PT_DYNAMIC, PT_GNU_EH_FRAME), so unlike
// section headers they must survive in any runnable binary.
func (p *ELFParser) parseProgramHeaders() ([]ProgramHeader, error) {
	if p.Header.PhOff == 0 || p.Header.PhNum == 0 {
		return nil, nil
	}

	var readUint32 func([]byte) uint32
	var readUint64 func([]byte) uint64
	if p.IsEndian {
		readUint32 = binary.LittleEndian.Uint32
		readUint64 = binary.LittleEndian.Uint64
	} else {
		readUint32 = binary.BigEndian.Uint32
		readUint64 = binary.BigEndian.Uint64
	}

	entSize := uint64(p.Header.PhEntSize)
	if entSize == 0 {
		if p.Header.Class == ELFCLASS64 {
			entSize = 56
		} else {
			entSize = 32
		}
	}
	minSize := uint64(56)
	if p.Header.Class != ELFCLASS64 {
		minSize = 32
	}
	if entSize < minSize {
		entSize = minSize
	}

	phdrs := make([]ProgramHeader, 0, p.Header.PhNum)
	offset := p.Header.PhOff
	for i := 0; i < int(p.Header.PhNum); i++ {
		if offset+entSize > uint64(len(p.Data)) {
			break
		}
		data := p.Data[offset:]

		ph := ProgramHeader{}
		if p.Header.Class == ELFCLASS64 {
			ph.Type = readUint32(data[0:4])
			ph.Flags = readUint32(data[4:8])
			ph.Offset = readUint64(data[8:16])
			ph.Vaddr = readUint64(data[16:24])
			ph.Paddr = readUint64(data[24:32])
			ph.FileSz = readUint64(data[32:40])
			ph.MemSz = readUint64(data[40:48])
			ph.Align = readUint64(data[48:56])
		} else {
			ph.Type = readUint32(data[0:4])
			ph.Offset = uint64(readUint32(data[4:8]))
			ph.Vaddr = uint64(readUint32(data[8:12]))
			ph.Paddr = uint64(readUint32(data[12:16]))
			ph.FileSz = uint64(readUint32(data[16:20]))
			ph.MemSz = uint64(readUint32(data[20:24]))
			ph.Flags = readUint32(data[24:28])
			ph.Align = uint64(readUint32(data[28:32]))
		}

		phdrs = append(phdrs, ph)
		offset += entSize
	}

	return phdrs, nil
}

// parseProgramSections synthesizes a section view for a binary whose
// section header table is missing or empty (e_shoff/e_shnum zeroed by a
// packer, protector, or full strip). The program headers are still
// required for the file to run at all, so they carry everything the
// rest of this package needs:
//
//   - PT_LOAD segments become pseudo PROGBITS sections with their
//     real permissions, so GetCodeSections/ReadCString/DataReader and
//     readFunctionCode still find code and data by address.
//   - PT_GNU_EH_FRAME becomes ".eh_frame_hdr", so DiscoverFunctions'
//     unwind-table fallback still recovers function boundaries for a
//     fully stripped binary.
//   - PT_DYNAMIC's entries (DT_SYMTAB/DT_STRTAB/DT_RELA/DT_JMPREL...)
//     become ".dynsym"/".dynstr"/".rela.dyn"/".rela.plt" pseudo
//     sections, so symbol names, imports, and GOT references still
//     resolve.
//
// The only thing genuinely lost is the finer .text/.rodata split that
// real section headers normally provide; FromSegments marks that so
// ReadCString can widen its search (see its own doc comment).
func (p *ELFParser) parseProgramSections() error {
	phdrs, err := p.parseProgramHeaders()
	if err != nil {
		return err
	}
	if len(phdrs) == 0 {
		return nil
	}

	vaddrToOffset := func(vaddr uint64) (uint64, bool) {
		for _, ph := range phdrs {
			if ph.Type != PT_LOAD || ph.FileSz == 0 {
				continue
			}
			if vaddr >= ph.Vaddr && vaddr < ph.Vaddr+ph.FileSz {
				return ph.Offset + (vaddr - ph.Vaddr), true
			}
		}
		return 0, false
	}

	var dynPh *ProgramHeader
	for i := range phdrs {
		ph := &phdrs[i]
		switch ph.Type {
		case PT_LOAD:
			flags := uint64(0)
			if ph.Flags&PF_R != 0 {
				flags |= SHF_ALLOC
			}
			if ph.Flags&PF_W != 0 {
				flags |= SHF_WRITE
			}
			if ph.Flags&PF_X != 0 {
				flags |= SHF_EXECINSTR
			}
			name := ".rodata"
			switch {
			case ph.Flags&PF_X != 0:
				name = ".text"
			case ph.Flags&PF_W != 0:
				name = ".data"
			}
			p.Sections = append(p.Sections, SectionHeader{
				SynthName: name,
				Type:      SHT_PROGBITS,
				Flags:     flags,
				Addr:      ph.Vaddr,
				Offset:    ph.Offset,
				Size:      ph.FileSz,
				AddrAlign: ph.Align,
			})
		case PT_GNU_EH_FRAME:
			p.Sections = append(p.Sections, SectionHeader{
				SynthName: ".eh_frame_hdr",
				Type:      SHT_PROGBITS,
				Flags:     SHF_ALLOC,
				Addr:      ph.Vaddr,
				Offset:    ph.Offset,
				Size:      ph.FileSz,
				AddrAlign: ph.Align,
			})
		case PT_DYNAMIC:
			dynPh = ph
		}
	}
	p.FromSegments = true

	if dynPh == nil || dynPh.FileSz == 0 {
		return nil
	}
	dynOff := dynPh.Offset
	if dynOff == 0 {
		var ok bool
		dynOff, ok = vaddrToOffset(dynPh.Vaddr)
		if !ok {
			return nil
		}
	}
	dyn := p.parseDynamicEntries(dynOff, dynPh.FileSz)

	addSection := func(name string, typ uint32, addr, size, entSize uint64) int {
		off, _ := vaddrToOffset(addr)
		p.Sections = append(p.Sections, SectionHeader{
			SynthName: name,
			Type:      typ,
			Flags:     SHF_ALLOC,
			Addr:      addr,
			Offset:    off,
			Size:      size,
			EntSize:   entSize,
		})
		return len(p.Sections) - 1
	}

	syment := dyn[DT_SYMENT]
	if syment == 0 {
		syment = 24
		if p.Header.Class != ELFCLASS64 {
			syment = 16
		}
	}

	dynstrIdx := -1
	if strtab, ok := dyn[DT_STRTAB]; ok {
		dynstrIdx = addSection(".dynstr", SHT_STRTAB, strtab, dyn[DT_STRSZ], 0)
	}

	dynsymIdx := -1
	if symtab, ok := dyn[DT_SYMTAB]; ok && dynstrIdx >= 0 {
		count := p.dynamicSymbolCount(dyn, syment, vaddrToOffset)
		dynsymIdx = addSection(".dynsym", SHT_DYNSYM, symtab, count*syment, syment)
		p.Sections[dynsymIdx].Link = uint32(dynstrIdx)
	}

	relaEnt := dyn[DT_RELAENT]
	if relaEnt == 0 {
		relaEnt = 24
		if p.Header.Class != ELFCLASS64 {
			relaEnt = 12
		}
	}
	if rela, ok := dyn[DT_RELA]; ok && dyn[DT_RELASZ] > 0 {
		idx := addSection(".rela.dyn", SHT_RELA, rela, dyn[DT_RELASZ], relaEnt)
		if dynsymIdx >= 0 {
			p.Sections[idx].Link = uint32(dynsymIdx)
		}
	}
	if jmprel, ok := dyn[DT_JMPREL]; ok && dyn[DT_PLTRELSZ] > 0 {
		idx := addSection(".rela.plt", SHT_RELA, jmprel, dyn[DT_PLTRELSZ], relaEnt)
		if dynsymIdx >= 0 {
			p.Sections[idx].Link = uint32(dynsymIdx)
		}
	}

	return nil
}

// parseDynamicEntries reads a PT_DYNAMIC table into tag->value form.
// A DT_NULL entry terminates the array (per the ELF spec), though some
// linkers also zero-pad afterwards, which the size bound alone would
// otherwise misread as more DT_NULL entries - harmless since the map
// only ever gets looked up by specific tags.
func (p *ELFParser) parseDynamicEntries(off, size uint64) map[int64]uint64 {
	entries := make(map[int64]uint64)
	if off >= uint64(len(p.Data)) {
		return entries
	}

	entSize := uint64(16)
	if p.Header.Class != ELFCLASS64 {
		entSize = 8
	}
	end := off + size
	if end > uint64(len(p.Data)) {
		end = uint64(len(p.Data))
	}

	for pos := off; pos+entSize <= end; pos += entSize {
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
		entries[tag] = val
	}

	return entries
}

// dynamicSymbolCount returns the number of entries in the dynamic
// symbol table, which (unlike a section header's sh_size) isn't spelled
// out directly in the dynamic array. DT_HASH stores it outright as
// nchain; DT_GNU_HASH requires walking buckets/chains (and, for a
// binary that exports nothing, its bucket array can be all zeros, in
// which case the pre-hash symbol count DT_GNU_HASH also stores is the
// answer); if neither is present, fall back to the distance between
// DT_SYMTAB and DT_STRTAB, which adjacent-table linkers make exact.
func (p *ELFParser) dynamicSymbolCount(dyn map[int64]uint64, syment uint64, vaddrToOffset func(uint64) (uint64, bool)) uint64 {
	if hashAddr, ok := dyn[DT_HASH]; ok {
		if off, ok := vaddrToOffset(hashAddr); ok && off+8 <= uint64(len(p.Data)) {
			read32 := binary.LittleEndian.Uint32
			if !p.IsEndian {
				read32 = binary.BigEndian.Uint32
			}
			nchain := read32(p.Data[off+4 : off+8])
			if nchain > 0 {
				return uint64(nchain)
			}
		}
	}

	if ghAddr, ok := dyn[DT_GNU_HASH]; ok {
		if off, ok := vaddrToOffset(ghAddr); ok {
			if count, ok := p.gnuHashSymbolCount(off); ok && count > 0 {
				return count
			}
		}
	}

	if symtab, ok := dyn[DT_SYMTAB]; ok && syment > 0 {
		if strtab, ok := dyn[DT_STRTAB]; ok && strtab > symtab {
			if count := (strtab - symtab) / syment; count > 0 {
				return count
			}
		}
	}

	return 0
}

// gnuHashSymbolCount derives the total dynamic symbol count from a GNU
// hash table at file offset off. Layout (ELF64 word sizes): nbuckets,
// symoffset, bloom_size, bloom_shift, bloom_size*8 bytes of bloom
// filter, nbuckets 32-bit buckets, then one 32-bit chain per hashed
// symbol. Every bucket is a symbol index; the chain word belonging to a
// bucket's last symbol has its low bit set, so walking the chains of
// the highest bucket index gives the symbol table's end.
func (p *ELFParser) gnuHashSymbolCount(off uint64) (uint64, bool) {
	data := p.Data
	if off+16 > uint64(len(data)) {
		return 0, false
	}

	read32 := binary.LittleEndian.Uint32
	if !p.IsEndian {
		read32 = binary.BigEndian.Uint32
	}

	nbuckets := read32(data[off : off+4])
	symoffset := read32(data[off+4 : off+8])
	bloomSize := read32(data[off+8 : off+12])

	wordSize := uint64(8)
	if p.Header.Class != ELFCLASS64 {
		wordSize = 4
	}
	bucketsOff := off + 16 + uint64(bloomSize)*wordSize
	if bucketsOff > uint64(len(data)) || uint64(nbuckets) > (uint64(len(data))-bucketsOff)/4 {
		return 0, false
	}

	maxSym := uint32(0)
	for i := uint32(0); i < nbuckets; i++ {
		b := read32(data[bucketsOff+uint64(i)*4 : bucketsOff+uint64(i)*4+4])
		if b > maxSym {
			maxSym = b
		}
	}
	if maxSym == 0 {
		// No symbol is reachable through the hash table at all. That's
		// legitimate for a binary exporting nothing (an executable): the
		// dynamic linker finds its imports by index through the
		// relocation tables, not by name, so the hash can be empty. Every
		// symbol before symoffset still exists, symoffset being where the
		// (empty) hashed region starts.
		return uint64(symoffset), true
	}

	chainsOff := bucketsOff + uint64(nbuckets)*4
	idx := uint64(maxSym)
	for {
		if idx < uint64(symoffset) {
			return 0, false
		}
		pos := chainsOff + (idx-uint64(symoffset))*4
		if pos+4 > uint64(len(data)) {
			return 0, false
		}
		word := read32(data[pos : pos+4])
		idx++
		if word&1 != 0 {
			break
		}
	}
	return idx, true
}

func (p *ELFParser) parseSymbols() error {
	for _, s := range p.Sections {
		if s.Type == SHT_SYMTAB {
			p.SymStrTabNdx = uint16(s.Link)
			return p.parseSymbolTable(s)
		}
	}
	// No .symtab (a stripped binary - the common case for a real-world
	// release build) - fall back to .dynsym, which a linker can never
	// fully strip from a dynamically linked binary, since the dynamic
	// linker itself needs it at load time to resolve imports/exports.
	// A stripped SHARED LIBRARY in particular often still has every one
	// of its exported functions (its real public API surface) listed
	// here with real addresses and sizes, even with zero private/
	// internal symbols left - this is what lets an otherwise
	// symbol-less binary still decompile at all (see
	// ELFParser.SymbolResolver's own doc comment).
	dynsyms, dynstrNdx, err := p.parseDynsym()
	if err != nil {
		return fmt.Errorf("no symbol table found (checked .symtab and .dynsym): %w", err)
	}
	p.Symbols = dynsyms
	p.SymStrTabNdx = dynstrNdx
	return nil
}

func (p *ELFParser) parseSymbolTable(sec SectionHeader) error {
	var readUint32 func([]byte) uint32
	var readUint64 func([]byte) uint64

	if p.IsEndian {
		readUint32 = binary.LittleEndian.Uint32
		readUint64 = binary.LittleEndian.Uint64
	} else {
		readUint32 = binary.BigEndian.Uint32
		readUint64 = binary.BigEndian.Uint64
	}

	entSize := uint64(24) // Default for 64-bit
	if p.Header.Class != ELFCLASS64 {
		entSize = 16
	}

	if sec.EntSize > 0 {
		entSize = sec.EntSize
	}

	count := sec.Size / entSize
	p.Symbols = make([]SymbolEntry, 0, count)

	offset := sec.Offset
	for i := uint64(0); i < count; i++ {
		if offset+entSize > uint64(len(p.Data)) {
			break
		}

		data := p.Data[offset:]
		sym := SymbolEntry{}

		if p.Header.Class == ELFCLASS64 {
			sym.Name = readUint32(data[0:4])
			sym.Info = data[4]
			sym.Other = data[5]
			sym.Shndx = binary.LittleEndian.Uint16(data[6:8])
			sym.Value = readUint64(data[8:16])
			sym.Size = readUint64(data[16:24])
		} else {
			sym.Name = readUint32(data[0:4])
			sym.Value = uint64(readUint32(data[4:8]))
			sym.Size = uint64(readUint32(data[8:12]))
			sym.Info = data[12]
			sym.Other = data[13]
			sym.Shndx = binary.LittleEndian.Uint16(data[14:16])
		}

		if sym.Info&0xf == STT_FUNC {
			p.Symbols = append(p.Symbols, sym)
		}

		offset += entSize
	}

	return nil
}

// GetSymbolName returns the name of a symbol
func (p *ELFParser) GetSymbolName(sym SymbolEntry) string {
	strTabNdx := p.SymStrTabNdx
	if strTabNdx == 0 {
		// No .symtab was parsed (SymStrTabNdx never set) - fall back to
		// the section-name string table, which is wrong in general but
		// preserves this function's old behavior for callers that
		// somehow still get a SymbolEntry without a real symbol table
		// having been parsed.
		strTabNdx = p.Header.ShStrNdx
	}
	if int(strTabNdx) >= len(p.Sections) {
		return ""
	}

	strSec := p.Sections[strTabNdx]
	if uint64(sym.Name)+256 > strSec.Size {
		return ""
	}

	start := strSec.Offset + uint64(sym.Name)
	if start >= uint64(len(p.Data)) {
		return ""
	}

	// Read until null terminator
	end := bytes.IndexByte(p.Data[start:], 0)
	if end < 0 {
		end = 256
	}

	return string(p.Data[start : start+uint64(end)])
}

// maxCStringLen bounds how many bytes ReadCString will scan for a NUL
// terminator - just a sanity limit against a corrupt/adversarial file
// claiming a huge section size, not a real string-length limit (a
// literal this long would be unusual for the log/error-message strings
// this exists to recover).
const maxCStringLen = 4096

// ReadCString reads a NUL-terminated string literal stored at absolute
// virtual address vaddr - the data half of the adrp/adr(+add) address
// computation idiom arm64lift's string-literal resolution uses (an
// adrp/adr alone gives an address; this turns that address into the
// actual text sitting there, the way a real string literal would
// appear in decompiled source).
//
// Deliberately restricted to non-executable PROGBITS sections (real
// rodata/data, never .text): reading through an address that happens
// to land in code would just decode raw instruction bytes as if they
// were text, producing plausible-looking but meaningless garbage
// rather than a real literal - the isPrintableASCII check catches most
// such cases anyway, but excluding .text outright removes the failure
// mode entirely rather than relying on it being merely unlikely.
// Returns ("", false) if vaddr isn't inside such a section, has no NUL
// within maxCStringLen bytes, or the bytes before that NUL aren't
// printable text (most likely: vaddr points at binary data - a
// pointer, a vtable, a length-prefixed non-C-string - not a plain C
// string).
//
// For a sectionless binary (FromSegments) there is no separate .rodata
// to find, so the executable range is searched too - see the fallback
// loop's own comment.
func (p *ELFParser) ReadCString(vaddr uint64) (string, bool) {
	for _, s := range p.Sections {
		if s.Type != SHT_PROGBITS || s.Flags&SHF_EXECINSTR != 0 {
			continue
		}
		if str, ok := p.readCStringInSection(s, vaddr); ok {
			return str, true
		}
	}
	if p.FromSegments {
		// No section headers means no separate .text/.rodata view: the
		// whole RX segment is one executable PROGBITS section, so a real
		// string literal can only be found by looking inside it. The
		// printable-text check is what rejects instruction bytes here
		// (a random run of instructions decoding as printable ASCII up
		// to a NUL is vanishingly unlikely, and this path only exists
		// when the alternative is recovering no strings at all).
		for _, s := range p.Sections {
			if s.Type != SHT_PROGBITS || s.Flags&SHF_EXECINSTR == 0 {
				continue
			}
			if str, ok := p.readCStringInSection(s, vaddr); ok {
				return str, true
			}
		}
	}
	return "", false
}

// readCStringInSection resolves vaddr inside s and applies the
// printable-text/NUL-termination checks; shared by ReadCString's
// normal and sectionless paths.
func (p *ELFParser) readCStringInSection(s SectionHeader, vaddr uint64) (string, bool) {
	if vaddr < s.Addr || vaddr >= s.Addr+s.Size {
		return "", false
	}
	fileOff := s.Offset + (vaddr - s.Addr)
	if fileOff >= uint64(len(p.Data)) {
		return "", false
	}
	limit := s.Offset + s.Size
	if fileOff+maxCStringLen < limit {
		limit = fileOff + maxCStringLen
	}
	if limit > uint64(len(p.Data)) {
		limit = uint64(len(p.Data))
	}
	data := p.Data[fileOff:limit]
	nul := bytes.IndexByte(data, 0)
	if nul < 0 {
		return "", false
	}
	raw := data[:nul]
	if !isPrintableCString(raw) {
		return "", false
	}
	return string(raw), true
}

// isPrintableCString reports whether b looks like genuine printable
// text (printable ASCII, plus tab/newline/carriage-return) rather than
// arbitrary binary data that happened to end in a zero byte.
func isPrintableCString(b []byte) bool {
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// GetCodeSections returns all executable sections
func (p *ELFParser) GetCodeSections() []CodeSection {
	var sections []CodeSection

	for _, s := range p.Sections {
		if s.Type == SHT_PROGBITS && s.Size > 0 {
			// Check if executable flag is set (bit 2)
			if s.Flags&0x4 != 0 {
				offset := s.Offset
				if offset+s.Size > uint64(len(p.Data)) {
					continue
				}

				code := p.Data[s.Offset : s.Offset+s.Size]
				if len(code) == 0 {
					continue
				}

				name := p.getSectionName(s)
				sections = append(sections, CodeSection{
					Name:    name,
					Address: s.Addr,
					Size:    s.Size,
					Data:    code,
					Offset:  s.Offset,
				})
			}
		}
	}

	return sections
}

// getSectionName returns the name of a section
func (p *ELFParser) getSectionName(sec SectionHeader) string {
	if sec.SynthName != "" {
		return sec.SynthName
	}
	if int(p.Header.ShStrNdx) >= len(p.Sections) {
		return ""
	}

	strSec := p.Sections[p.Header.ShStrNdx]
	start := strSec.Offset + uint64(sec.Name)
	if start >= uint64(len(p.Data)) {
		return ""
	}

	end := bytes.IndexByte(p.Data[start:], 0)
	if end < 0 {
		end = 64
	}

	return string(p.Data[start : start+uint64(end)])
}

// CodeSection represents a section containing code
type CodeSection struct {
	Name    string
	Address uint64
	Size    uint64
	Data    []byte
	Offset  uint64
}

// DisassembleSection disassembles a code section using Capstone
func DisassembleSection(section CodeSection, arch, mode int) ([]Instruction, error) {
	d, err := NewDisassembler(arch, mode)
	if err != nil {
		return nil, fmt.Errorf("create disassembler: %w", err)
	}
	defer d.Close()

	return d.DisassembleAll(section.Data, section.Address)
}

// DisassembleELFFile disassembles all code sections in an ELF file
func DisassembleELFFile(path string, w io.Writer) error {
	parser, err := NewELFParser(path)
	if err != nil {
		return fmt.Errorf("parse ELF: %w", err)
	}

	sections := parser.GetCodeSections()
	if len(sections) == 0 {
		return fmt.Errorf("no code sections found")
	}

	fmt.Fprintf(w, "; ELF disassembly\n")
	fmt.Fprintf(w, "; Architecture: %s\n", GetArchName(parser.Arch))
	fmt.Fprintf(w, "; %d code sections\n\n", len(sections))

	for _, sec := range sections {
		fmt.Fprintf(w, "; ===== Section: %s @ 0x%x (%d bytes) =====\n",
			sec.Name, sec.Address, sec.Size)

		instructions, err := DisassembleSection(sec, parser.Arch, parser.Mode)
		if err != nil {
			fmt.Fprintf(w, "; Error disassembling: %v\n\n", err)
			continue
		}

		for _, inst := range instructions {
			// Try to find symbol name
			symName := ""
			for _, sym := range parser.Symbols {
				if sym.Value <= inst.Address && sym.Value+sym.Size > inst.Address {
					symName = parser.GetSymbolName(sym)
					break
				}
			}

			if symName != "" {
				fmt.Fprintf(w, "\n; %s:\n", symName)
			}

			// Print instruction bytes
			byteStr := ""
			for _, b := range inst.Bytes {
				byteStr += fmt.Sprintf("%02x ", b)
			}
			for len(byteStr) < 24 {
				byteStr += " "
			}

			fmt.Fprintf(w, "  %08x  %s  %-8s %s\n",
				inst.Address, byteStr, inst.Mnemonic, inst.OpStr)
		}

		fmt.Fprintln(w)
	}

	return nil
}

// RelaEntry is one Elf64_Rela relocation entry: r_offset (where the
// relocation applies - a GOT slot's address, for the JUMP_SLOT
// relocations PLT resolution cares about), r_info (packs the symbol
// table index in its upper 32 bits and the relocation type in its
// lower 32 bits), and r_addend (unused for JUMP_SLOT relocations).
type RelaEntry struct {
	Offset uint64
	Info   uint64
	Addend int64
}

// SymbolIndex returns the .dynsym index this relocation's symbol comes
// from (the upper 32 bits of Info).
func (r RelaEntry) SymbolIndex() uint32 {
	return uint32(r.Info >> 32)
}

// parseDynsym parses the .dynsym section (dynamic/import symbols,
// distinct from .symtab's locally-defined symbols) into a slice
// indexed the same way .rela.plt's relocation entries reference it -
// unlike parseSymbolTable (used for .symtab), this keeps every entry,
// including the mandatory empty entry 0 and non-function symbols,
// since RelaEntry.SymbolIndex() must be able to index directly into
// the result.
func (p *ELFParser) parseDynsym() ([]SymbolEntry, uint16, error) {
	var dynsymSec *SectionHeader
	for i := range p.Sections {
		if p.Sections[i].Type == SHT_DYNSYM {
			dynsymSec = &p.Sections[i]
			break
		}
	}
	if dynsymSec == nil {
		return nil, 0, fmt.Errorf("no .dynsym section found")
	}

	entSize := dynsymSec.EntSize
	if entSize == 0 {
		entSize = 24
		if p.Header.Class != ELFCLASS64 {
			entSize = 16
		}
	}
	count := dynsymSec.Size / entSize
	syms := make([]SymbolEntry, 0, count)

	var readUint32 func([]byte) uint32
	var readUint64 func([]byte) uint64
	if p.IsEndian {
		readUint32 = binary.LittleEndian.Uint32
		readUint64 = binary.LittleEndian.Uint64
	} else {
		readUint32 = binary.BigEndian.Uint32
		readUint64 = binary.BigEndian.Uint64
	}

	offset := dynsymSec.Offset
	for i := uint64(0); i < count; i++ {
		if offset+entSize > uint64(len(p.Data)) {
			break
		}
		data := p.Data[offset:]
		sym := SymbolEntry{}
		if p.Header.Class == ELFCLASS64 {
			sym.Name = readUint32(data[0:4])
			sym.Info = data[4]
			sym.Other = data[5]
			sym.Shndx = binary.LittleEndian.Uint16(data[6:8])
			sym.Value = readUint64(data[8:16])
			sym.Size = readUint64(data[16:24])
		} else {
			sym.Name = readUint32(data[0:4])
			sym.Value = uint64(readUint32(data[4:8]))
			sym.Size = uint64(readUint32(data[8:12]))
			sym.Info = data[12]
			sym.Other = data[13]
			sym.Shndx = binary.LittleEndian.Uint16(data[14:16])
		}
		syms = append(syms, sym)
		offset += entSize
	}

	return syms, uint16(dynsymSec.Link), nil
}

// parseRelaSection parses any SHT_RELA section (.rela.plt or .rela.dyn)
// into its individual relocation entries.
func (p *ELFParser) parseRelaSection(sec SectionHeader) []RelaEntry {
	entSize := sec.EntSize
	if entSize == 0 {
		if p.Header.Class == ELFCLASS64 {
			entSize = 24
		} else {
			entSize = 12
		}
	}
	count := sec.Size / entSize
	entries := make([]RelaEntry, 0, count)

	var readUint32 func([]byte) uint32
	var readUint64 func([]byte) uint64
	if p.IsEndian {
		readUint32 = binary.LittleEndian.Uint32
		readUint64 = binary.LittleEndian.Uint64
	} else {
		readUint32 = binary.BigEndian.Uint32
		readUint64 = binary.BigEndian.Uint64
	}

	offset := sec.Offset
	for i := uint64(0); i < count; i++ {
		if offset+entSize > uint64(len(p.Data)) {
			break
		}
		data := p.Data[offset:]
		if p.Header.Class == ELFCLASS64 {
			entries = append(entries, RelaEntry{
				Offset: readUint64(data[0:8]),
				Info:   readUint64(data[8:16]),
				Addend: int64(readUint64(data[16:24])),
			})
		} else {
			entries = append(entries, RelaEntry{
				Offset: uint64(readUint32(data[0:4])),
				Info:   uint64(readUint32(data[4:8])),
				Addend: int64(int32(readUint32(data[8:12]))),
			})
		}
		offset += entSize
	}
	return entries
}

// ResolvePLT builds a map from PLT stub address to imported function
// name (e.g. 0x18d70 -> "geteuid") by cross-referencing three pieces of
// ELF metadata: .dynsym (import names), .rela.plt (which GOT slot each
// import's JUMP_SLOT relocation targets), and the .plt section's own
// machine code (disassembled to recognize each 16-byte stub's
// "adrp x16, page; ldr x17, [x16, #off]; add x16, x16, #off; br x17"
// pattern and read which GOT slot it jumps through).
//
// A caller lifting "bl <addr>" can look addr up in the returned map to
// resolve it to the real imported function's name instead of treating
// it as an unknown/internal call.
func (p *ELFParser) ResolvePLT() (map[uint64]string, error) {
	dynsyms, dynstrNdx, err := p.parseDynsym()
	if err != nil {
		return nil, err
	}
	if int(dynstrNdx) >= len(p.Sections) {
		return nil, fmt.Errorf("invalid .dynsym string table index")
	}
	dynstrSec := p.Sections[dynstrNdx]

	dynsymName := func(sym SymbolEntry) string {
		start := dynstrSec.Offset + uint64(sym.Name)
		if start >= uint64(len(p.Data)) {
			return ""
		}
		end := bytes.IndexByte(p.Data[start:], 0)
		if end < 0 {
			return ""
		}
		return string(p.Data[start : start+uint64(end)])
	}

	// Map GOT slot address -> imported function name, from .rela.plt's
	// JUMP_SLOT relocations.
	gotToName := make(map[uint64]string)
	for _, sec := range p.Sections {
		if sec.Type != SHT_RELA || p.getSectionName(sec) != ".rela.plt" {
			continue
		}
		for _, rel := range p.parseRelaSection(sec) {
			idx := rel.SymbolIndex()
			if int(idx) >= len(dynsyms) {
				continue
			}
			name := dynsymName(dynsyms[idx])
			if name != "" {
				gotToName[rel.Offset] = name
			}
		}
	}

	// Disassemble .plt itself and recognize each stub's own GOT
	// reference, mapping the stub's start address to the same name its
	// GOT slot resolved to above.
	//
	// This ARM64-specific pattern recognition is only run on AArch64
	// binaries; for other architectures we fall back to the GOT map
	// alone, which still gives useful names for imported functions.
	if p.Header.Machine != EM_AARCH64 {
		return gotToName, nil
	}

	var pltSec *SectionHeader
	for i := range p.Sections {
		if p.getSectionName(p.Sections[i]) == ".plt" {
			pltSec = &p.Sections[i]
			break
		}
	}
	if pltSec == nil {
		return gotToName, nil // no .plt - return what .rela.plt alone gave us (rare, but not an error)
	}

	d, err := NewARM64Disassembler()
	if err != nil {
		return nil, fmt.Errorf("create disassembler: %w", err)
	}
	defer d.Close()

	pltCode := p.Data[pltSec.Offset : pltSec.Offset+pltSec.Size]
	insns, err := d.DisassembleDetailed(pltCode, pltSec.Addr)
	if err != nil {
		return nil, fmt.Errorf("disassemble .plt: %w", err)
	}

	result := make(map[uint64]string)
	// Each stub is exactly 4 instructions (adrp, ldr, add, br) in the
	// standard AAPCS64 PLT stub shape this project already relies on
	// (see the ptrace PLT-stub analysis this function automates).
	for i := 0; i+3 < len(insns); i += 4 {
		adrp, ldr, br := insns[i], insns[i+1], insns[i+3]
		if adrp.Mnemonic != "adrp" || ldr.Mnemonic != "ldr" || br.Mnemonic != "br" {
			continue
		}
		if len(adrp.Operands) != 2 || adrp.Operands[1].Type != OperandImm {
			continue
		}
		if len(ldr.Operands) != 2 || ldr.Operands[1].Type != OperandMem {
			continue
		}
		page := uint64(adrp.Operands[1].Imm)
		gotAddr := page + uint64(int64(ldr.Operands[1].Mem.Disp))
		if name, ok := gotToName[gotAddr]; ok {
			result[adrp.Address] = name
		}
	}

	return result, nil
}

// ARM64 relocation types this project's GOT/data-slot resolution
// cares about (from the AArch64 ELF ABI - ordinary Elf64_Rela type
// codes, not Capstone or anything ARM64-lifter-specific).
const (
	rAARCH64_ABS64    = 257
	rAARCH64_GLOB_DAT = 1025
	rAARCH64_RELATIVE = 1027
)

// ResolveGOT builds a map from a data/GOT slot's absolute address
// (the same address a "adrp Xd, #page" + "ldr Xt, [Xd, #off]" pair
// computes and then dereferences - see arm64lift's addrRegs/liftLdr
// for the lifter side of this) to a human-readable name for whatever
// pointer is actually stored there, by reading .rela.dyn (the dynamic
// linker's relocations for ordinary data, as opposed to .rela.plt's
// function-only JUMP_SLOT entries that ResolvePLT already handles):
//
//   - R_AARCH64_RELATIVE: the slot's link-time-resolved value is
//     r_addend itself (a plain module-relative address, consistent
//     with how every other address in this package is already
//     treated as load-bias-0) - resolved to whatever named symbol (in
//     either .symtab or .dynsym) starts at exactly that address, if
//     any. This is the common case for a GOT slot holding the address
//     of some object DEFINED in this same module (e.g. a vtable, a
//     typeinfo, or - the case that matters most for readability - a
//     global object like an iostream instance that a compiler-emitted
//     alias/reference for the "same" extern symbol resolves to
//     locally).
//   - R_AARCH64_GLOB_DAT / R_AARCH64_ABS64: the slot instead refers to
//     a symbol resolved by NAME through .dynsym - typically an extern
//     global truly defined in another shared object (e.g. a
//     dynamically-linked libc++'s std::cout/std::cerr) that this
//     module only imports, so there's no local address to resolve at
//     all - only the imported symbol's own (mangled) name.
//
// Slots whose relocation type isn't one of these, or whose target
// address/symbol index doesn't resolve to any name, are simply absent
// from the result - callers should treat that the same as any other
// unresolved address (fall back to a raw numeric value).
func (p *ELFParser) ResolveGOT() (map[uint64]string, error) {
	dynsyms, dynstrNdx, err := p.parseDynsym()
	if err != nil {
		return nil, err
	}
	if int(dynstrNdx) >= len(p.Sections) {
		return nil, fmt.Errorf("invalid .dynsym string table index")
	}
	dynstrSec := p.Sections[dynstrNdx]

	dynsymName := func(sym SymbolEntry) string {
		start := dynstrSec.Offset + uint64(sym.Name)
		if start >= uint64(len(p.Data)) {
			return ""
		}
		end := bytes.IndexByte(p.Data[start:], 0)
		if end < 0 {
			return ""
		}
		return string(p.Data[start : start+uint64(end)])
	}

	// Index every named symbol (both .symtab and .dynsym - a locally
	// DEFINED object a RELATIVE relocation points at could show up in
	// either table depending on whether it's also exported) by its
	// exact address, for RELATIVE relocations to look up by target.
	byAddr := make(map[uint64]string)
	for _, sym := range p.Symbols {
		if sym.Value == 0 {
			continue
		}
		if name := p.GetSymbolName(sym); name != "" {
			byAddr[sym.Value] = name
		}
	}
	for _, sym := range dynsyms {
		if sym.Value == 0 {
			continue
		}
		if name := dynsymName(sym); name != "" {
			byAddr[sym.Value] = name
		}
	}

	result := make(map[uint64]string)
	for _, sec := range p.Sections {
		if sec.Type != SHT_RELA || p.getSectionName(sec) != ".rela.dyn" {
			continue
		}
		for _, rel := range p.parseRelaSection(sec) {
			relType := rel.Info & 0xffffffff
			switch relType {
			case rAARCH64_RELATIVE:
				if name, ok := byAddr[uint64(rel.Addend)]; ok {
					result[rel.Offset] = name
				}
			case rAARCH64_GLOB_DAT, rAARCH64_ABS64:
				idx := rel.SymbolIndex()
				if int(idx) >= len(dynsyms) {
					continue
				}
				if name := dynsymName(dynsyms[idx]); name != "" {
					result[rel.Offset] = name
				}
			}
		}
	}

	return result, nil
}

// DataReader returns a function that reads up to n bytes from a virtual
// address inside a PROGBITS section. This is the low-level accessor the
// ARM64 lifter uses to read jump-table entries from the binary's rodata
// when it recognizes a switch idiom.
func (p *ELFParser) DataReader() func(addr uint64, n int) ([]byte, bool) {
	return func(addr uint64, n int) ([]byte, bool) {
		for _, s := range p.Sections {
			if s.Type != SHT_PROGBITS || s.Size == 0 {
				continue
			}
			if addr < s.Addr || addr >= s.Addr+s.Size {
				continue
			}
			off := s.Offset + (addr - s.Addr)
			end := off + uint64(n)
			if end > s.Offset+s.Size {
				end = s.Offset + s.Size
			}
			if end > uint64(len(p.Data)) {
				end = uint64(len(p.Data))
			}
			if end <= off {
				return nil, false
			}
			return p.Data[off:end], true
		}
		return nil, false
	}
}

// SymbolResolver returns a single address->name lookup combining this
// ELF's own .symtab/.dynsym entries, PLT stub resolution (ResolvePLT),
// and GOT/relocation-based global-object resolution (ResolveGOT) - the
// shared oracle a caller like arm64lift.LiftFunction needs for both
// call targets (bl/blr/tail-call "b"/"br") and GOT/data-slot addresses
// an "ldr" dereferences (see arm64lift's own doc comments for why the
// same lookup serves both). PLT/GOT resolution failures are silently
// ignored here (that half of the lookup just contributes nothing) -
// callers that want to know why should call ResolvePLT/ResolveGOT
// themselves.
//
// A function symbol (STT_FUNC) with no name - real -O0 code sometimes
// emits these for hand-written assembly helpers using local rather
// than global linkage, e.g. libunwind's own low-level register-restore
// trampoline - is given a synthetic "sub_<address>" name rather than
// being silently excluded, matching how other disassemblers/
// decompilers name unnamed routines. This is what lets a tail call to
// one of these still be recognized as a genuine call instead of being
// dropped for looking unresolvable: arm64lift's own liftTailCall/
// liftBr both deliberately require a RESOLVED target (see their own
// doc comments for why - an unresolved branch is far more likely an
// intra-function control-flow edge this lifter doesn't yet understand
// than a real call), and "no name at all" would otherwise be
// indistinguishable from that.
func (p *ELFParser) SymbolResolver() func(addr uint64) (string, bool) {
	plt, _ := p.ResolvePLT()
	got, _ := p.ResolveGOT()

	const sttFunc = 2
	symByAddr := make(map[uint64]string)
	for _, sym := range p.Symbols {
		name := p.GetSymbolName(sym)
		if name == "" && sym.Info&0xf == sttFunc && sym.Value != 0 {
			name = fmt.Sprintf("sub_%x", sym.Value)
		}
		if name != "" {
			symByAddr[sym.Value] = name
		}
	}

	return func(addr uint64) (string, bool) {
		if name, ok := symByAddr[addr]; ok {
			return name, true
		}
		if name, ok := plt[addr]; ok {
			return name, true
		}
		if name, ok := got[addr]; ok {
			return name, true
		}
		return "", false
	}
}
