package il2cpp

import (
	"context"
	"encoding/binary"
	"fmt"
)

// Minimal ELF reader tailored to the IL2CPP registration search. It
// keeps only what the dumper needs (program headers, dynamic entries,
// dynamic symbols and relocations) and applies dynamic relocations to a
// private copy of the image so pointers in .data/.data.rel.ro can be
// followed the same way the dynamic linker would.
type elfFile struct {
	data    []byte
	is64    bool
	order   binary.ByteOrder
	machine uint16

	phdrs []elfPhdr

	dyn     map[int64]uint64
	symbols []elfSymbol
}

type elfPhdr struct {
	typ    uint32
	flags  uint32
	off    uint64
	vaddr  uint64
	filesz uint64
	memsz  uint64
}

type elfSymbol struct {
	name  string
	value uint64
	size  uint64
}

// Dynamic tags.
const (
	dtNull           = 0
	dtHash           = 4
	dtStrtab         = 5
	dtSymtab         = 6
	dtRela           = 7
	dtRelaSz         = 8
	dtRelaEnt        = 9
	dtStrSz          = 10
	dtSyment         = 11
	dtRel            = 17
	dtRelSz          = 18
	dtRelEnt         = 19
	dtGnuHash        = 0x6ffffef5
	ptLoad           = 1
	ptDynamic        = 2
	pfX              = 0x1
	pfW              = 0x2
	pfR              = 0x4
	emAArch64        = 183
	emX8664          = 62
	emARM            = 40
	em386            = 3
	rAArch64Abs64    = 257
	rAArch64Relative = 1027
	rX8664_64        = 1
	rX8664Relative   = 8
	r386_32          = 1
	rARM_ABS32       = 2
)

// newELF parses the ELF header and program headers. The caller hands
// over ownership of data; relocations are applied in place.
func newELF(data []byte) (*elfFile, error) {
	return newELFContext(context.Background(), data)
}

// newELFContext is newELF with cancellation: ctx is checked between parse
// phases and inside the symbol/relocation table scans, so a dump cancelled
// while preparing the image stops at the next scan chunk.
func newELFContext(ctx context.Context, data []byte) (*elfFile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) < 64 || string(data[:4]) != "\x7fELF" {
		return nil, fmt.Errorf("not an ELF file")
	}
	e := &elfFile{data: data}
	switch data[4] {
	case 1:
		e.is64 = false
	case 2:
		e.is64 = true
	default:
		return nil, fmt.Errorf("unsupported ELF class %d", data[4])
	}
	if data[5] != 1 {
		return nil, fmt.Errorf("unsupported ELF data encoding %d", data[5])
	}
	e.order = binary.LittleEndian

	if e.is64 {
		e.machine = e.u16(0x12)
		e.parsePhdrs64()
	} else {
		e.machine = e.u16(0x12)
		e.parsePhdrs32()
	}
	if len(e.phdrs) == 0 {
		return nil, fmt.Errorf("no program headers in ELF")
	}
	e.parseDynamic()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e.parseSymbolsContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e.applyRelocationsContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *elfFile) u16(off int) uint16 {
	if off < 0 || off > len(e.data) || len(e.data)-off < 2 {
		return 0
	}
	return e.order.Uint16(e.data[off:])
}

func (e *elfFile) u32(off int) uint32 {
	if off < 0 || off > len(e.data) || len(e.data)-off < 4 {
		return 0
	}
	return e.order.Uint32(e.data[off:])
}

func (e *elfFile) u64(off int) uint64 {
	if off < 0 || off > len(e.data) || len(e.data)-off < 8 {
		return 0
	}
	return e.order.Uint64(e.data[off:])
}

func (e *elfFile) parsePhdrs64() {
	phoff := e.u64(0x20)
	phentsize := int(e.u16(0x36))
	phnum := int(e.u16(0x38))
	if phentsize <= 0 {
		phentsize = 56
	}
	if phentsize < 56 {
		return
	}
	start, _, ok := byteRange(e.data, phoff, uint64(phnum)*uint64(phentsize))
	if !ok {
		return
	}
	for i := 0; i < phnum; i++ {
		o := start + i*phentsize
		if o+56 > len(e.data) {
			break
		}
		e.phdrs = append(e.phdrs, elfPhdr{
			typ:    e.u32(o),
			flags:  e.u32(o + 4),
			off:    e.u64(o + 8),
			vaddr:  e.u64(o + 16),
			filesz: e.u64(o + 32),
			memsz:  e.u64(o + 40),
		})
	}
}

func (e *elfFile) parsePhdrs32() {
	phoff := uint64(e.u32(0x1C))
	phentsize := int(e.u16(0x2A))
	phnum := int(e.u16(0x2C))
	if phentsize <= 0 {
		phentsize = 32
	}
	if phentsize < 32 {
		return
	}
	start, _, ok := byteRange(e.data, phoff, uint64(phnum)*uint64(phentsize))
	if !ok {
		return
	}
	for i := 0; i < phnum; i++ {
		o := start + i*phentsize
		if o+32 > len(e.data) {
			break
		}
		e.phdrs = append(e.phdrs, elfPhdr{
			typ:    e.u32(o),
			off:    uint64(e.u32(o + 4)),
			vaddr:  uint64(e.u32(o + 8)),
			filesz: uint64(e.u32(o + 16)),
			memsz:  uint64(e.u32(o + 20)),
			flags:  e.u32(o + 24),
		})
	}
}

func (e *elfFile) parseDynamic() {
	e.dyn = make(map[int64]uint64)
	for _, ph := range e.phdrs {
		if ph.typ != ptDynamic || ph.filesz == 0 {
			continue
		}
		ent := 16
		if !e.is64 {
			ent = 8
		}
		start, end, ok := byteRange(e.data, ph.off, ph.filesz)
		if !ok {
			continue
		}
		for off := start; off <= end-ent; off += ent {
			var tag int64
			var val uint64
			if e.is64 {
				tag = int64(e.u64(off))
				val = e.u64(off + 8)
			} else {
				tag = int64(int32(e.u32(off)))
				val = uint64(e.u32(off + 4))
			}
			if tag == dtNull {
				break
			}
			e.dyn[tag] = val
		}
		return
	}
}

func (e *elfFile) parseSymbols() {
	e.parseSymbolsContext(context.Background())
}

func (e *elfFile) parseSymbolsContext(ctx context.Context) {
	symtab, ok := e.dyn[dtSymtab]
	if !ok {
		return
	}
	count := e.symbolCountContext(ctx)
	syment := 24
	if !e.is64 {
		syment = 16
	}
	if v, ok := e.dyn[dtSyment]; ok && v != 0 {
		if v < uint64(syment) || v > uint64(len(e.data)) {
			return
		}
		syment = int(v)
	}
	off, ok := e.mapVATR(symtab)
	if !ok {
		return
	}
	var strtab uint64
	if v, ok := e.dyn[dtStrtab]; ok {
		strtab = v
	}
	start, _, ok := byteRange(e.data, off, 0)
	if !ok {
		return
	}
	available := (len(e.data) - start) / syment
	if count < uint64(available) {
		available = int(count)
	}
	for i := 0; i < available; i++ {
		if i&0xFFF == 0 && ctx.Err() != nil {
			return
		}
		o := start + i*syment
		var nameOff uint32
		var sym elfSymbol
		if e.is64 {
			nameOff = e.u32(o)
			sym.value = e.u64(o + 8)
			sym.size = e.u64(o + 16)
		} else {
			nameOff = e.u32(o)
			sym.value = uint64(e.u32(o + 4))
			sym.size = uint64(e.u32(o + 8))
		}
		if strtab != 0 && nameOff != 0 {
			if strtab <= ^uint64(0)-uint64(nameOff) {
				sym.name = e.readCStringContext(ctx, strtab+uint64(nameOff))
			}
		}
		e.symbols = append(e.symbols, sym)
	}
}

// symbolCount reproduces Il2CppDumper's DT_HASH / DT_GNU_HASH symbol
// count computation, since stripped Android binaries carry no section
// headers to derive it from.
func (e *elfFile) symbolCount() uint64 {
	return e.symbolCountContext(context.Background())
}

// symbolCountContext is symbolCount with cancellation.
func (e *elfFile) symbolCountContext(ctx context.Context) uint64 {
	if hash, ok := e.dyn[dtHash]; ok {
		if off, ok := e.mapVATR(hash); ok {
			if start, _, valid := byteRange(e.data, off, 8); valid {
				return uint64(e.u32(start + 4)) // nchain
			}
		}
	}
	hash, ok := e.dyn[dtGnuHash]
	if !ok {
		return 0
	}
	off, ok := e.mapVATR(hash)
	if !ok {
		return 0
	}
	o, _, ok := byteRange(e.data, off, 16)
	if !ok {
		return 0
	}
	nbuckets := e.u32(o)
	symoffset := e.u32(o + 4)
	bloomSize := e.u32(o + 8)
	bloomWord := uint64(8)
	if !e.is64 {
		bloomWord = 4
	}
	_, bucketsOff, ok := recordRange(e.data, off+16, uint64(bloomSize), bloomWord)
	if !ok {
		return 0
	}
	_, chains, ok := recordRange(e.data, uint64(bucketsOff), uint64(nbuckets), 4)
	if !ok {
		return 0
	}
	var last uint32
	for i := 0; i < int(nbuckets); i++ {
		if i&0xFFF == 0 && ctx.Err() != nil {
			return 0
		}
		b := e.u32(bucketsOff + 4*i)
		if b > last {
			last = b
		}
	}
	if last < symoffset {
		return uint64(symoffset)
	}
	_, pos, ok := recordRange(e.data, uint64(chains), uint64(last-symoffset), 4)
	if !ok {
		return 0
	}
	scanned := 0
	for pos <= len(e.data)-4 {
		scanned++
		if scanned&0xFFF == 0 && ctx.Err() != nil {
			return 0
		}
		c := e.u32(pos)
		pos += 4
		last++
		if c&1 != 0 {
			break
		}
	}
	return uint64(last)
}

func (e *elfFile) applyRelocations() {
	e.applyRelocationsContext(context.Background())
}

// applyRelocationsContext is applyRelocations with cancellation: the
// relocation entry walks poll ctx every 4096 entries.
func (e *elfFile) applyRelocationsContext(ctx context.Context) {
	if rela, ok := e.dyn[dtRela]; ok {
		size := e.dyn[dtRelaSz]
		ent := 24
		if !e.is64 {
			ent = 12
		}
		if v, ok := e.dyn[dtRelaEnt]; ok && v != 0 {
			if v < uint64(ent) || v > uint64(len(e.data)) {
				ent = 0
			} else {
				ent = int(v)
			}
		}
		off, ok := e.mapVATR(rela)
		if ok && ent != 0 {
			start, _, valid := byteRange(e.data, off, size)
			if valid {
				for i := uint64(0); i < size/uint64(ent); i++ {
					if i&0xFFF == 0 && ctx.Err() != nil {
						return
					}
					o := start + int(i)*ent
					e.applyRela64(o, ent)
				}
			}
		}
	}
	if rel, ok := e.dyn[dtRel]; ok {
		size := e.dyn[dtRelSz]
		ent := 8
		if v, ok := e.dyn[dtRelEnt]; ok && v != 0 {
			if v < uint64(ent) || v > uint64(len(e.data)) {
				ent = 0
			} else {
				ent = int(v)
			}
		}
		off, ok := e.mapVATR(rel)
		if ok && ent != 0 {
			start, _, valid := byteRange(e.data, off, size)
			if valid {
				for i := uint64(0); i < size/uint64(ent); i++ {
					if i&0xFFF == 0 && ctx.Err() != nil {
						return
					}
					o := start + int(i)*ent
					e.applyRel32(o)
				}
			}
		}
	}
}

func (e *elfFile) applyRela64(o, ent int) {
	var rOffset, rInfo uint64
	var rAddend int64
	if e.is64 {
		rOffset = e.u64(o)
		rInfo = e.u64(o + 8)
		rAddend = int64(e.u64(o + 16))
	} else {
		if ent < 12 {
			return
		}
		rOffset = uint64(e.u32(o))
		rInfo = uint64(e.u32(o + 4))
		rAddend = int64(int32(e.u32(o + 8)))
	}
	rtype := uint32(rInfo & 0xffffffff)
	rsym := rInfo >> 32
	target, ok := e.mapVATR(rOffset)
	if !ok {
		return
	}
	var value uint64
	recognized := true
	switch {
	case e.machine == emAArch64 && rtype == rAArch64Relative:
		value = uint64(rAddend)
	case e.machine == emAArch64 && rtype == rAArch64Abs64:
		value = e.symValue(rsym) + uint64(rAddend)
	case e.machine == emX8664 && rtype == rX8664Relative:
		value = uint64(rAddend)
	case e.machine == emX8664 && rtype == rX8664_64:
		value = e.symValue(rsym) + uint64(rAddend)
	default:
		recognized = false
	}
	if !recognized {
		return
	}
	if e.is64 {
		if start, _, ok := byteRange(e.data, target, 8); ok {
			e.order.PutUint64(e.data[start:], value)
		}
	} else if start, _, ok := byteRange(e.data, target, 4); ok {
		e.order.PutUint32(e.data[start:], uint32(value))
	}
}

// applyRel32 handles the 32-bit REL forms used on ARM/x86 Android:
// Il2CppDumper only resolves R_ARM_ABS32 / R_386_32 and leaves
// RELATIVE entries untouched (their slot already holds the addend).
func (e *elfFile) applyRel32(o int) {
	rOffset := uint64(e.u32(o))
	rInfo := e.u32(o + 4)
	rtype := rInfo & 0xff
	rsym := rInfo >> 8
	target, ok := e.mapVATR(rOffset)
	start, _, valid := byteRange(e.data, target, 4)
	if !ok || !valid {
		return
	}
	if e.machine == em386 && rtype == r386_32 {
		e.order.PutUint32(e.data[start:], uint32(e.symValue(uint64(rsym))))
	} else if e.machine != em386 && rtype == rARM_ABS32 {
		e.order.PutUint32(e.data[start:], uint32(e.symValue(uint64(rsym))))
	}
}

func (e *elfFile) symValue(index uint64) uint64 {
	if index < uint64(len(e.symbols)) {
		return e.symbols[index].value
	}
	return 0
}

// mapVATR maps a virtual address to a file offset.
func (e *elfFile) mapVATR(addr uint64) (uint64, bool) {
	for _, ph := range e.phdrs {
		if ph.typ != ptLoad {
			continue
		}
		if addr >= ph.vaddr && addr-ph.vaddr < ph.filesz {
			delta := addr - ph.vaddr
			if ph.off <= ^uint64(0)-delta {
				if _, _, ok := byteRange(e.data, ph.off+delta, 1); ok {
					return ph.off + delta, true
				}
			}
		}
	}
	return 0, false
}

// mapRTVA maps a file offset back to a virtual address.
func (e *elfFile) mapRTVA(addr uint64) uint64 {
	for _, ph := range e.phdrs {
		if ph.typ != ptLoad {
			continue
		}
		if addr >= ph.off && addr-ph.off < ph.filesz && ph.vaddr <= ^uint64(0)-(addr-ph.off) {
			return addr - ph.off + ph.vaddr
		}
	}
	return 0
}

func (e *elfFile) readU64(addr uint64) uint64 {
	off, ok := e.mapVATR(addr)
	if !ok {
		return 0
	}
	if start, _, ok := byteRange(e.data, off, 8); ok {
		return e.u64(start)
	}
	return 0
}

func (e *elfFile) readU32(addr uint64) uint32 {
	off, ok := e.mapVATR(addr)
	if !ok {
		return 0
	}
	if start, _, ok := byteRange(e.data, off, 4); ok {
		return e.u32(start)
	}
	return 0
}

func (e *elfFile) readBytes(off, n int) []byte {
	if off < 0 || n < 0 || uint64(off) > uint64(len(e.data)) || uint64(n) > uint64(len(e.data))-uint64(off) {
		return nil
	}
	return e.data[off : off+n]
}

// readCString reads a NUL-terminated string from a virtual address.
func (e *elfFile) readCString(addr uint64) string {
	return e.readCStringContext(context.Background(), addr)
}

// readCStringContext is readCString with cancellation: the terminator scan
// polls ctx every 4096 bytes and returns "" once cancelled.
func (e *elfFile) readCStringContext(ctx context.Context, addr uint64) string {
	off, ok := e.mapVATR(addr)
	if !ok {
		return ""
	}
	end, _, ok := byteRange(e.data, off, 1)
	if !ok {
		return ""
	}
	for end < len(e.data) && e.data[end] != 0 {
		if end&0xFFF == 0 && ctx.Err() != nil {
			return ""
		}
		end++
	}
	return string(e.data[off:end])
}

// searchSection is a contiguous mapped range used by the registration
// search. offset/address ranges match Il2CppDumper's SearchSection.
type searchSection struct {
	offset     uint64
	offsetEnd  uint64
	address    uint64
	addressEnd uint64
}

func (e *elfFile) execSections() []searchSection {
	var out []searchSection
	for _, ph := range e.phdrs {
		if ph.typ != ptLoad || ph.memsz == 0 {
			continue
		}
		if !e.validSection(ph) {
			continue
		}
		switch ph.flags {
		case pfX, pfX | pfW, pfX | pfR, pfX | pfW | pfR:
			out = append(out, searchSection{
				offset: ph.off, offsetEnd: ph.off + ph.filesz,
				address: ph.vaddr, addressEnd: ph.vaddr + ph.memsz,
			})
		}
	}
	return out
}

func (e *elfFile) dataSections() []searchSection {
	var out []searchSection
	for _, ph := range e.phdrs {
		if ph.typ != ptLoad || ph.memsz == 0 {
			continue
		}
		if !e.validSection(ph) {
			continue
		}
		switch ph.flags {
		case pfW, pfR, pfW | pfR:
			out = append(out, searchSection{
				offset: ph.off, offsetEnd: ph.off + ph.filesz,
				address: ph.vaddr, addressEnd: ph.vaddr + ph.memsz,
			})
		}
	}
	return out
}

func (e *elfFile) validSection(ph elfPhdr) bool {
	if _, _, ok := byteRange(e.data, ph.off, ph.filesz); !ok {
		return false
	}
	return ph.vaddr <= ^uint64(0)-ph.memsz && ph.vaddr <= ^uint64(0)-ph.filesz
}

// findReferences scans the data sections once and returns every slot
// holding one of the requested pointer values, in file order. This is
// equivalent to calling Il2CppDumper's FindReference per target but
// avoids re-scanning tens of megabytes for every lookup.
//
// ctx is checked once per section and every 4096 bytes of each scan; a
// cancelled scan returns the references collected so far and the caller
// (which holds the same ctx) aborts before using them.
func (e *elfFile) findReferences(ctx context.Context, targets map[uint64]struct{}) map[uint64][]uint64 {
	out := make(map[uint64][]uint64)
	if len(targets) == 0 {
		return out
	}
	for _, sec := range e.dataSections() {
		if ctx.Err() != nil {
			return out
		}
		pos := sec.offset
		end := sec.offsetEnd
		if end > uint64(len(e.data)) {
			end = uint64(len(e.data))
		}
		scanned := uint64(0)
		for pos <= end && end-pos >= 8 {
			scanned++
			if scanned%512 == 0 && ctx.Err() != nil { // every 4096 bytes
				return out
			}
			v := e.u64(int(pos))
			if _, ok := targets[v]; ok {
				out[v] = append(out[v], pos-sec.offset+sec.address)
			}
			pos += 8
		}
	}
	return out
}
