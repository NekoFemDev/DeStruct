// Package hexedit implements the `destruct hex` session: an interactive,
// command-loop hex editor over a single file, with format-aware
// disassembly and decompilation for ELF binaries.
//
// The file is mapped read-only; nothing the session does touches disk
// until an explicit apply/save command. Edits are staged as byte patches
// in memory and replayed over the mapped source for display, search and
// disassembly. Addresses default to file offsets ("f:"); virtual
// addresses ("v:") are available for ELF files and are shown alongside
// file offsets whenever the two differ.
package hexedit

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/destruct/destruct/internal/native"
)

// Format is the coarse file-format classification used by `info` and by
// error messages that point the user at the right subcommand.
type Format string

const (
	FormatRaw    Format = "raw"
	FormatELF    Format = "ELF"
	FormatDEX    Format = "DEX"
	FormatClass  Format = "Java class"
	FormatZIP    Format = "ZIP archive (jar/apk)"
	FormatHermes Format = "Hermes bytecode"
)

// detectFormat recognizes just enough magic to classify a file. Hex
// editing works on any file; the classification only drives `info` and
// the guidance printed when a format-specific command cannot run.
func detectFormat(data []byte) Format {
	switch {
	case len(data) >= 4 && string(data[:4]) == "\x7fELF":
		return FormatELF
	case len(data) >= 4 && string(data[:4]) == "dex\n":
		return FormatDEX
	case len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) == 0xCAFEBABE:
		return FormatClass
	case len(data) >= 4 && string(data[:4]) == "PK\x03\x04":
		return FormatZIP
	case len(data) >= 8 && binary.LittleEndian.Uint64(data[:8]) == 0x1F1903C103BC1FC6:
		return FormatHermes
	default:
		return FormatRaw
	}
}

// Image is the read-only, memory-mapped view of the file a session was
// opened on, plus whatever format metadata could be parsed from it. The
// mapping is owned by the Image; Close releases it.
type Image struct {
	Path   string
	Size   int64
	Format Format

	data []byte // read-only mmap; nil for an empty file
	elf  *native.ELFParser
	// elfErr records a failed ELF parse. An ELF-magic file whose header
	// tables do not parse is still opened - as a raw image with the
	// error recorded - because a truncated or corrupt binary is exactly
	// the kind of file a hex editor gets pointed at. OpenImage only
	// fails on I/O errors.
	elfErr error

	// Arch and Machine mirror the parsed ELF header fields; zero for
	// non-ELF or unparsed files.
	Arch    int
	Machine uint16
}

// OpenImage maps path read-only and parses format metadata.
func OpenImage(path string) (*Image, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}

	img := &Image{Path: resolved, Size: st.Size()}
	if st.Size() > 0 {
		if int64(int(st.Size())) != st.Size() {
			return nil, fmt.Errorf("%s: file too large to map on this platform (%d bytes)", path, st.Size())
		}
		data, err := syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ, syscall.MAP_PRIVATE)
		if err != nil {
			return nil, fmt.Errorf("mmap %s: %w", path, err)
		}
		img.data = data
	}

	img.Format = detectFormat(img.data)
	if img.Format == FormatELF {
		elf, err := native.NewELFParserFromData(img.data)
		if err != nil {
			img.elfErr = err
		} else {
			img.elf = elf
			img.Arch = elf.Arch
			img.Machine = elf.Header.Machine
		}
	}
	return img, nil
}

// ELF returns the parsed ELF metadata, or nil for non-ELF (and
// unparseable-ELF) files.
func (img *Image) ELF() *native.ELFParser { return img.elf }

// ELFError reports why an ELF-magic file failed to parse, if it did.
func (img *Image) ELFError() error { return img.elfErr }

// Bytes returns the raw mapped bytes without any staged-overlay applied.
// The slice aliases the mapping and must not be modified.
func (img *Image) Bytes() []byte { return img.data }

// Close releases the mapping. It is idempotent.
func (img *Image) Close() error {
	if img.data == nil {
		return nil
	}
	data := img.data
	img.data = nil
	img.elf = nil
	return syscall.Munmap(data)
}

// fileBacked reports whether a section actually has bytes in the file.
// SHT_NOBITS (.bss) has an address and a size but no file content, so it
// must never participate in file/VA translation.
func fileBacked(s *native.SectionHeader) bool {
	return s.Type == native.SHT_PROGBITS && s.Size > 0
}

// addressable reports whether a section can be the target of a virtual
// address: it needs file content (fileBacked) and a real virtual
// address - either the section is allocated (SHF_ALLOC), or it carries
// a non-zero sh_addr despite the flag. Non-allocated sections
// (.comment, .symtab, .debug_*, .shstrtab) have sh_addr == 0 by
// definition and no address in the loaded image; treating those as VA
// mappings makes v:0 - and any other value colliding with their zero
// address - silently resolve to their file offset.
func addressable(s *native.SectionHeader) bool {
	return fileBacked(s) && (s.Flags&native.SHF_ALLOC != 0 || s.Addr != 0)
}

// FileToVA maps a file offset to a virtual address using the ELF section
// table (or the synthesized PT_LOAD sections when the section table is
// stripped). ok is false when the offset falls outside every file-backed
// section.
func (img *Image) FileToVA(off uint64) (uint64, bool) {
	if img.elf == nil {
		return 0, false
	}
	for i := range img.elf.Sections {
		s := &img.elf.Sections[i]
		if !fileBacked(s) {
			continue
		}
		if off < s.Offset || off-s.Offset >= s.Size {
			continue
		}
		return s.Addr + (off - s.Offset), true
	}
	return 0, false
}

// VAToFile maps a virtual address back to a file offset. ok is false
// when the address is not inside any file-backed, allocated section:
// virtual addresses only exist for allocated sections, so a section
// whose sh_addr is 0 (as every non-allocated section's is) must never
// match - v:0 would otherwise resolve to, e.g., .comment's file
// offset.
func (img *Image) VAToFile(va uint64) (uint64, bool) {
	if img.elf == nil {
		return 0, false
	}
	for i := range img.elf.Sections {
		s := &img.elf.Sections[i]
		if !addressable(s) {
			continue
		}
		if va < s.Addr || va-s.Addr >= s.Size {
			continue
		}
		return s.Offset + (va - s.Addr), true
	}
	return 0, false
}

// CodeSectionAtFile returns the executable section containing a file
// offset. Disassembly uses it to stop at section boundaries instead of
// decoding whatever bytes happen to follow.
func (img *Image) CodeSectionAtFile(off uint64) (native.SectionHeader, bool) {
	if img.elf == nil {
		return native.SectionHeader{}, false
	}
	for i := range img.elf.Sections {
		s := &img.elf.Sections[i]
		if s.Flags&native.SHF_EXECINSTR == 0 || s.Size == 0 {
			continue
		}
		if off >= s.Offset && off-s.Offset < s.Size {
			return *s, true
		}
	}
	return native.SectionHeader{}, false
}

// SectionInfo is a resolved section view for the command layer.
type SectionInfo struct {
	Name   string
	Addr   uint64
	Offset uint64
	Size   uint64
	Flags  uint64
}

// SectionAtFile returns the file-backed section containing a file
// offset, if any. Sections without file content (SHT_NOBITS, and the
// zero-size null section) never match.
func (img *Image) SectionAtFile(off uint64) (SectionInfo, bool) {
	if img.elf == nil {
		return SectionInfo{}, false
	}
	for i := range img.elf.Sections {
		s := &img.elf.Sections[i]
		if !fileBacked(s) {
			continue
		}
		if off >= s.Offset && off-s.Offset < s.Size {
			return SectionInfo{
				Name:   img.elf.SectionName(*s),
				Addr:   s.Addr,
				Offset: s.Offset,
				Size:   s.Size,
				Flags:  s.Flags,
			}, true
		}
	}
	return SectionInfo{}, false
}
