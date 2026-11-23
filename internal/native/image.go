package native

import (
	"fmt"
)

// maxLoadImageSize bounds the reconstructed load image so a pathological
// executable with high virtual addresses cannot allocate an enormous blob.
const maxLoadImageSize = 512 << 20

const shtNobits = 8

// LoadImage reconstructs the process image described by the ELF's
// SHF_ALLOC sections: file-backed bytes are copied to their virtual
// addresses, NOBITS ranges stay zero, and gaps are zero-filled.
//
// base is 0 for PIE/shared objects and for ordinary low-address
// executables; high-address ET_EXEC images keep their lowest section
// address (page aligned) instead.
func (p *ELFParser) LoadImage() (base uint64, image []byte, err error) {
	minAddr := ^uint64(0)
	maxAddr := uint64(0)
	for _, s := range p.Sections {
		if s.Flags&SHF_ALLOC == 0 || s.Size == 0 {
			continue
		}
		if s.Addr < minAddr {
			minAddr = s.Addr
		}
		end := s.Addr + s.Size
		if end < s.Addr {
			continue
		}
		if end > maxAddr {
			maxAddr = end
		}
	}
	if minAddr == ^uint64(0) || maxAddr <= minAddr {
		return 0, nil, fmt.Errorf("ELF has no allocated sections")
	}

	base = 0
	if p.Header.Type != ET_DYN && maxAddr > maxLoadImageSize {
		base = minAddr &^ 0xfff
	}
	size := maxAddr - base
	if size == 0 || size > maxLoadImageSize {
		return 0, nil, fmt.Errorf("ELF image span 0x%x exceeds the %d MiB limit", size, maxLoadImageSize>>20)
	}

	image = make([]byte, size)
	// A PIE's first PT_LOAD includes the ELF header and program headers
	// at virtual address 0. Section-based copying starts at .interp, so
	// copy the prefix too.
	if base == 0 && p.Header.Type == ET_DYN {
		n := minAddr
		if n > uint64(len(p.Data)) {
			n = uint64(len(p.Data))
		}
		copy(image, p.Data[:n])
	}
	for _, s := range p.Sections {
		if s.Flags&SHF_ALLOC == 0 || s.Size == 0 || s.Addr < base {
			continue
		}
		off := s.Addr - base
		if off >= size {
			continue
		}
		n := s.Size
		if off+n > size {
			n = size - off
		}
		if s.Type == shtNobits {
			continue
		}
		if s.Offset > uint64(len(p.Data)) || s.Offset+s.Size > uint64(len(p.Data)) {
			continue
		}
		copy(image[off:off+n], p.Data[s.Offset:s.Offset+n])
	}
	return base, image, nil
}
