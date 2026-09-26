package hexedit

import (
	"fmt"
	"strconv"
	"strings"
)

// Space is the address space an address expression is written in. File
// offsets are the default and the only space for files without ELF
// metadata; virtual addresses require ELF sections (including the
// PT_LOAD sections synthesized for stripped binaries).
type Space int

const (
	SpaceFile Space = iota
	SpaceVirtual
)

func (s Space) prefix() string {
	if s == SpaceVirtual {
		return "v"
	}
	return "f"
}

func (s Space) String() string {
	if s == SpaceVirtual {
		return "virtual address"
	}
	return "file offset"
}

// Addr is a parsed address expression: a value plus the space it is
// expressed in.
type Addr struct {
	Value uint64
	Space Space
}

// String renders the address with its space prefix, e.g. "f:0x00001234".
func (a Addr) String() string {
	return fmt.Sprintf("%s:0x%08x", a.Space.prefix(), a.Value)
}

// ParseAddr parses an address expression:
//
//	1234 / 0x1234   file offset, hex (the default; hexdump convention)
//	f:0x1234        explicit file offset
//	v:0x1234        virtual address (ELF only)
//	0d1234          decimal
//
// A "0x"/"0X" prefix is optional for hex values; every bare number is
// parsed as hex, matching hexdump and radare2 conventions.
func ParseAddr(expr string) (Addr, error) {
	text := strings.TrimSpace(expr)
	if text == "" {
		return Addr{}, fmt.Errorf("empty address")
	}

	space := SpaceFile
	if len(text) >= 2 && text[1] == ':' {
		switch text[0] {
		case 'f', 'F':
			space = SpaceFile
		case 'v', 'V':
			space = SpaceVirtual
		default:
			return Addr{}, fmt.Errorf("unknown address-space prefix %q (use f: for file offset or v: for virtual address)", text[:2])
		}
		text = text[2:]
	}
	if text == "" {
		return Addr{}, fmt.Errorf("missing number after address-space prefix")
	}

	base := 16
	digits := text
	switch {
	case strings.HasPrefix(text, "0d") || strings.HasPrefix(text, "0D"):
		base, digits = 10, text[2:]
	case strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X"):
		digits = text[2:]
	}
	if digits == "" {
		return Addr{}, fmt.Errorf("invalid address %q: missing digits", expr)
	}

	value, err := strconv.ParseUint(digits, base, 64)
	if err != nil {
		if base == 16 {
			return Addr{}, fmt.Errorf("invalid address %q: expected a hex number (0x optional), or 0d<N> for decimal", expr)
		}
		return Addr{}, fmt.Errorf("invalid address %q", expr)
	}
	return Addr{Value: value, Space: space}, nil
}
