package hexedit

import (
	"context"
	"fmt"
	"strings"

	"github.com/destruct/destruct/internal/native"
)

const (
	defaultReadLength = 256
	maxReadLength     = 64 * 1024
)

// Exec runs one command line. It returns quit=true when the session
// should end. Command errors are returned to the caller, which prints
// them; a failed command never ends the session.
func (s *Session) Exec(ctx context.Context, line string) (quit bool, err error) {
	if cerr := ctx.Err(); cerr != nil {
		return false, cerr
	}
	text := strings.TrimSpace(line)
	if text == "" {
		return false, nil
	}
	name, rest, _ := strings.Cut(text, " ")
	rest = strings.TrimSpace(rest)

	switch name {
	case "help", "?":
		s.printHelp()
		return false, nil
	case "exit", "quit", "q", "q!":
		return true, nil
	case "goto", "g":
		return false, s.cmdGoto(rest)
	case "read":
		return false, s.cmdRead(rest)
	case "info", "i":
		return false, s.cmdInfo(rest)
	default:
		return false, fmt.Errorf("unknown command %q (try 'help')", name)
	}
}

// cmdGoto moves the cursor, validating that the address resolves to a
// real file offset first.
func (s *Session) cmdGoto(rest string) error {
	fields := strings.Fields(rest)
	if len(fields) != 1 {
		return fmt.Errorf("usage: goto <addr>")
	}
	a, err := ParseAddr(fields[0])
	if err != nil {
		return err
	}
	if _, err := s.ResolveAddr(a); err != nil {
		return err
	}
	s.SetCursor(a)
	s.printfln("=> %s", a)
	return nil
}

// cmdRead writes a hex dump around the requested address. The start is
// aligned down to a 16-byte row so the dump stays readable, while the
// requested length still covers [addr, addr+len).
func (s *Session) cmdRead(rest string) error {
	fields := strings.Fields(rest)
	if len(fields) > 2 {
		return fmt.Errorf("usage: read [addr] [len]")
	}

	startOff, err := s.ResolveAddr(s.cursor)
	if err != nil {
		// The cursor is only ever set through ResolveAddr, so this is
		// defensive; surface it rather than dumping the wrong bytes.
		return err
	}
	if len(fields) >= 1 {
		a, err := ParseAddr(fields[0])
		if err != nil {
			return err
		}
		off, err := s.ResolveAddr(a)
		if err != nil {
			return err
		}
		s.SetCursor(a)
		startOff = off
	}

	n := defaultReadLength
	if len(fields) == 2 {
		if n, err = parseCount(fields[1]); err != nil {
			return err
		}
	}
	if n <= 0 {
		return fmt.Errorf("read length must be positive")
	}
	if n > maxReadLength {
		return fmt.Errorf("read length %d exceeds the maximum of %d bytes", n, maxReadLength)
	}

	aligned := startOff &^ int64(hexDumpRowBytes-1)
	window := n + int(startOff-aligned)
	data, err := s.Read(aligned, window)
	if err != nil {
		return err
	}
	renderHexDump(s.out, s.img, aligned, data)
	return nil
}

// cmdInfo prints the file format summary: classification, arch, entry
// point and the section table for ELF inputs.
func (s *Session) cmdInfo(rest string) error {
	if rest != "" {
		return fmt.Errorf("usage: info")
	}
	img := s.img
	s.printfln("file:      %s", img.Path)
	s.printfln("size:      %d bytes (0x%x)", img.Size, img.Size)
	s.printfln("format:    %s", s.formatDescription())
	if elf := img.ELF(); elf != nil {
		entry := elf.Header.Entry
		line := fmt.Sprintf("entry:     v:0x%08x", entry)
		if off, ok := img.VAToFile(entry); ok {
			line += fmt.Sprintf(" (f:0x%08x)", off)
		}
		s.printfln("%s", line)

		s.printfln("sections:  %d", len(elf.Sections))
		for i := range elf.Sections {
			sec := &elf.Sections[i]
			if sec.Size == 0 && sec.Name == 0 && sec.SynthName == "" {
				continue // null section
			}
			name := elf.SectionName(*sec)
			if name == "" {
				name = "<unnamed>"
			}
			s.printfln("  [%2d] %-18s f:0x%08x v:0x%08x 0x%08x %s",
				i, name, sec.Offset, sec.Addr, sec.Size, sectionFlags(sec.Flags))
		}
		s.printfln("symbols:   %d", len(elf.Symbols))
	}
	return nil
}

// formatDescription renders the one-line format summary used by info.
func (s *Session) formatDescription() string {
	img := s.img
	if elf := img.ELF(); elf != nil {
		order := "MSB"
		if elf.IsEndian {
			order = "LSB"
		}
		return fmt.Sprintf("ELF %d-bit %s %s, %s",
			elf.Bits, order, elfTypeName(elf.Header.Type), native.GetArchName(img.Arch))
	}
	if img.Format == FormatELF && img.ELFError() != nil {
		return fmt.Sprintf("ELF (parse failed: %v)", img.ELFError())
	}
	return string(img.Format)
}

const (
	etRel  = 1
	etExec = 2
	etDyn  = 3
	etCore = 4
)

// elfTypeName names the ELF e_type field.
func elfTypeName(t uint16) string {
	switch t {
	case etRel:
		return "ET_REL (relocatable)"
	case etExec:
		return "ET_EXEC (executable)"
	case etDyn:
		return "ET_DYN (shared object)"
	case etCore:
		return "ET_CORE (core dump)"
	default:
		return fmt.Sprintf("ET_%d", t)
	}
}

// sectionFlags renders section permission flags in readelf's A/W/X
// shorthand.
func sectionFlags(flags uint64) string {
	var b strings.Builder
	if flags&native.SHF_ALLOC != 0 {
		b.WriteByte('A')
	}
	if flags&native.SHF_WRITE != 0 {
		b.WriteByte('W')
	}
	if flags&native.SHF_EXECINSTR != 0 {
		b.WriteByte('X')
	}
	return b.String()
}

// printHelp writes the command reference. It is expanded as commands
// are implemented; the address-model notes are the part users need
// before they touch anything.
func (s *Session) printHelp() {
	s.printfln(`Commands:
  read [addr] [len]   hex dump (default: cursor, 256 bytes; max 65536)
  goto <addr>         move the cursor
  info                file format, architecture and section table
  help                this text
  exit | quit | q     leave the session

Addresses: numbers are hex by default.
  f:0x1234   file offset (default; patches write here)
  v:0x1234   virtual address (ELF only; shown when it differs)
Counts are decimal unless written as 0x<hex>.

The file is mapped read-only. Nothing touches disk until an explicit
apply or save.`)
}
