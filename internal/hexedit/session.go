package hexedit

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/destruct/destruct/internal/native"
)

// Options configures a session.
type Options struct {
	// ReadOnly refuses patch/apply/save commands.
	ReadOnly bool
	// Yes answers apply/save confirmation prompts affirmatively (the
	// --yes flag, for -c scripts).
	Yes bool
	// Out is where command output and the prompt go. Defaults to
	// os.Stdout.
	Out io.Writer
}

// fileSig guards apply: if the file's size or mtime changed since the
// session opened, applying staged patches could clobber someone else's
// write, so apply/save-to-original refuse until the user reopens.
type fileSig struct {
	size  int64
	mtime time.Time
}

// Session is one hex-editing session over one file. All state - cursor,
// staged patches, format metadata - lives here; the interactive loop
// (repl.go) and the one-shot -c path both drive Exec.
type Session struct {
	img  *Image
	opts Options
	out  io.Writer

	cursor Addr

	openSig fileSig

	// dis is the Capstone handle shared by every disasm/decompile
	// command in this session; opened lazily, closed by Close.
	dis *native.Disassembler
	// resolver is the lazily built ELF symbol resolver used for
	// disassembly annotations (symbol headers, branch targets).
	resolver func(uint64) (string, bool)
}

// Open maps path and starts a session. opts.Out defaults to os.Stdout.
func Open(path string, opts Options) (*Session, error) {
	img, err := OpenImage(path)
	if err != nil {
		return nil, err
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	st, err := os.Stat(img.Path)
	if err != nil {
		img.Close()
		return nil, err
	}
	return &Session{
		img:     img,
		opts:    opts,
		out:     opts.Out,
		openSig: fileSig{size: st.Size(), mtime: st.ModTime()},
	}, nil
}

// Close releases the mapping and any disassembler handle. It is
// idempotent.
func (s *Session) Close() error {
	if s.dis != nil {
		s.dis.Close()
		s.dis = nil
	}
	if s.img == nil {
		return nil
	}
	err := s.img.Close()
	s.img = nil
	return err
}

// Image returns the session's mapped image. Valid until Close.
func (s *Session) Image() *Image { return s.img }

// Path returns the resolved path the session was opened on.
func (s *Session) Path() string { return s.img.Path }

// Size returns the file size in bytes.
func (s *Session) Size() int64 { return s.img.Size }

// ReadOnly reports whether editing commands are disabled.
func (s *Session) ReadOnly() bool { return s.opts.ReadOnly }

// Cursor returns the current address.
func (s *Session) Cursor() Addr { return s.cursor }

// SetCursor moves the cursor.
func (s *Session) SetCursor(a Addr) { s.cursor = a }

// printf writes formatted output to the session's writer.
func (s *Session) printf(format string, args ...interface{}) {
	fmt.Fprintf(s.out, format, args...)
}

// printfln writes a formatted line to the session's writer.
func (s *Session) printfln(format string, args ...interface{}) {
	fmt.Fprintf(s.out, format+"\n", args...)
}

// ResolveAddr converts an address expression into a file offset. When a
// file offset lies beyond EOF but the same number maps as a virtual
// address (or vice versa), the error explains the likely confusion -
// on typical Android ELFs p_vaddr equals p_offset for loadable
// segments, so the two spaces look identical until they don't.
func (s *Session) ResolveAddr(a Addr) (int64, error) {
	switch a.Space {
	case SpaceFile:
		if a.Value >= uint64(s.img.Size) {
			if s.img.elf != nil {
				if _, fileOK := s.img.FileToVA(a.Value); !fileOK {
					if _, vaOK := s.img.VAToFile(a.Value); vaOK {
						return 0, fmt.Errorf("%s is beyond the end of the file (%d bytes), but maps as a virtual address - did you mean v:0x%x?", a, s.img.Size, a.Value)
					}
				}
			}
			return 0, fmt.Errorf("%s is beyond the end of the file (%d bytes)", a, s.img.Size)
		}
		return int64(a.Value), nil

	case SpaceVirtual:
		off, ok := s.img.VAToFile(a.Value)
		if !ok {
			switch {
			case s.img.elf == nil:
				return 0, fmt.Errorf("%s does not map to any section (this file has no ELF metadata, so only f: file offsets are available)", a)
			default:
				if _, fileOK := s.img.FileToVA(a.Value); fileOK {
					return 0, fmt.Errorf("%s does not map to any section - did you mean f:0x%x?", a, a.Value)
				}
				return 0, fmt.Errorf("%s does not map to any file-backed section", a)
			}
		}
		return int64(off), nil

	default:
		return 0, fmt.Errorf("unknown address space %d", a.Space)
	}
}

// Read returns up to n bytes at the file offset, clamped at EOF. It is
// an error to read at or beyond EOF: there is no data to show there.
// The returned slice aliases the mapping and must not be modified.
func (s *Session) Read(off int64, n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("negative read length %d", n)
	}
	if off < 0 || off >= s.img.Size {
		return nil, fmt.Errorf("offset 0x%x is at or beyond the end of the file (%d bytes)", off, s.img.Size)
	}
	end := off + int64(n)
	if end > s.img.Size {
		end = s.img.Size
	}
	return s.img.data[off:end], nil
}
