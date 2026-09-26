package hexedit

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
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
	// In is where confirmation prompts read from. Defaults to
	// os.Stdin.
	In io.Reader
}

// Patch is one staged byte write. Orig is captured from the merged view
// at staging time, so a later patch overlapping an earlier one shows
// the earlier patch as its original bytes.
type Patch struct {
	Off  int64
	Orig []byte
	New  []byte
}

// overlayRun is a sorted, merged run of staged bytes used to overlay
// the mapped source without a per-byte map lookup.
type overlayRun struct {
	off  int64
	data []byte
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
	in   *bufio.Reader

	cursor Addr

	// patches is the ordered staging list (source of truth for diff,
	// drop and apply ordering); runs is the merged byte overlay
	// recomputed from it.
	patches []Patch
	runs    []overlayRun

	openSig fileSig

	// dis is the Capstone handle shared by every disasm/decompile
	// command in this session; opened lazily, closed by Close.
	dis *native.Disassembler
	// resolver is the lazily built ELF symbol resolver used for
	// disassembly annotations (symbol headers, branch targets).
	resolver func(uint64) (string, bool)
}

// Open maps path and starts a session. opts.Out defaults to os.Stdout
// and opts.In to os.Stdin.
func Open(path string, opts Options) (*Session, error) {
	img, err := OpenImage(path)
	if err != nil {
		return nil, err
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.In == nil {
		opts.In = os.Stdin
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
		in:      bufio.NewReader(opts.In),
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

// Read returns up to n bytes at the file offset, clamped at EOF, with
// staged patches applied. It is an error to read at or beyond EOF:
// there is no data to show there. The returned slice may alias the
// mapping when nothing is staged and must not be modified.
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
	return s.view(off, int(end-off)), nil
}

// view returns the merged view (mapped source + staged overlay) of up
// to n bytes at off. It aliases the mapping when nothing is staged;
// with staged bytes it always copies.
func (s *Session) view(off int64, n int) []byte {
	if n < 0 {
		n = 0
	}
	end := off + int64(n)
	if end > s.img.Size {
		end = s.img.Size
	}
	if off >= end {
		return nil
	}
	raw := s.img.data[off:end]
	if len(s.runs) == 0 {
		return raw
	}
	out := append([]byte(nil), raw...)
	s.applyRuns(out, off)
	return out
}

// applyRuns copies every staged run intersecting [off, off+len(dst))
// into dst.
func (s *Session) applyRuns(dst []byte, off int64) {
	end := off + int64(len(dst))
	for _, r := range s.runs {
		lo := off
		if r.off > lo {
			lo = r.off
		}
		hi := end
		if rEnd := r.off + int64(len(r.data)); rEnd < hi {
			hi = rEnd
		}
		if lo >= hi {
			continue
		}
		copy(dst[lo-off:hi-off], r.data[lo-r.off:hi-r.off])
	}
}

// rebuildRuns recomputes the merged overlay from the ordered patch
// list; later patches win on overlapping bytes.
func (s *Session) rebuildRuns() {
	if len(s.patches) == 0 {
		s.runs = nil
		return
	}
	merged := make(map[int64]byte)
	for _, p := range s.patches {
		for i, b := range p.New {
			merged[p.Off+int64(i)] = b
		}
	}
	offsets := make([]int64, 0, len(merged))
	for off := range merged {
		offsets = append(offsets, off)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })

	runs := make([]overlayRun, 0, len(offsets))
	for _, off := range offsets {
		if n := len(runs); n > 0 && runs[n-1].off+int64(len(runs[n-1].data)) == off {
			runs[n-1].data = append(runs[n-1].data, merged[off])
			continue
		}
		runs = append(runs, overlayRun{off: off, data: []byte{merged[off]}})
	}
	s.runs = runs
}

// dirty reports whether any patch is staged.
func (s *Session) dirty() bool { return len(s.patches) > 0 }

// stagedMask returns a per-byte mask of staged positions in
// [off, off+n), or nil when nothing is staged there.
func (s *Session) stagedMask(off int64, n int) []bool {
	if len(s.runs) == 0 || n <= 0 {
		return nil
	}
	end := off + int64(n)
	var mask []bool
	for _, r := range s.runs {
		lo := off
		if r.off > lo {
			lo = r.off
		}
		hi := end
		if rEnd := r.off + int64(len(r.data)); rEnd < hi {
			hi = rEnd
		}
		if lo >= hi {
			continue
		}
		if mask == nil {
			mask = make([]bool, n)
		}
		for i := lo; i < hi; i++ {
			mask[i-off] = true
		}
	}
	return mask
}
