package hexedit

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/destruct/destruct/internal/atomicfile"
)

const (
	// commitChunkBytes bounds the copy buffer when rewriting the file.
	commitChunkBytes = 1 << 20
	// diffPreviewBytes caps how many bytes of a patch are printed; the
	// full bytes are always what gets applied.
	diffPreviewBytes = 32
)

// cmdPatch stages a byte patch. Nothing touches disk until apply/save.
func (s *Session) cmdPatch(rest string) error {
	if s.opts.ReadOnly {
		return fmt.Errorf("session is read-only")
	}
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return fmt.Errorf("usage: patch <addr> <hex bytes>")
	}
	a, err := ParseAddr(fields[0])
	if err != nil {
		return err
	}
	newBytes, err := parseHexBytes(fields[1:])
	if err != nil {
		return err
	}
	off, err := s.ResolveAddr(a)
	if err != nil {
		return err
	}
	if off+int64(len(newBytes)) > s.img.Size {
		return fmt.Errorf("patch of %d bytes at f:0x%08x would extend past the end of the file (%d bytes); hexedit never changes file size", len(newBytes), off, s.img.Size)
	}

	orig, err := s.Read(off, len(newBytes))
	if err != nil {
		return err
	}
	orig = append([]byte(nil), orig...)

	for i, p := range s.patches {
		if rangesOverlap(off, int64(len(newBytes)), p.Off, int64(len(p.New))) {
			s.printfln("; warning: overlaps staged patch #%d at f:0x%08x", i, p.Off)
		}
	}

	s.patches = append(s.patches, Patch{Off: off, Orig: orig, New: newBytes})
	s.rebuildRuns()
	s.SetCursor(a)
	s.printfln("#%d f:0x%08x  %s -> %s", len(s.patches)-1, off, hexPreview(orig), hexPreview(newBytes))
	return nil
}

// cmdDiff prints the staged patch list. Patch indices are stable across
// diff/drop until an apply or clear.
func (s *Session) cmdDiff(rest string) error {
	if rest != "" {
		return fmt.Errorf("usage: diff")
	}
	s.printDiff()
	return nil
}

// cmdDrop removes one staged patch by index.
func (s *Session) cmdDrop(rest string) error {
	fields := strings.Fields(rest)
	if len(fields) != 1 {
		return fmt.Errorf("usage: drop <index>")
	}
	idx, err := strconv.Atoi(fields[0])
	if err != nil || idx < 0 || idx >= len(s.patches) {
		return fmt.Errorf("invalid patch index %q (0..%d)", fields[0], len(s.patches)-1)
	}
	s.patches = append(s.patches[:idx], s.patches[idx+1:]...)
	s.rebuildRuns()
	s.printfln("dropped patch #%d (%d remaining)", idx, len(s.patches))
	return nil
}

// cmdClear discards all staged patches.
func (s *Session) cmdClear(rest string) error {
	if rest != "" {
		return fmt.Errorf("usage: clear")
	}
	if !s.dirty() {
		s.printfln("no staged patches")
		return nil
	}
	n := len(s.patches)
	s.patches = nil
	s.runs = nil
	s.printfln("cleared %d staged patch(es)", n)
	return nil
}

// cmdApply commits staged patches to the original file, atomically and
// only after an interactive confirmation (or --yes).
func (s *Session) cmdApply(rest string) error {
	if rest != "" {
		return fmt.Errorf("usage: apply")
	}
	return s.commitTo(s.img.Path)
}

// cmdSave commits staged patches to a path (default: the original
// file, which is then the same as apply).
func (s *Session) cmdSave(rest string) error {
	fields := strings.Fields(rest)
	if len(fields) > 1 {
		return fmt.Errorf("usage: save [path]")
	}
	target := s.img.Path
	if len(fields) == 1 {
		target = fields[0]
	}
	return s.commitTo(target)
}

// commitTo writes the merged file to target. Writing to the original
// file is guarded by a size/mtime check against the state captured at
// Open, requires confirmation, and reopens the session afterward
// because the old mapping now points at the unlinked inode. Writing to
// a different path leaves the session (and its mapping) untouched.
func (s *Session) commitTo(target string) error {
	if s.opts.ReadOnly {
		return fmt.Errorf("session is read-only")
	}
	if !s.dirty() {
		return fmt.Errorf("no staged patches to write")
	}
	s.printDiff()

	inPlace := s.isOriginal(target)
	if inPlace {
		if err := s.checkUnchanged(); err != nil {
			return err
		}
	}

	prompt := ""
	switch {
	case inPlace:
		prompt = fmt.Sprintf("apply %d patch(es) to %s?", len(s.patches), target)
	case fileExists(target):
		prompt = fmt.Sprintf("overwrite existing %s?", target)
	}
	if prompt != "" && !s.opts.Yes {
		if !s.confirm(prompt) {
			s.printfln("cancelled")
			return nil
		}
	}

	perm := os.FileMode(0o644)
	if st, err := os.Stat(s.img.Path); err == nil {
		perm = st.Mode().Perm()
	}
	if err := s.writePatched(target, perm); err != nil {
		return err
	}

	n := len(s.patches)
	s.patches = nil
	s.runs = nil
	if inPlace {
		s.printfln("applied %d patch(es) to %s", n, target)
		if err := s.reopen(); err != nil {
			return fmt.Errorf("patches were applied, but reopening the session failed: %w", err)
		}
		return nil
	}
	s.printfln("saved %d patch(es) to %s", n, target)
	return nil
}

// reopen remaps the file after an in-place apply: the old mapping
// references the replaced (unlinked) inode, and the disassembler's
// cached header data would be stale.
func (s *Session) reopen() error {
	if s.dis != nil {
		s.dis.Close()
		s.dis = nil
	}
	s.resolver = nil
	img, err := OpenImage(s.img.Path)
	if err != nil {
		return err
	}
	old := s.img
	s.img = img
	old.Close()
	st, err := os.Stat(img.Path)
	if err != nil {
		return err
	}
	s.openSig = fileSig{size: st.Size(), mtime: st.ModTime()}
	return nil
}

// checkUnchanged refuses to overwrite a file that changed since the
// session opened.
func (s *Session) checkUnchanged() error {
	st, err := os.Stat(s.img.Path)
	if err != nil {
		return err
	}
	if st.Size() != s.openSig.size || !st.ModTime().Equal(s.openSig.mtime) {
		return fmt.Errorf("%s changed since this session opened (size or mtime); reopen the session before applying over it", s.img.Path)
	}
	return nil
}

// writePatched streams the mapped source through atomicfile, splicing
// in the merged staged runs; memory stays bounded by commitChunkBytes.
func (s *Session) writePatched(target string, perm os.FileMode) error {
	f, err := atomicfile.Create(target, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", target, err)
	}
	defer f.Abort()

	data := s.img.Bytes()
	pos := int64(0)
	for _, r := range s.runs {
		if err := writeRange(f, data, pos, r.off); err != nil {
			return fmt.Errorf("write %s: %w", target, err)
		}
		if _, err := f.Write(r.data); err != nil {
			return fmt.Errorf("write %s: %w", target, err)
		}
		pos = r.off + int64(len(r.data))
	}
	if err := writeRange(f, data, pos, s.img.Size); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	if err := f.Commit(); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	return nil
}

func writeRange(w io.Writer, data []byte, start, end int64) error {
	for start < end {
		chunk := end - start
		if chunk > commitChunkBytes {
			chunk = commitChunkBytes
		}
		if _, err := w.Write(data[start : start+chunk]); err != nil {
			return err
		}
		start += chunk
	}
	return nil
}

// printDiff writes the staged patch list, capping each patch preview.
func (s *Session) printDiff() {
	if !s.dirty() {
		s.printfln("; no staged patches")
		return
	}
	bytes := 0
	for _, p := range s.patches {
		bytes += len(p.New)
	}
	s.printfln("; %d staged patch(es), %d byte(s)", len(s.patches), bytes)
	for i, p := range s.patches {
		s.printfln("#%d f:0x%08x  orig: %s  new: %s", i, p.Off, hexPreview(p.Orig), hexPreview(p.New))
	}
}

// confirm prints an interactive y/N prompt and reads one line.
func (s *Session) confirm(prompt string) bool {
	s.printf("%s [y/N] ", prompt)
	line, _ := s.in.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// isOriginal reports whether target refers to the same file the
// session was opened on.
func (s *Session) isOriginal(target string) bool {
	st, err := os.Stat(target)
	if err != nil {
		return false
	}
	orig, err := os.Stat(s.img.Path)
	if err != nil {
		return false
	}
	return os.SameFile(st, orig)
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// parseHexBytes joins hex args (spaces optional) and decodes them.
func parseHexBytes(args []string) ([]byte, error) {
	joined := strings.Join(args, "")
	if joined == "" {
		return nil, fmt.Errorf("no bytes given")
	}
	if len(joined)%2 != 0 {
		return nil, fmt.Errorf("odd number of hex digits in %q", joined)
	}
	data, err := hex.DecodeString(joined)
	if err != nil {
		return nil, fmt.Errorf("invalid hex bytes: %w", err)
	}
	return data, nil
}

// hexPreview renders bytes as space-separated hex, truncating long
// patches with a count of the hidden remainder.
func hexPreview(b []byte) string {
	shown := b
	suffix := ""
	if len(b) > diffPreviewBytes {
		shown = b[:diffPreviewBytes]
		suffix = fmt.Sprintf(" ... (%d more)", len(b)-diffPreviewBytes)
	}
	parts := make([]string, len(shown))
	for i, x := range shown {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, " ") + suffix
}

func rangesOverlap(aOff, aLen, bOff, bLen int64) bool {
	return aOff < bOff+bLen && bOff < aOff+aLen
}
