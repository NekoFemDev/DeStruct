package hermes

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/destruct/destruct/internal/hermes/asm"
	"github.com/destruct/destruct/internal/hermes/disasm"
	"github.com/destruct/destruct/internal/hermes/ir"
	"github.com/destruct/destruct/internal/hermes/parser"
)

// =============================================================================
// Repl is an interactive, radare2-inspired command shell for patching a
// .hbc/.bundle file, rebuilt on the parser/disasm/asm packages:
//
//   - the working file bytes (Data) are the source of truth; every write
//     re-parses them into an ir.Module so all views stay consistent;
//   - `wx` overwrites raw bytes in place (fixed size, no recalculation),
//     like radare2's own wx;
//   - `wi` replaces one instruction through the full assembler pipeline
//     (address recalculation, Addr8->*Long promotion, header/SHA1
//     bookkeeping) by reassembling a partial disassembly of the function
//     the cursor is in;
//   - nothing touches disk until an explicit `w`/`wq`.
// =============================================================================

// Repl holds one interactive patching session's state.
type Repl struct {
	File   *ir.Module // parsed view of Data (may lag after a raw `wx`)
	Data   []byte     // working file bytes
	Cursor uint32     // absolute file offset
	Path   string     // path this session was opened from (default save target for `w`)
	Dirty  bool       // true if any write command has been applied since the last save

	out io.Writer
}

// NewRepl creates a patching session over the given file bytes. path is
// the default save target for `w`. The SHA1 footer is verified on open,
// the same as a plain parse.
func NewRepl(hbcData []byte, path string, out io.Writer) (*Repl, error) {
	m, err := parser.Parse(hbcData)
	if err != nil {
		return nil, err
	}
	if err := parser.Decode(m); err != nil {
		return nil, err
	}
	return &Repl{
		File: m,
		Data: append([]byte(nil), hbcData...),
		Path: path,
		out:  out,
	}, nil
}

// Run reads commands from in, one per line, until `q`/`quit`/EOF, printing
// a "> " prompt and command output to the Repl's configured writer. It
// returns nil on a clean quit (including EOF); a non-nil error only for an
// I/O failure reading input.
func (r *Repl) Run(in io.Reader) error {
	scanner := bufio.NewScanner(in)
	fmt.Fprintln(r.out, "DeStruct interactive patcher. Type 'help' for commands, 'q' to quit.")
	r.printPrompt()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			quit, err := r.Exec(line)
			if err != nil {
				fmt.Fprintf(r.out, "error: %v\n", err)
			}
			if quit {
				return nil
			}
		}
		r.printPrompt()
	}
	return scanner.Err()
}

func (r *Repl) printPrompt() {
	fmt.Fprintf(r.out, "[0x%08x]> ", r.Cursor)
}

// Exec runs a single command line. Returns (true, nil) if the session
// should end (a quit command was given).
func (r *Repl) Exec(line string) (quit bool, err error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false, nil
	}
	cmd, args := fields[0], fields[1:]

	switch cmd {
	case "q", "quit":
		if r.Dirty {
			fmt.Fprintln(r.out, "warning: unsaved changes - use 'w' to save, or 'q!' to discard and quit")
			return false, nil
		}
		return true, nil
	case "q!":
		return true, nil

	case "help", "?":
		r.printHelp()
		return false, nil

	case "i":
		return false, r.cmdInfo()

	case "s", "seek":
		return false, r.cmdSeek(args)

	case "px":
		return false, r.cmdHexdump(args)

	case "pd":
		return false, r.cmdDisasm(args)

	case "pf":
		return false, r.cmdFuncInfo()

	case "f", "functions":
		return false, r.cmdListFunctions(args)

	case "sf":
		return false, r.cmdSeekFunction(args)

	case "wx":
		return false, r.cmdWriteBytes(args)

	case "wi":
		return false, r.cmdWriteInstruction(line)

	case "w":
		return false, r.cmdSave(r.Path)

	case "wq":
		path := r.Path
		if len(args) > 0 {
			path = args[0]
		}
		if err := r.cmdSave(path); err != nil {
			return false, err
		}
		return true, nil

	default:
		return false, fmt.Errorf("unknown command %q (type 'help' for a list)", cmd)
	}
}

func (r *Repl) printHelp() {
	fmt.Fprint(r.out, `Commands:
  s <addr>            seek to an absolute file offset (hex, e.g. s 0x1c or s 1c)
  sf <name|#N>         seek to a function by name or index (e.g. sf describeFiber, sf #2962)
  f [filter]           list functions, optionally filtered by substring
  i                    file info (version, function count, size)
  pf                   info about the function the cursor is currently in
  px [n]                hexdump n bytes from the cursor (default 64)
  pd [n]                disassemble n instructions from the cursor, hermes-dec format (default 10)
  wx <hex bytes>        write raw bytes at the cursor (fixed size, no address recalculation - e.g. wx 9096)
  wi <instruction text>  write one instruction via the assembler at the cursor's instruction
                         (e.g. wi LoadConstFalse Reg8: 4 - goes through full address recalculation
                         and can change the instruction's size; Addr8 branches are promoted
                         to their *Long form automatically)
  w                     save changes to the file this session was opened from
  wq [path]             save (to path if given, else the original file) and quit
  q                     quit (warns if there are unsaved changes)
  q!                    quit without saving, discarding any warning
  help, ?               this text
`)
}

func (r *Repl) cmdInfo() error {
	f := r.File
	fmt.Fprintf(r.out, "path: %s\n", r.Path)
	fmt.Fprintf(r.out, "bytecode version: %d\n", f.Version)
	fmt.Fprintf(r.out, "functions: %d\n", len(f.Functions))
	fmt.Fprintf(r.out, "strings: %d\n", len(f.Strings))
	fmt.Fprintf(r.out, "file size: %d bytes\n", len(r.Data))
	if r.Dirty {
		fmt.Fprintln(r.out, "status: unsaved changes")
	} else {
		fmt.Fprintln(r.out, "status: clean")
	}
	return nil
}

// parseAddr parses an address argument the way radare2 does: an optional
// "0x" prefix, always hex.
func parseAddr(s string) (uint32, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid address %q: %w", s, err)
	}
	return uint32(v), nil
}

func (r *Repl) cmdSeek(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: s <addr>")
	}
	addr, err := parseAddr(args[0])
	if err != nil {
		return err
	}
	if int64(addr) >= int64(len(r.Data)) {
		return fmt.Errorf("address 0x%x is past the end of the file (0x%x bytes)", addr, len(r.Data))
	}
	r.Cursor = addr
	return nil
}

func (r *Repl) cmdHexdump(args []string) error {
	n := 64
	if len(args) > 0 {
		v, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid byte count %q: %w", args[0], err)
		}
		n = v
	}
	if n <= 0 {
		return fmt.Errorf("byte count must be positive")
	}
	start := int64(r.Cursor)
	end := start + int64(n)
	if end > int64(len(r.Data)) {
		end = int64(len(r.Data))
	}
	if start >= end {
		return fmt.Errorf("nothing to show at 0x%x", r.Cursor)
	}
	data := r.Data[start:end]

	for i := 0; i < len(data); i += 16 {
		row := data[i:]
		if len(row) > 16 {
			row = row[:16]
		}
		fmt.Fprintf(r.out, "0x%08x  ", start+int64(i))
		for j := 0; j < 16; j++ {
			if j < len(row) {
				fmt.Fprintf(r.out, "%02x ", row[j])
			} else {
				fmt.Fprint(r.out, "   ")
			}
			if j == 7 {
				fmt.Fprint(r.out, " ")
			}
		}
		fmt.Fprint(r.out, " ")
		for _, b := range row {
			if b >= 0x20 && b < 0x7f {
				fmt.Fprintf(r.out, "%c", b)
			} else {
				fmt.Fprint(r.out, ".")
			}
		}
		fmt.Fprintln(r.out)
	}
	return nil
}

// funcAtOffset finds which function's bytecode contains the given
// absolute file offset, and returns its index and offset-within-function.
// Returns (-1, 0) if the offset doesn't fall within any function's
// current bytecode range.
func (r *Repl) funcAtOffset(addr uint32) (funcIdx int, funcRelOffset uint32) {
	for i := range r.File.Functions {
		h := &r.File.Functions[i]
		if addr >= h.Offset && addr < h.Offset+h.BytecodeSizeInBytes {
			return i, addr - h.Offset
		}
	}
	return -1, 0
}

func (r *Repl) cmdDisasm(args []string) error {
	n := 10
	if len(args) > 0 {
		v, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid instruction count %q: %w", args[0], err)
		}
		n = v
	}
	if n <= 0 {
		return fmt.Errorf("instruction count must be positive")
	}

	funcIdx, relOff := r.funcAtOffset(r.Cursor)
	if funcIdx < 0 {
		return fmt.Errorf("0x%x is not inside any function's bytecode - use 'sf' to seek to a function first", r.Cursor)
	}
	f := &r.File.Functions[funcIdx]

	// Start from the instruction containing the cursor (the cursor may
	// sit mid-instruction).
	start := -1
	for i := range f.Instructions {
		in := &f.Instructions[i]
		if in.Offset <= relOff && relOff < in.Offset+uint32(in.Size()) {
			start = i
			break
		}
	}
	if start < 0 {
		return fmt.Errorf("0x%x is not within any decoded instruction of function #%d", r.Cursor, funcIdx)
	}

	for i := start; i < len(f.Instructions) && i < start+n; i++ {
		in := &f.Instructions[i]
		text, err := disasm.FormatInstruction(r.File, in)
		if err != nil {
			return err
		}
		marker := "  "
		if f.Offset+in.Offset == r.Cursor {
			marker = "->"
		}
		fmt.Fprintf(r.out, "%s func#%d %s\n", marker, funcIdx, text)
	}
	return nil
}

func (r *Repl) cmdFuncInfo() error {
	funcIdx, relOff := r.funcAtOffset(r.Cursor)
	if funcIdx < 0 {
		return fmt.Errorf("0x%x is not inside any function's bytecode", r.Cursor)
	}
	h := &r.File.Functions[funcIdx]
	fmt.Fprintf(r.out, "function #%d %q\n", funcIdx, h.Name)
	fmt.Fprintf(r.out, "  file offset: 0x%08x, size: %d bytes\n", h.Offset, h.BytecodeSizeInBytes)
	fmt.Fprintf(r.out, "  cursor is at instruction-stream offset 0x%x within this function\n", relOff)
	fmt.Fprintf(r.out, "  params: %d, frame size: %d, strict: %v\n", h.ParamCount, h.FrameSize, h.StrictMode)
	return nil
}

func (r *Repl) cmdListFunctions(args []string) error {
	filter := ""
	if len(args) > 0 {
		filter = strings.ToLower(args[0])
	}
	count := 0
	for i := range r.File.Functions {
		h := &r.File.Functions[i]
		if filter != "" && !strings.Contains(strings.ToLower(h.Name), filter) {
			continue
		}
		fmt.Fprintf(r.out, "#%-6d 0x%08x  %6d bytes  %s\n", i, h.Offset, h.BytecodeSizeInBytes, h.Name)
		count++
		if count >= 200 {
			fmt.Fprintln(r.out, "... (200 shown, refine your filter for more)")
			break
		}
	}
	return nil
}

func (r *Repl) cmdSeekFunction(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sf <name|#N>")
	}
	target := args[0]

	if strings.HasPrefix(target, "#") {
		idx, err := strconv.Atoi(target[1:])
		if err != nil {
			return fmt.Errorf("invalid function index %q: %w", target, err)
		}
		if idx < 0 || idx >= len(r.File.Functions) {
			return fmt.Errorf("function index %d out of range (file has %d functions)", idx, len(r.File.Functions))
		}
		r.Cursor = r.File.Functions[idx].Offset
		return nil
	}

	lower := strings.ToLower(target)
	var matches []int
	for i := range r.File.Functions {
		if strings.ToLower(r.File.Functions[i].Name) == lower {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("no function named %q (use 'f %s' to search by substring)", target, target)
	}
	if len(matches) > 1 {
		sort.Ints(matches)
		fmt.Fprintf(r.out, "multiple functions named %q, seeking to the first (#%d); others: ", target, matches[0])
		for i, m := range matches[1:] {
			if i > 0 {
				fmt.Fprint(r.out, ", ")
			}
			fmt.Fprintf(r.out, "#%d", m)
		}
		fmt.Fprintln(r.out)
	}
	r.Cursor = r.File.Functions[matches[0]].Offset
	return nil
}

// reparse refreshes the parsed view from the working bytes without the
// SHA1 check (the footer is stale between an edit and the next save).
func (r *Repl) reparse() error {
	m, err := parser.ParseWithOptions(r.Data, parser.Options{SkipHashCheck: true})
	if err != nil {
		return err
	}
	if err := parser.Decode(m); err != nil {
		return err
	}
	r.File = m
	return nil
}

func (r *Repl) cmdWriteBytes(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: wx <hex bytes> (e.g. wx 9096, or wx 90 96)")
	}
	joined := strings.Join(args, "")
	joined = strings.ReplaceAll(joined, " ", "")
	if len(joined)%2 != 0 {
		return fmt.Errorf("odd number of hex digits in %q", joined)
	}
	data, err := hex.DecodeString(joined)
	if err != nil {
		return fmt.Errorf("invalid hex bytes: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("no bytes given")
	}

	start := int64(r.Cursor)
	end := start + int64(len(data))
	if end > int64(len(r.Data)) {
		return fmt.Errorf("writing %d bytes at 0x%x would go past the end of the file (0x%x bytes) - wx never changes file size, only overwrites in place", len(data), r.Cursor, len(r.Data))
	}

	copy(r.Data[start:end], data)
	r.Dirty = true

	// Refresh the parsed view so pd/pf see the new bytes. A raw write
	// can land mid-instruction and make the file undecodable; in that
	// case the bytes are kept but the parsed view stays on the last
	// good state (a warning tells the user).
	if err := r.reparse(); err != nil {
		fmt.Fprintf(r.out, "wrote %d bytes at 0x%08x (warning: file no longer parses: %v)\n", len(data), r.Cursor, err)
		return nil
	}
	fmt.Fprintf(r.out, "wrote %d bytes at 0x%08x\n", len(data), r.Cursor)
	return nil
}

func (r *Repl) cmdWriteInstruction(line string) error {
	// Everything after "wi " is the instruction text, e.g.
	// "LoadConstFalse Reg8: 4" or "Jmp Addr8: 20". Reformat it into one
	// hermes-dec-exact instruction line and push the whole function
	// through the same parse+diff+patch pipeline the file-based
	// assembler uses - no separate parsing logic to keep in sync.
	rest := strings.TrimSpace(strings.TrimPrefix(line, "wi"))
	if rest == "" {
		return fmt.Errorf("usage: wi <Name> [Type: value, Type: value, ...] (e.g. wi LoadConstFalse Reg8: 4)")
	}

	name, operandsText, _ := strings.Cut(rest, " ")
	operandsText = strings.TrimSpace(operandsText)

	funcIdx, relOff := r.funcAtOffset(r.Cursor)
	if funcIdx < 0 {
		return fmt.Errorf("0x%x is not inside any function's bytecode - use 'sf' to seek to a function first", r.Cursor)
	}

	f := &r.File.Functions[funcIdx]
	if _, err := instructionIndexAt(f, relOff); err != nil {
		return err
	}

	text, err := disasm.Function(r.File, funcIdx)
	if err != nil {
		return err
	}
	lines := strings.Split(text, "\n")

	// Replace the instruction line whose offset matches the cursor.
	targetLine := fmt.Sprintf("==> %08x:", relOff)
	replaced := false
	for i, l := range lines {
		if strings.HasPrefix(l, targetLine) {
			lines[i] = fmt.Sprintf("==> %08x: <%s>: <%s>", relOff, name, operandsText)
			replaced = true
			break
		}
	}
	if !replaced {
		return fmt.Errorf("internal error: could not locate instruction at 0x%x in function #%d's text (please report this as a bug)", relOff, funcIdx)
	}

	result, err := asm.Assemble(r.File, strings.Join(lines, "\n"))
	if err != nil {
		return fmt.Errorf("assembling: %w", err)
	}
	if len(result.ChangedFunctions) == 0 {
		fmt.Fprintln(r.out, "no change (identical to current instruction)")
		return nil
	}

	// Adopt the patched bytes and refresh the parsed view so offsets,
	// sizes and instruction boundaries reflect the edit.
	r.Data = result.Data
	r.Dirty = true
	if err := r.reparse(); err != nil {
		return fmt.Errorf("re-parsing the patched file: %w", err)
	}
	fmt.Fprintf(r.out, "patched function #%d (size change: %+d bytes)\n", funcIdx, result.SizeDelta)
	return nil
}

// instructionIndexAt returns the 0-based index, among f's current
// instructions, of the one starting exactly at relOff (function-relative
// byte offset). Errors if relOff isn't the start of any instruction.
func instructionIndexAt(f *ir.Function, relOff uint32) (int, error) {
	for i := range f.Instructions {
		if f.Instructions[i].Offset == relOff {
			return i, nil
		}
	}
	return 0, fmt.Errorf("0x%x is not the start of an instruction in function #%d - use 'pd' to see valid instruction boundaries", f.Offset+relOff, f.Index)
}

func (r *Repl) cmdSave(path string) error {
	if path == "" {
		return fmt.Errorf("no path to save to (this session wasn't opened from a file path)")
	}
	if err := r.refreshSHA1(); err != nil {
		return err
	}
	if err := os.WriteFile(path, r.Data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	r.Dirty = false
	fmt.Fprintf(r.out, "saved to %s\n", path)
	return nil
}

// refreshSHA1 recomputes the SHA1 footer over the working bytes. The
// footer lives at FileLength-20 within the file (FileLength includes it).
func (r *Repl) refreshSHA1() error {
	h := r.File.Header
	if h.Version < 75 {
		return nil
	}
	fileLength := int(h.FileLength)
	if fileLength < 20 || fileLength > len(r.Data) {
		return fmt.Errorf("file length %d in the header is not consistent with the %d-byte buffer", fileLength, len(r.Data))
	}
	sum := sha1.Sum(r.Data[:fileLength-20])
	copy(r.Data[fileLength-20:fileLength], sum[:])
	return nil
}
