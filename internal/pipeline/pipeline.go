package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/destruct/destruct/internal/archivelimits"
	"github.com/destruct/destruct/internal/arm64lift"
	"github.com/destruct/destruct/internal/atomicfile"
	"github.com/destruct/destruct/internal/dex"
	unflutter "github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/cmd/unflutter"
	"github.com/destruct/destruct/internal/il2cpp"
	"github.com/destruct/destruct/internal/ir"
	javagen "github.com/destruct/destruct/internal/java"
	"github.com/destruct/destruct/internal/jvm"
	"github.com/destruct/destruct/internal/llvm"
	"github.com/destruct/destruct/internal/native"
)

type Format int

const (
	FormatJVM Format = iota
	FormatFlutter
	FormatELF
	FormatDEX
)

type Options struct {
	Input           string
	Output          string
	Format          Format
	Verbose         bool
	Deobf           bool
	Project         bool
	Decompile       bool
	SourceLocations bool
	SplitFunctions  bool
	CrossReferences bool
	SimplifyCFG     bool
	EmitLLVM        bool
	// IL2CPPOffsets is the path to an IL2CPP field-offset dump -
	// offsets.json / offset.hpp, or a directory containing one (see
	// internal/arm64lift.LoadOffsetDB). Empty means no IL2CPP metadata
	// is loaded and the lifted output stays purely numeric.
	IL2CPPOffsets string
	// IL2CPPMetadata is the path to a Unity global-metadata.dat. When
	// set (or auto-detected next to a libil2cpp.so), method names,
	// parameter names and instance field names/offsets are recovered.
	IL2CPPMetadata string
	// EmitPseudo selects the unified pseudo-C rendering explicitly (the
	// default). It exists so a caller can request the documented mode by
	// name; it no longer has a mutually exclusive alternative.
	EmitPseudo bool
	// RegsAsVars renames register placeholders to argN / var_N /
	// fvar_N in the pseudo output as well - see
	// arm64lift.LiftOptions.RegsAsVars.
	RegsAsVars bool
}

type Pipeline struct {
	opts Options
	// dwarf is the optional debug-info index loaded for ELF
	// decompilation; nil when the input has no usable DWARF.
	dwarf *native.DWARFInfo
	// il2cppIndex is the optional Unity metadata index loaded from
	// --il2cpp-metadata (or auto-detected global-metadata.dat).
	il2cppIndex *il2cpp.MetadataIndex
	// codeContains reports whether an address lies in an executable
	// section of the ELF currently being decompiled.
	codeContains func(uint64) bool
	// elfImageBase/elfImageSize describe the original load image emitted
	// alongside split output for absolute-address reconstruction.
	elfImageBase uint64
	elfImageSize uint64
	// functionPtr maps an address to the C symbol of a lifted or imported
	// function, for function-pointer arguments and tables.
	functionPtr func(uint64) (string, bool)
	// knownFunction reports candidate function starts to the lifter so it
	// doesn't inline a real function that happens to sit inside a larger
	// lift range.
	knownFunction func(uint64) bool
	// outlinedContexts maps outlined entry points to the callee-saved
	// registers they inherit from their dispatcher.
	outlinedContexts map[uint64][]string
	// condMiss counts unresolved condition operators for diagnostics.
	condMiss        map[string]int
	condMissSamples []string
}

// Magic numbers for the cheap boundary-level signature checks below.
var (
	zipMagic = []byte{'P', 'K', 0x03, 0x04} // JAR/APK are zip containers
	elfMagic = []byte{0x7f, 'E', 'L', 'F'}  // shared objects are ELF
)

func New(opts Options) *Pipeline {
	if opts.Output == "" {
		opts.Output = "output"
	}
	return &Pipeline{opts: opts}
}

// ext returns the input path's extension, lowercased, so that .JAR, .Jar
// and .jar all dispatch identically. Every format check in this file goes
// through it rather than calling filepath.Ext directly.
func (p *Pipeline) ext() string {
	return strings.ToLower(filepath.Ext(p.opts.Input))
}

// validateInputSignature is a cheap sanity check that the input actually
// looks like the container its extension claims. A .jar that isn't a zip,
// or a .so that isn't an ELF, otherwise fails deep inside a parser with a
// confusing message; catching the magic here gives a clear error and avoids
// creating an output directory for input that can never be processed.
// Formats without a cheap magic check (.class, .dex, raw ELF, PE) fall
// through to their own parsers.
func (p *Pipeline) validateInputSignature() error {
	var magic []byte
	switch p.ext() {
	case ".jar", ".apk":
		magic = zipMagic
	case ".so", ".elf":
		magic = elfMagic
	default:
		return nil
	}

	f, err := os.Open(p.opts.Input)
	if err != nil {
		return fmt.Errorf("opening input: %w", err)
	}
	defer f.Close()

	var header [4]byte
	if _, err := io.ReadFull(f, header[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return fmt.Errorf("input %s is too small to be a valid %s file", p.opts.Input, strings.TrimPrefix(p.ext(), "."))
		}
		return fmt.Errorf("reading input header: %w", err)
	}
	if !bytes.HasPrefix(header[:], magic) {
		return fmt.Errorf("input %s does not look like a valid %s file (bad signature)", p.opts.Input, strings.TrimPrefix(p.ext(), "."))
	}
	return nil
}

// Run executes the pipeline with a background context. It is a thin
// wrapper around RunContext, kept so existing callers don't have to change.
func (p *Pipeline) Run() error {
	return p.RunContext(context.Background())
}

// RunContext executes the pipeline, cancelling the format-specific work if
// ctx is done. ctx is checked at the natural boundaries of each format's
// long loop - per .class/.dex entry for JAR/DEX/APK, per function for ELF -
// so a SIGINT or API timeout stops work cleanly instead of only after the
// whole input has been processed. The format runners that accept a context
// are called through their Context variants; Flutter's in-process scan
// (unflutter.Run) does not take a context, so it is only checked at its
// outer boundary.
func (p *Pipeline) RunContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.validateInputSignature(); err != nil {
		return err
	}

	if err := os.MkdirAll(p.opts.Output, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	switch p.opts.Format {
	case FormatFlutter:
		return p.decompileFlutter(ctx)

	case FormatJVM:
		return p.decompileAndGenerateJVM(ctx)

	case FormatDEX:
		return p.decompileAndGenerateDEX(ctx)

	case FormatELF:
		if p.opts.Decompile {
			return p.decompileELFArm64(ctx)
		}
		return p.disassembleELF(ctx)

	default:
		return fmt.Errorf("unsupported input format")
	}
}

func (p *Pipeline) decompileAndGenerateJVM(ctx context.Context) error {
	ext := p.ext()

	gen := javagen.NewGenerator(javagen.Options{
		OutputDir: p.opts.Output,
		Deobf:     p.opts.Deobf,
		Verbose:   p.opts.Verbose,
	})

	if ext != ".jar" {
		prog, err := jvm.DecompileClassFile(p.opts.Input)
		if err != nil {
			return fmt.Errorf("decompilation: %w", err)
		}
		return gen.Generate(prog)
	}

	total, err := jvm.CountClassEntriesContext(ctx, p.opts.Input)
	if err != nil {
		return fmt.Errorf("reading jar: %w", err)
	}
	fmt.Printf("Found %d classes in %s\n", total, filepath.Base(p.opts.Input))

	// Stream the .jar one class at a time: read -> parse -> decompile ->
	// write .java -> discard, before moving to the next entry. This is
	// what keeps memory use flat regardless of how many classes the .jar
	// contains, instead of holding every class's parsed bytecode and
	// decompiled AST in memory simultaneously.
	//
	// current* below is watched by a background goroutine so that if any
	// single class's parse/decompile/generate ever takes an unusually
	// long time (a stall that isn't itself an infinite loop bug, or a
	// bug not yet found), the person sees which class it's stuck on
	// instead of the process silently going quiet.
	var currentMu sync.Mutex
	currentName := ""
	currentStart := time.Now()

	watchdogStop := make(chan struct{})
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		lastWarned := ""
		for {
			select {
			case <-watchdogStop:
				return
			case <-ticker.C:
				currentMu.Lock()
				name, since := currentName, time.Since(currentStart)
				currentMu.Unlock()
				if name == "" || name == lastWarned {
					continue
				}
				if since > 8*time.Second {
					fmt.Printf("  ... still on %s (%.0fs) - this class may be unusually large or complex\n", name, since.Seconds())
					lastWarned = name
				}
			}
		}
	}()

	count := 0
	skipped := 0
	lastReport := time.Now()
	err = jvm.DecompileJARStreamingContext(ctx, p.opts.Input,
		func(cf *jvm.ClassFile, prog *ir.Program) error {
			for _, class := range prog.Classes {
				currentMu.Lock()
				currentName = class.Name
				currentStart = time.Now()
				currentMu.Unlock()

				if err := gen.GenerateClass(class); err != nil {
					return err
				}
				count++

				if p.opts.Verbose {
					fmt.Printf("  [%d/%d] %s\n", count, total, class.Name)
				} else if time.Since(lastReport) > time.Second {
					fmt.Printf("  ... %d/%d classes\n", count, total)
					lastReport = time.Now()
				}
			}
			return nil
		},
		func(entryName string, reason jvm.SkipReason, entryErr error) {
			skipped++
			if p.opts.Verbose {
				if entryErr != nil {
					fmt.Printf("  [skip] %s: %s (%v)\n", entryName, reason, entryErr)
				} else {
					fmt.Printf("  [skip] %s: %s\n", entryName, reason)
				}
			}
		},
	)

	close(watchdogStop)
	<-watchdogDone

	if err != nil {
		return fmt.Errorf("decompilation: %w", err)
	}

	fmt.Printf("Decompiled %d classes\n", count)
	if skipped > 0 {
		fmt.Printf("Skipped %d classes (malformed, oversized, or failed to decompile; rerun with -v to see which)\n", skipped)
	}
	return nil
}

func (p *Pipeline) decompileAndGenerateDEX(ctx context.Context) error {
	ext := p.ext()

	gen := javagen.NewGenerator(javagen.Options{
		OutputDir: p.opts.Output,
		Deobf:     p.opts.Deobf,
		Verbose:   p.opts.Verbose,
	})

	// For DEX files, we process them directly
	if ext == ".dex" {
		// Count classes first
		total, err := dex.CountDexClassesContext(ctx, p.opts.Input)
		if err != nil {
			return fmt.Errorf("counting dex classes: %w", err)
		}
		fmt.Printf("Found %d classes in %s\n", total, filepath.Base(p.opts.Input))

		// Stream the DEX file one class at a time
		var currentMu sync.Mutex
		currentName := ""
		currentStart := time.Now()

		watchdogStop := make(chan struct{})
		watchdogDone := make(chan struct{})
		go func() {
			defer close(watchdogDone)
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-watchdogStop:
					return
				case <-ticker.C:
					currentMu.Lock()
					name := currentName
					elapsed := time.Since(currentStart)
					currentMu.Unlock()
					if elapsed > 5*time.Second && name != "" {
						fmt.Fprintf(os.Stderr, "  [watchdog] still processing %s (%.1fs)...\n", name, elapsed.Seconds())
					}
				}
			}
		}()

		err = dex.DecompileDexStreamingContext(ctx, p.opts.Input, func(class *ir.Class) {
			fullName := class.Package + "." + class.Name
			if class.Package == "" {
				fullName = class.Name
			}
			currentMu.Lock()
			currentName = fullName
			currentStart = time.Now()
			currentMu.Unlock()

			if err := gen.GenerateClass(class); err != nil {
				fmt.Fprintf(os.Stderr, "Error generating class %s: %v\n", fullName, err)
			}
		}, func(className string, err error) {
			fmt.Fprintf(os.Stderr, "Error decompiling %s: %v\n", className, err)
		})

		close(watchdogStop)
		<-watchdogDone

		if err != nil {
			return fmt.Errorf("decompilation: %w", err)
		}
		return nil
	}

	// For APK files, extract and process all DEX files
	if ext == ".apk" {
		total, err := dex.CountApkDexClassesContext(ctx, p.opts.Input)
		if err != nil {
			return fmt.Errorf("counting apk dex classes: %w", err)
		}
		fmt.Printf("Found %d classes in %s\n", total, filepath.Base(p.opts.Input))

		err = dex.DecompileApkStreamingContext(ctx, p.opts.Input, func(class *ir.Class) {
			fullName := class.Package + "." + class.Name
			if class.Package == "" {
				fullName = class.Name
			}
			if err := gen.GenerateClass(class); err != nil {
				fmt.Fprintf(os.Stderr, "Error generating class %s: %v\n", fullName, err)
			}
		}, func(name string, err error) {
			fmt.Fprintf(os.Stderr, "Skipping %s: %v\n", name, err)
		})
		if err != nil {
			return fmt.Errorf("decompiling apk: %w", err)
		}
		return nil
	}

	return fmt.Errorf("unsupported DEX file format: %s", ext)
}

func (p *Pipeline) decompileFlutter(ctx context.Context) error {
	input := p.opts.Input
	ext := p.ext()

	if err := ctx.Err(); err != nil {
		return err
	}

	// If input is APK, extract libapp.so first.
	if ext == ".apk" {
		soPath, err := p.extractLibapp(ctx, input)
		if err != nil {
			return fmt.Errorf("extract libapp.so from APK: %w", err)
		}
		input = soPath
		defer os.Remove(input)
	}

	args := []string{input, "--out", p.opts.Output}
	if p.opts.Verbose {
		args = append(args, "--verbose")
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	if exitCode, err := unflutter.Run(args); err != nil {
		return fmt.Errorf("unflutter (exit %d): %w", exitCode, err)
	}
	// unflutter.Run does not accept a context, so an in-flight scan can only
	// be observed here, at its outer boundary, rather than aborted mid-scan.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Combine per-function .txt and .bin files into output root.
	asmDir := filepath.Join(p.opts.Output, "asm")
	if err := combineAsmFiles(ctx, asmDir, p.opts.Output); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not combine asm files: %v\n", err)
	} else {
		fmt.Printf("Combined: %s/asm.txt + asm.bin\n", p.opts.Output)
	}

	fmt.Printf("Flutter disassembly complete. Output: %s/\n", p.opts.Output)
	fmt.Println("Edit asm.txt (ARM64 assembly) and use asm.bin for binary patching.")
	return nil
}

func combineAsmFiles(ctx context.Context, asmDir, outDir string) error {
	entries, err := os.ReadDir(asmDir)
	if err != nil {
		return err
	}

	type funcEntry struct {
		name string
		txt  string
		bin  []byte
	}
	var funcs []funcEntry

	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") || e.Name() == "asm.txt" {
			continue
		}
		funcName := strings.TrimSuffix(e.Name(), ".txt")
		txtData, err := os.ReadFile(filepath.Join(asmDir, e.Name()))
		if err != nil {
			continue
		}
		binData, _ := os.ReadFile(filepath.Join(asmDir, funcName+".bin"))
		funcs = append(funcs, funcEntry{name: funcName, txt: string(txtData), bin: binData})
	}
	if len(funcs) == 0 {
		return fmt.Errorf("no .txt files in %s", asmDir)
	}

	txtOut, err := atomicfile.Create(filepath.Join(outDir, "asm.txt"), 0o644)
	if err != nil {
		return err
	}
	defer txtOut.Abort()

	binOut, err := atomicfile.Create(filepath.Join(outDir, "asm.bin"), 0o644)
	if err != nil {
		return err
	}
	defer binOut.Abort()

	for _, f := range funcs {
		fmt.Fprintf(txtOut, "\n; ===== %s =====\n", f.name)
		txtOut.WriteString(f.txt)
		binOut.Write(f.bin)
	}
	if err := txtOut.Commit(); err != nil {
		return err
	}
	return binOut.Commit()
}

func (p *Pipeline) extractLibapp(ctx context.Context, apkPath string) (string, error) {
	zr, err := archivelimits.Open(apkPath)
	if err != nil {
		return "", err
	}
	defer zr.Close()

	var budget archivelimits.ReadBudget
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if strings.HasPrefix(f.Name, "lib/arm64-v8a/") && strings.HasSuffix(f.Name, "libapp.so") {
			data, err := budget.ReadEntry(f)
			if err != nil {
				return "", err
			}

			tmp, err := os.CreateTemp("", "libapp-*.so")
			if err != nil {
				return "", err
			}
			if _, err := tmp.Write(data); err != nil {
				tmp.Close()
				os.Remove(tmp.Name())
				return "", err
			}
			if err := tmp.Close(); err != nil {
				os.Remove(tmp.Name())
				return "", err
			}
			return tmp.Name(), nil
		}
	}

	return "", fmt.Errorf("libapp.so not found in lib/arm64-v8a/")
}

func (p *Pipeline) disassembleELF(ctx context.Context) error {
	if p.opts.Decompile {
		return p.decompileELFArm64(ctx)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	fmt.Printf("Parsing ELF file: %s\n", p.opts.Input)

	// Create output file
	outPath := filepath.Join(p.opts.Output, filepath.Base(p.opts.Input)+".asm")
	f, err := atomicfile.Create(outPath, 0o644)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Abort()

	if err := native.DisassembleELFFileContext(ctx, p.opts.Input, f); err != nil {
		return fmt.Errorf("disassemble ELF: %w", err)
	}
	if err := f.Commit(); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	fmt.Printf("Disassembly: %s\n", outPath)
	return nil
}

// annotatedELFResolver wraps the ELF symbol resolver with a
// section-label fallback for data addresses: when no symbol-table name
// exists for an address, a non-executable section the address falls in
// gives a traceable ".rodata+0x1fa0" / ".got+0x8" label instead of a
// bare decimal page constant. Executable addresses deliberately keep
// the base resolver's behavior (func_<addr> placeholders and real
// symbols) - see native.ELFParser.AnnotateAddr.
func annotatedELFResolver(ctx context.Context, elf *native.ELFParser) arm64lift.SymbolResolver {
	base := elf.SymbolResolverContext(ctx)
	return func(addr uint64) (string, bool) {
		if name, ok := base(addr); ok {
			return name, true
		}
		return elf.AnnotateAddr(addr)
	}
}

// loadIL2CPPOffsetDump loads an offset dump from a file (offsets.json /
// offset.hpp) or from a directory containing one. A directory without
// offsets.json but with offset.hpp is accepted too, so pointing at the
// game_dump or at a header-only copy both work.
func loadIL2CPPOffsetDump(path string) (*arm64lift.OffsetDB, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("IL2CPP offsets: %w", err)
	}
	if !st.IsDir() {
		return arm64lift.LoadOffsetDB(path)
	}
	for _, name := range []string{"offsets.json", "offset.hpp", "offsets.hpp"} {
		p := filepath.Join(path, name)
		if _, err := os.Stat(p); err == nil {
			return arm64lift.LoadOffsetDB(p)
		}
	}
	return nil, fmt.Errorf("IL2CPP offsets: %s contains neither offsets.json nor offset.hpp", path)
}

// decompileELFArm64 lifts every function symbol in an AArch64 ELF
// binary to C-like pseudocode (see internal/arm64lift) and writes the
// whole binary's output to a SINGLE file, one function after another -
// unlike disassembleELF's raw listing, this recovers real control flow
// (if/else, while/do-while loops, calls, locals, struct field access)
// rather than a flat instruction stream. Only AArch64 is supported (the
// lifter itself is architecture-specific); any other machine type
// fails fast with a clear error rather than silently producing
// nonsense output.
//
// Never aborts the whole run over one function: a panic recovered
// during a single function's own lift (this lifter is still a
// best-effort heuristic system, not a verified one - see
// internal/arm64lift/lift.go's own trailing doc comment for its
// documented, honest limitations) is reported inline as a comment in
// the output and counted, not fatal.
func (p *Pipeline) decompileELFArm64(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.dwarf = nil
	fmt.Printf("Parsing ELF file: %s\n", p.opts.Input)

	elf, err := native.NewELFParserContext(ctx, p.opts.Input)
	if err != nil {
		return fmt.Errorf("parsing ELF: %w", err)
	}
	if elf.Header.Machine != native.EM_AARCH64 {
		return fmt.Errorf("arm64 decompilation requires an AArch64 binary (machine type 0x%x found) - use plain \"destruct elf\" (without --decompile) for a raw disassembly of any architecture instead", elf.Header.Machine)
	}

	d, err := native.NewARM64Disassembler()
	if err != nil {
		return fmt.Errorf("creating disassembler: %w", err)
	}
	defer d.Close()

	resolver := annotatedELFResolver(ctx, elf)
	strResolver := func(addr uint64) (string, bool) { return elf.ReadCString(addr) }
	dataReader := elf.DataReader()
	p.codeContains = func(addr uint64) bool {
		for _, s := range elf.Sections {
			if s.Flags&native.SHF_EXECINSTR == 0 || s.Size == 0 || addr < s.Addr {
				continue
			}
			if addr-s.Addr < s.Size {
				return true
			}
		}
		return false
	}

	// Optional DWARF debug info: function/parameter names, source lines
	// and simple frame-relative locals. A binary without debug sections
	// is the common case and is not an error.
	if di, derr := native.LoadDWARF(p.opts.Input); derr == nil {
		p.dwarf = di
		s := di.Summary()
		fmt.Printf("DWARF: %d functions, %d lines, %d params, %d locals\n",
			s.Functions, s.Lines, s.Params, s.Locals)
		baseResolver := resolver
		resolver = func(addr uint64) (string, bool) {
			if fn, ok := di.FunctionAt(addr); ok && fn.Name != "" {
				return fn.Name, true
			}
			return baseResolver(addr)
		}
	} else if !errors.Is(derr, native.ErrNoDWARF) {
		fmt.Fprintf(os.Stderr, "warning: DWARF: %v\n", derr)
	}

	// Optional Unity IL2CPP metadata: method/parameter/field names.
	p.il2cppIndex = nil
	metadataPath := p.opts.IL2CPPMetadata
	if metadataPath == "" {
		metadataPath = findIL2CPPMetadata(p.opts.Input)
	}
	if metadataPath != "" {
		res, ierr := il2cpp.RunContext(ctx, il2cpp.Options{
			LibPath:      p.opts.Input,
			MetadataPath: metadataPath,
			Verbose:      p.opts.Verbose,
			IndexOnly:    true,
		})
		if ierr != nil {
			return fmt.Errorf("IL2CPP metadata: %w", ierr)
		}
		p.il2cppIndex = res.Index
		fmt.Printf("IL2CPP metadata: %d methods from %s\n", res.MethodCount, metadataPath)
	}

	// IL2CPP mode: load the field-offset dump when one was given. The
	// unified pseudo-C renderer always emits explicit pointer casts;
	// register renaming remains an explicit --regs-as-vars choice.
	var offsetDB *arm64lift.OffsetDB
	if p.opts.IL2CPPOffsets != "" {
		offsetDB, err = loadIL2CPPOffsetDump(p.opts.IL2CPPOffsets)
		if err != nil {
			return err
		}
		fmt.Printf("IL2CPP offsets: %d classes loaded from %s\n", offsetDB.Count(), p.opts.IL2CPPOffsets)
	}
	baseName := filepath.Base(p.opts.Input)

	// LLVM IR mode writes every lifted function again, one LLVM define
	// per function, into a single .ll module file next to the main
	// output (combined regardless of split mode, since lifted functions
	// call each other by name and belong in one module).
	var llMod *llvm.Module
	var llFile *atomicfile.File
	if p.opts.EmitLLVM {
		llPath := filepath.Join(p.opts.Output, baseName+".decompiled.ll")
		llFile, err = atomicfile.Create(llPath, 0o644)
		if err != nil {
			return fmt.Errorf("create LLVM output file: %w", err)
		}
		defer llFile.Abort()
		llMod = llvm.NewModule(llFile)
		llMod.EmitHeader(baseName, p.opts.Input)
	}

	// Split-function mode writes every function to its own file inside
	// <basename>_decompiled/ plus a functions.json index. The classic mode
	// keeps the whole binary in a single .decompiled.c file.
	var splitDir string
	var f *atomicfile.File
	var metas []functionMeta
	if p.opts.SplitFunctions {
		splitDir = filepath.Join(p.opts.Output, baseName+"_decompiled")
		if err := os.MkdirAll(splitDir, 0o755); err != nil {
			return fmt.Errorf("creating split output directory: %w", err)
		}
	} else {
		outPath := filepath.Join(p.opts.Output, baseName+".decompiled.c")
		f, err = atomicfile.Create(outPath, 0o644)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Abort()
	}

	// Reconstruct the original load image so absolute addresses in the
	// lifted code can index real data instead of unmapped host memory.
	imageDir := p.opts.Output
	if p.opts.SplitFunctions {
		imageDir = splitDir
	}
	if ierr := writeTLSSupport(imageDir); ierr != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot write TLS support file: %v\n", ierr)
	}
	p.elfImageBase, p.elfImageSize = 0, 0
	if imgBase, imgSize, ierr := writeELFImage(elf, imageDir); ierr != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot write ELF image: %v\n", ierr)
	} else if imgSize > 0 {
		p.elfImageBase, p.elfImageSize = imgBase, imgSize
		fmt.Printf("Reconstructed %d MiB load image (base 0x%x) for absolute addresses\n", imgSize>>20, imgBase)
	}

	// The unified pseudo-C mode is a self-contained translation unit:
	// fixed-width integer includes plus one function definition per
	// lifted symbol. No IL2CPP class header is generated.
	if f != nil {
		if p.elfImageSize > 0 {
			arm64lift.WriteCFilePreambleWithImage(f, baseName, p.elfImageBase, p.elfImageSize)
		} else {
			arm64lift.WriteCFilePreamble(f, baseName)
		}
	}

	candidates := functionCandidatesFromSymbols(elf)
	if p.dwarf != nil {
		candidates = mergeDWARFCandidates(candidates, p.dwarf)
	}
	fromUnwindFallback := false
	if len(candidates) == 0 {
		// No usable function symbol anywhere (neither .symtab nor
		// .dynsym has one - a stripped EXECUTABLE, most likely, since a
		// stripped shared library's own exports normally survive in
		// .dynsym regardless - see ELFParser.SymbolResolver's own doc
		// comment). Fall back to .eh_frame_hdr's own unwind-table
		// function boundaries (see ELFParser.DiscoverFunctions' own doc
		// comment for why that still works even here), naming each one
		// "sub_<address>" - there's no real name to recover, only
		// where it starts and how big it is.
		if discovered, discErr := elf.DiscoverFunctionsContext(ctx); discErr == nil {
			var discoveredCandidates []funcCandidate
			discoveredCandidates, resolver = withDiscoveredFunctions(discovered, resolver)
			candidates = append(candidates, discoveredCandidates...)
			fromUnwindFallback = true
			fmt.Printf("No symbol table found - recovered %d function boundaries from .eh_frame_hdr instead\n", len(candidates))
		} else {
			fmt.Printf("warning: no function symbols and no .eh_frame_hdr fallback available (%v) - nothing to decompile\n", discErr)
		}
	}

	// .eh_frame gap sizes are coarse when a binary contains functions
	// without unwind entries. Split those gaps at direct call targets,
	// prologue-shaped entries and writable relative-pointer targets.
	if fromUnwindFallback {
		var split int
		candidates, resolver, split = splitCoarseFunctions(ctx, candidates, elf, d, resolver)
		if split > 0 {
			fmt.Printf("Split coarse unwind gaps - recovered %d additional functions (%d total)\n", split, len(candidates))
		}
	}

	// Jump-table case bodies and similar compiler-outlined entries read
	// callee-saved registers set by their dispatcher. Identify them before
	// lifting so callers can save that context and the entries can reload
	// it instead of starting from zero.
	p.outlinedContexts = computeOutlinedContexts(candidates, elf, d)
	if n := len(p.outlinedContexts); n > 0 {
		fmt.Printf("Recovered caller context for %d outlined blocks\n", n)
	}

	// Function-pointer references (initializers, atexit handlers, vtables
	// passed by address) must resolve to lifted/imported C symbols rather
	// than a pointer into the original code bytes.
	knownStarts := make(map[uint64]bool, len(candidates))
	for _, c := range candidates {
		knownStarts[c.addr] = true
	}
	p.knownFunction = func(addr uint64) bool { return knownStarts[addr] }

	p.functionPtr = nil
	funcNames := make(map[uint64]string, len(candidates))
	for _, c := range candidates {
		if name := arm64lift.FunctionCName(c.name); isCIdent(name) {
			funcNames[c.addr] = name
		}
	}
	baseResolver := resolver
	p.functionPtr = func(addr uint64) (string, bool) {
		if name, ok := funcNames[addr]; ok {
			return name, true
		}
		if p.codeContains == nil || !p.codeContains(addr) {
			return "", false
		}
		raw, ok := baseResolver(addr)
		if !ok || raw == "" || strings.HasPrefix(raw, "sub_") || strings.HasPrefix(raw, "func_") {
			return "", false
		}
		name := arm64lift.ExternalCName(raw)
		if !isCIdent(name) {
			return "", false
		}
		return name, true
	}

	// Apply the original image's relative relocations so data pointers in
	// the blob (vtables, init_array, string tables) become host pointers,
	// and function pointers become addresses of lifted sub_* functions.
	if p.elfImageSize > 0 {
		if n, rerr := writeImageRelocations(ctx, elf, imageDir, p.elfImageBase, p.elfImageSize, candidates); rerr != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot write image relocations: %v\n", rerr)
		} else if n > 0 {
			fmt.Printf("Applied %d relative relocations to the load image\n", n)
		}
	}

	// Optional cross-reference pre-pass: discover callers/callees before
	// emitting output so each function can carry XREF comments.
	var xrefs map[uint64]*functionXrefs
	if p.opts.CrossReferences {
		xrefs = computeCrossReferences(candidates, elf, d, resolver)
	}

	var ok, empty, failed int
	p.condMiss = make(map[string]int)
	p.condMissSamples = nil
	lastReport := time.Now()
	for _, c := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		liftOpts := p.liftOptionsFor(c)
		code, codeOK := readFunctionCode(c, elf)
		if !codeOK {
			continue
		}
		insns, err := d.DisassembleDetailed(code, c.addr)
		if err != nil || len(insns) == 0 {
			continue
		}

		if p.opts.SplitFunctions {
			meta := p.writeSplitFunction(splitDir, c, insns, resolver, strResolver, dataReader, xrefs[c.addr], llMod, liftOpts, offsetDB)
			if meta.Success {
				if meta.Empty {
					empty++
				} else {
					ok++
				}
			} else {
				failed++
			}
			metas = append(metas, functionMeta{
				Address: fmt.Sprintf("0x%x", c.addr),
				Name:    c.name,
				Size:    c.size,
				Success: meta.Success,
				Source:  c.source(),
			})
		} else {
			func() {
				defer func() {
					if r := recover(); r != nil {
						failed++
						fmt.Fprintf(f, "// %s\n// [failed to decompile: %v]\n\n", arm64lift.Demangle(c.name), r)
					}
				}()
				stmts := arm64lift.LiftFunctionWithOptions(insns, c.params, resolver, strResolver, dataReader, liftOpts)
				if len(stmts) == 0 {
					empty++
				} else {
					ok++
				}
				if p.opts.EmitLLVM && llMod != nil {
					func() {
						defer func() {
							// The emitter only formats already-lifted IR,
							// but a malformed node must never kill the
							// whole run - report inline like a lift panic.
							if r := recover(); r != nil {
								fmt.Fprintf(os.Stderr, "warning: LLVM export of %s failed: %v\n", c.name, r)
							}
						}()
						llMod.EmitFunction(arm64lift.Demangle(c.name), stmts)
					}()
				}
				// The LLVM export consumes the plain lifted IR; the
				// unified pseudo-C renderer applies its own C spellings
				// at print time and never mutates the IR.
				fmt.Fprintf(f, "// %s\n", arm64lift.Demangle(c.name))
				if p.opts.SourceLocations {
					writeFunctionLocation(f, c, insns)
				}
				writeXrefComments(f, xrefs[c.addr])
				arm64lift.RenderCFunctionWithOptions(f, c.name, stmts, arm64lift.CRenderOptions{
					Offsets:             offsetDB,
					OffsetComments:      offsetDB != nil,
					SimplifyVTableCalls: true,
					ReduceGotos:         true,
					CharConstants:       true,
					AddressComments:     true,
					LocalTypes:          liftOpts.LocalTypes,
					ParamNames:          c.params,
					ParamTypes:          c.paramTypes,
					ReturnType:          c.returnType,
					ImageBase:           p.elfImageBase,
					HasImage:            p.elfImageSize > 0,
					FunctionPtr:         p.functionPtr,
				})
				fmt.Fprintln(f)
			}()
		}

		if p.opts.Verbose {
			fmt.Printf("  [%d/%d/%d ok/empty/failed] %s\n", ok, empty, failed, c.name)
		} else if time.Since(lastReport) > time.Second {
			fmt.Printf("  ... %d functions decompiled\n", ok+empty+failed)
			lastReport = time.Now()
		}
	}

	if p.opts.SplitFunctions {
		jsonPath := filepath.Join(splitDir, "functions.json")
		data, err := json.MarshalIndent(metas, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write functions.json: %v\n", err)
		} else if err := atomicfile.WriteFile(jsonPath, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write functions.json: %v\n", err)
		}
		if p.opts.CrossReferences {
			xrefsPath := filepath.Join(splitDir, "xrefs.json")
			if err := writeXrefsJSON(xrefsPath, xrefs); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to write xrefs.json: %v\n", err)
			}
		}
		fmt.Printf("Decompiled %d functions (%d empty, %d failed) to %s/\n", ok, empty, failed, splitDir)
		if p.opts.EmitLLVM {
			fmt.Printf("LLVM IR: %s\n", filepath.Join(p.opts.Output, baseName+".decompiled.ll"))
		}
	} else {
		if p.opts.CrossReferences {
			xrefsPath := filepath.Join(p.opts.Output, baseName+".xrefs.json")
			if err := writeXrefsJSON(xrefsPath, xrefs); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to write xrefs.json: %v\n", err)
			}
		}
		fmt.Printf("Decompiled %d functions (%d empty, %d failed) to %s\n", ok, empty, failed, filepath.Join(p.opts.Output, baseName+".decompiled.c"))
		if p.opts.EmitLLVM {
			fmt.Printf("LLVM IR: %s\n", filepath.Join(p.opts.Output, baseName+".decompiled.ll"))
		}
	}
	p.printCondMiss()
	if f != nil {
		if err := f.Commit(); err != nil {
			return fmt.Errorf("write decompiled output: %w", err)
		}
	}
	if llMod != nil {
		if err := llMod.Finish(); err != nil {
			return fmt.Errorf("finish LLVM output: %w", err)
		}
		if err := llFile.Commit(); err != nil {
			return fmt.Errorf("write LLVM output: %w", err)
		}
	}
	return nil
}

// funcCandidate is one function decompileELFArm64 attempts to lift -
// either a real, named symbol-table entry, or (see
// functionCandidatesFromSymbols' own caller) a synthetically-named
// boundary recovered from .eh_frame_hdr when there's no symbol table
// at all.
type funcCandidate struct {
	addr uint64
	size uint64
	name string
	// params are source parameter names recovered from DWARF (empty
	// when no debug info is available).
	params []string
	// paramTypes are the matching C parameter types (empty strings
	// default to uint64_t).
	paramTypes []string
	// returnType is the DWARF return type (empty when unknown).
	returnType string
	// sourceFile/sourceLine point at the DWARF declaration site.
	sourceFile string
	sourceLine int
}

func (c funcCandidate) source() string {
	if c.sourceFile == "" {
		return ""
	}
	if c.sourceLine > 0 {
		return fmt.Sprintf("%s:%d", c.sourceFile, c.sourceLine)
	}
	return c.sourceFile
}

// writeFunctionLocation reports only known ELF virtual addresses. Lifted
// statements can combine or reorder instructions, so a rendered C line has
// no reliable instruction address to attach to it.
func writeFunctionLocation(w io.Writer, c funcCandidate, insns []native.DetailedInstruction) {
	if src := c.sourceFile; src != "" {
		src = native.SourceName(src)
		if c.sourceLine > 0 {
			src = fmt.Sprintf("%s:%d", src, c.sourceLine)
		}
		fmt.Fprintf(w, "// Source: %s\n", src)
	}
	fmt.Fprintf(w, "// ELF function entry VA: 0x%x\n", c.addr)
	if len(insns) > 0 && insns[0].Address != c.addr {
		fmt.Fprintf(w, "// First decoded instruction VA: 0x%x\n", insns[0].Address)
	}
}

// functionMeta describes one decompiled function for functions.json.
type functionMeta struct {
	Address string `json:"address"`
	Name    string `json:"name"`
	Size    uint64 `json:"size"`
	Success bool   `json:"success"`
	Source  string `json:"source,omitempty"`
}

// splitFuncResult is the outcome of writing a single split-function file.
type splitFuncResult struct {
	Success bool
	Empty   bool
}

// functionFileName picks a filesystem-safe name for a per-function output
// file. Real symbol names are sanitized and kept together with the address
// to avoid collisions; discovered functions use the classic sub_<addr>.c form.
func functionFileName(c funcCandidate) string {
	base := "sub"
	if c.name != "" && !strings.HasPrefix(c.name, "sub_") {
		base = sanitizeFunctionName(c.name)
	}
	return fmt.Sprintf("%s_%x.c", base, c.addr)
}

// sanitizeFunctionName replaces characters that are unsafe in filenames.
func sanitizeFunctionName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "sub"
	}
	return b.String()
}

// writeSplitFunction writes one function to its own .c file inside splitDir.
// llMod is the combined LLVM module stream, or nil when --emit-llvm is off.
func (p *Pipeline) writeSplitFunction(
	splitDir string,
	c funcCandidate,
	insns []native.DetailedInstruction,
	resolver arm64lift.SymbolResolver,
	strResolver arm64lift.StringResolver,
	dataReader func(uint64, int) ([]byte, bool),
	fx *functionXrefs,
	llMod *llvm.Module,
	liftOpts arm64lift.LiftOptions,
	offsetDB *arm64lift.OffsetDB,
) splitFuncResult {
	filePath := filepath.Join(splitDir, functionFileName(c))
	outF, err := atomicfile.Create(filePath, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot create %s: %v\n", filePath, err)
		return splitFuncResult{Success: false}
	}
	defer outF.Abort()

	if p.elfImageSize > 0 {
		arm64lift.WriteCFilePreambleWithImage(outF, filepath.Base(p.opts.Input), p.elfImageBase, p.elfImageSize)
	} else {
		arm64lift.WriteCFilePreamble(outF, filepath.Base(p.opts.Input))
	}

	var result splitFuncResult
	func() {
		defer func() {
			if r := recover(); r != nil {
				result = splitFuncResult{Success: false}
				fmt.Fprintf(outF, "// %s\n// [failed to decompile: %v]\n\n", arm64lift.Demangle(c.name), r)
			}
		}()
		stmts := arm64lift.LiftFunctionWithOptions(insns, c.params, resolver, strResolver, dataReader, liftOpts)
		result.Empty = len(stmts) == 0
		result.Success = true
		if p.opts.EmitLLVM && llMod != nil {
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "warning: LLVM export of %s failed: %v\n", c.name, r)
					}
				}()
				llMod.EmitFunction(arm64lift.Demangle(c.name), stmts)
			}()
		}
		fmt.Fprintf(outF, "// %s\n", arm64lift.Demangle(c.name))
		if p.opts.SourceLocations {
			writeFunctionLocation(outF, c, insns)
		}
		writeXrefComments(outF, fx)
		arm64lift.RenderCFunctionWithOptions(outF, c.name, stmts, arm64lift.CRenderOptions{
			Offsets:             offsetDB,
			OffsetComments:      offsetDB != nil,
			SimplifyVTableCalls: true,
			ReduceGotos:         true,
			CharConstants:       true,
			AddressComments:     true,
			LocalTypes:          liftOpts.LocalTypes,
			ParamNames:          c.params,
			ParamTypes:          c.paramTypes,
			ReturnType:          c.returnType,
			ImageBase:           p.elfImageBase,
			HasImage:            p.elfImageSize > 0,
			FunctionPtr:         p.functionPtr,
		})
		fmt.Fprintln(outF)
	}()

	if err := outF.Commit(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot write %s: %v\n", filePath, err)
		return splitFuncResult{Success: false}
	}

	return result
}

// dwarfDebugInfo adapts one DWARF function to arm64lift.DebugInfo.
type dwarfDebugInfo struct {
	fn *native.DWARFFunction
}

func (d dwarfDebugInfo) LocalAt(off int64) (string, string, bool) {
	if d.fn == nil {
		return "", "", false
	}
	return d.fn.LocalAt(off)
}

func (p *Pipeline) noteCondMiss(fn, instr uint64, op string) {
	if op == "" {
		op = "?"
	}
	p.condMiss[op]++
	if len(p.condMissSamples) < 16 {
		p.condMissSamples = append(p.condMissSamples, fmt.Sprintf("%s at 0x%x (fn 0x%x)", op, instr, fn))
	}
}

func (p *Pipeline) printCondMiss() {
	total := 0
	for _, n := range p.condMiss {
		total += n
	}
	if total == 0 {
		return
	}
	keys := make([]string, 0, len(p.condMiss))
	for op := range p.condMiss {
		keys = append(keys, op)
	}
	sort.Slice(keys, func(i, j int) bool { return p.condMiss[keys[i]] > p.condMiss[keys[j]] })
	parts := make([]string, 0, len(keys))
	for _, op := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", op, p.condMiss[op]))
	}
	fmt.Printf("Unresolved conditions: %d (%s)\n", total, strings.Join(parts, ", "))
	if len(p.condMissSamples) > 0 {
		fmt.Printf("  first misses: %s\n", strings.Join(p.condMissSamples, "; "))
	}
}

// liftOptionsFor builds the per-function lift options, including the
// DWARF local-name provider and the map the renderer reads type
// declarations from.
func (p *Pipeline) liftOptionsFor(c funcCandidate) arm64lift.LiftOptions {
	opts := arm64lift.LiftOptions{
		Simplify:               p.opts.SimplifyCFG,
		RegsAsVars:             p.opts.RegsAsVars,
		LocalTypes:             make(map[string]string),
		ReturnType:             c.returnType,
		CodeContains:           p.codeContains,
		KnownFunction:          p.knownFunction,
		OutlinedContextRegs:    p.outlinedContexts[c.addr],
		OutlinedContextTargets: p.outlinedContexts,
		CondMiss: func(op string, addr uint64) {
			p.noteCondMiss(c.addr, addr, op)
		},
	}
	if p.dwarf != nil {
		if fn, ok := p.dwarf.FunctionAt(c.addr); ok {
			opts.Debug = dwarfDebugInfo{fn: fn}
		}
	}
	if p.il2cppIndex != nil {
		opts.Metadata = p.il2cppIndex
	}
	return opts
}

// findIL2CPPMetadata auto-detects the conventional metadata file next
// to a libil2cpp.so.
func findIL2CPPMetadata(input string) string {
	if !strings.EqualFold(filepath.Base(input), "libil2cpp.so") {
		return ""
	}
	path := filepath.Join(filepath.Dir(input), "global-metadata.dat")
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

// mergeDWARFCandidates enriches symbol-derived candidates with DWARF
// parameter/source information and adds DWARF-only functions (static
// helpers, stripped binaries without a usable symbol table).
func mergeDWARFCandidates(candidates []funcCandidate, info *native.DWARFInfo) []funcCandidate {
	byAddr := make(map[uint64]int, len(candidates))
	for i := range candidates {
		byAddr[candidates[i].addr] = i
	}

	for _, fn := range info.Functions {
		if fn.HighPC <= fn.LowPC {
			continue
		}
		params := make([]string, 0, len(fn.Params))
		paramTypes := make([]string, 0, len(fn.Params))
		for _, p := range fn.Params {
			params = append(params, p.Name)
			paramTypes = append(paramTypes, p.Type)
		}
		if idx, ok := byAddr[fn.LowPC]; ok {
			c := &candidates[idx]
			if c.name == "" || strings.HasPrefix(c.name, "sub_") {
				c.name = fn.Name
			}
			if len(c.params) == 0 {
				c.params = params
				c.paramTypes = paramTypes
				c.returnType = fn.ReturnType
			}
			if c.sourceFile == "" {
				c.sourceFile = fn.DeclFile
				c.sourceLine = fn.DeclLine
			}
			continue
		}
		candidates = append(candidates, funcCandidate{
			addr:       fn.LowPC,
			size:       fn.HighPC - fn.LowPC,
			name:       fn.Name,
			params:     params,
			paramTypes: paramTypes,
			returnType: fn.ReturnType,
			sourceFile: fn.DeclFile,
			sourceLine: fn.DeclLine,
		})
		byAddr[fn.LowPC] = len(candidates) - 1
	}

	// Enrich symbol candidates whose DWARF range starts elsewhere but
	// still contains the symbol address (aliases, function sections).
	for i := range candidates {
		c := &candidates[i]
		if c.sourceFile != "" && len(c.params) > 0 {
			continue
		}
		if fn, ok := info.FunctionAt(c.addr); ok {
			if len(c.params) == 0 {
				for _, p := range fn.Params {
					c.params = append(c.params, p.Name)
					c.paramTypes = append(c.paramTypes, p.Type)
				}
				c.returnType = fn.ReturnType
			}
			if c.sourceFile == "" {
				c.sourceFile = fn.DeclFile
				c.sourceLine = fn.DeclLine
			}
			if c.name == "" || strings.HasPrefix(c.name, "sub_") {
				c.name = fn.Name
			}
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].addr < candidates[j].addr })
	return candidates
}

// functionCandidatesFromSymbols builds the ordinary, name-bearing
// candidate list from elf.Symbols (.symtab, or .dynsym when that's all
// a stripped binary has left - see ELFParser.SymbolResolver's own doc
// comment). Symbols with a zero size get a size estimated from the
// distance to the next function symbol, which dramatically improves
// candidate discovery for stripped shared libraries whose .dynsym
// exports real function addresses but leaves their sizes at 0.
func functionCandidatesFromSymbols(elf *native.ELFParser) []funcCandidate {
	const sttFunc = 2

	// Collect function symbol addresses in sorted order for size estimation.
	funcAddrs := make([]uint64, 0, len(elf.Symbols))
	for _, sym := range elf.Symbols {
		if sym.Info&0xf == sttFunc && sym.Value != 0 {
			funcAddrs = append(funcAddrs, sym.Value)
		}
	}
	sort.Slice(funcAddrs, func(i, j int) bool { return funcAddrs[i] < funcAddrs[j] })

	var candidates []funcCandidate
	for _, sym := range elf.Symbols {
		if sym.Info&0xf != sttFunc {
			continue
		}
		name := elf.GetSymbolName(sym)
		if name == "" || sym.Value == 0 {
			continue
		}
		size := sym.Size
		if size == 0 {
			size = estimateSymbolSize(sym.Value, funcAddrs)
		}
		if size == 0 {
			continue
		}
		candidates = append(candidates, funcCandidate{addr: sym.Value, size: size, name: name})
	}
	return candidates
}

// estimateSymbolSize returns the distance from addr to the next known
// function address, capped by a sane maximum. This is the standard
// fallback for dynamic symbol tables that list exports without sizes.
func estimateSymbolSize(addr uint64, sortedAddrs []uint64) uint64 {
	for _, next := range sortedAddrs {
		if next > addr {
			return next - addr
		}
	}
	return 0
}

// withDiscoveredFunctions builds the candidate list for functions
// found only through .eh_frame_hdr (see ELFParser.DiscoverFunctions'
// own doc comment - no real name to recover, only where each one
// starts and how big it is), named "sub_<address>", and wraps base
// (the ordinary symbol-based resolver) so a CALL from one of these
// discovered-but-unnamed functions to another one also resolves to
// that same "sub_<address>" name instead of falling through to
// buildCall's own generic "func_<address>" placeholder (see its own
// doc comment) - two different placeholder spellings for the identical
// "no real name" situation otherwise, depending only on whether an
// address is being decompiled as its OWN top-level entry or merely
// called FROM another one. base is always tried first, so a real
// symbol (should one somehow exist at the same address as a discovered
// one) still wins.
func withDiscoveredFunctions(discovered []native.DiscoveredFunction, base func(uint64) (string, bool)) ([]funcCandidate, func(uint64) (string, bool)) {
	candidates := make([]funcCandidate, 0, len(discovered))
	names := make(map[uint64]string, len(discovered))
	for _, fn := range discovered {
		name := fmt.Sprintf("sub_%x", fn.Addr)
		candidates = append(candidates, funcCandidate{addr: fn.Addr, size: fn.Size, name: name})
		names[fn.Addr] = name
	}
	resolver := func(addr uint64) (string, bool) {
		if name, ok := base(addr); ok {
			return name, true
		}
		name, ok := names[addr]
		return name, ok
	}
	return candidates, resolver
}
