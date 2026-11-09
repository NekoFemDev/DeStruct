package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/destruct/destruct/internal/arm64lift"
	"github.com/destruct/destruct/internal/hermes"
	"github.com/destruct/destruct/internal/hermes/asm"
	"github.com/destruct/destruct/internal/hermes/disasm"
	"github.com/destruct/destruct/internal/hermes/parser"
	"github.com/destruct/destruct/internal/il2cpp"
	"github.com/destruct/destruct/internal/js"
	"github.com/destruct/destruct/internal/pipeline"
)

const version = "1.0.0-beta.3"

func main() {
	// Cancel in-flight work on Ctrl-C (SIGINT) or SIGTERM. Long-running
	// pipeline operations poll this context at their natural boundaries
	// (per archive entry / per function), so the process stops promptly
	// instead of finishing the whole input first.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		if errors.Is(err, errUsage) {
			// Usage errors have already printed their message.
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// errUsage marks a usage error whose message has already been printed by
// printUsage; main exits non-zero without printing it again.
var errUsage = errors.New("invalid usage")

// run dispatches a single CLI invocation. Command handlers return errors
// instead of terminating the process, which keeps them testable. ctx is the
// signal-cancelled context from main; handlers that run long operations
// thread it into the work and check it at their boundaries.
func run(ctx context.Context, args []string) error {
	if len(args) < 1 {
		printUsage()
		return errUsage
	}

	switch cmd := args[0]; cmd {
	case "jvm":
		return handleJVM(ctx, args[1:])
	case "dex":
		return handleDex(ctx, args[1:])
	case "apk":
		return handleAPK(ctx, args[1:])
	case "hermes":
		return handleHermes(ctx, args[1:])
	case "js":
		return handleJS(args[1:])
	case "assemble":
		return handleAssemble(args[1:])
	case "interactive", "repl":
		return handleInteractive(args[1:])
	case "hex":
		return handleHex(ctx, args[1:])
	case "flutter":
		return handleFlutter(ctx, args[1:])
	case "elf":
		return handleELF(ctx, args[1:])
	case "il2cpp":
		return handleIL2CPP(ctx, args[1:])
	case "pe":
		return handlePE(ctx, args[1:])
	case "version":
		fmt.Printf("DeStruct v%s\n", version)
		return nil
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

func printUsage() {
	fmt.Println(`DeStruct - Multi-format Decompiler
Usage: destruct <command> [options]

Commands:
  jvm         Decompile JVM .class/.jar files to Java source code
  dex         Decompile Android .dex/.apk files to Java source code
  apk         Rebuild (build) or align/sign (sign) an APK
  hermes      Disassemble Hermes .hbc bytecode (hermes-dec exact format)
  js          Deobfuscate/beautify a JavaScript file (AST-based, tdewolff parser)
  assemble    Assemble an edited .hasm back into a patched .hbc
  interactive, repl
              Interactive Hermes patching session (seek/hexdump/disasm/write)
  hex         Interactive hex editor with staged patching (mapped read-only;
               ELF disasm/decompile; -c for one-shot scripting)
  flutter     Disassemble Flutter libapp.so to readable Dart bytecode
  elf         Disassemble ELF binaries to readable assembly (--decompile: AArch64-only pseudo-C)
  elf recompile <decompiled_dir> -o <binary>
              Generate link stubs and recompile all .c files into a dummy
              executable with clang
  il2cpp      Dump Unity IL2CPP metadata (global-metadata.dat + libil2cpp.so) to dump.cs
  pe          Disassemble PE binaries to readable assembly
  version     Show version
  help        Show this help

Options:
  -o, --output          Output file/directory
  -i, --input           Original .hbc/.bundle (required for assemble: the
                         .hasm references that file's tables and is not
                         self-contained)
  -v, --verbose         Verbose output
  --deobfuscate         Enable deobfuscation
  --decompile           Use the decompiler (jvm/dex/flutter/elf). Hermes
                         decompilation is disabled during the refactor -
                         use the disassembly instead.
  --split-functions, -sf
                        With --decompile (ELF), write each function to a
                         separate .c file under <input>_decompiled/ and emit
                         functions.json metadata (address, name, size, success)
  --cross-references, -x
                        With --decompile (ELF), add cross-reference comments
                         (callers/callees) and emit an xrefs.json file
  --simplify-cfg        Run CFG simplification / unreachable-block removal
                         for AArch64 ELF decompilation (experimental)
  --emit-llvm           With --decompile (ELF), also export every lifted
                         function as LLVM IR to <input>.decompiled.ll
  --il2cpp-offsets <path>
                         With --decompile (ELF), load an IL2CPP field-offset
                         dump (offsets.json / offset.hpp, or a directory
                         containing one, e.g. game_dump/) so field accesses can
                         use the dump's resolved names/offsets
  --emit-pseudo         With --decompile (ELF), select the unified pseudo-C
                         output explicitly (the default). The output is a
                         syntactically valid C translation unit: declarations,
                         uintptr_t casts, normalized labels and one dummy
                         function per lifted symbol
  --regs-as-vars        With --decompile (ELF), rename register placeholders
                         to arg0..arg7 / var_N / fvar_N (default keeps x0/w0)
  --no-enhance          Disable enhanced comments when using --decompile (ELF)
  --no-location-comments Disable source-location comments when using --decompile (ELF)
  --print-options       Print the parsed configuration and exit
  --arch                With 'apk build', keep only lib/<arch>/ native
                         libraries (e.g. arm64-v8a, armeabi-v7a)
  --hermes-dec          Accepted no-op alias: the hermes-dec exact format is
                         always used for disassembly and assembly

Workflow for Hermes patching (structural edits):
  1. destruct hermes file.hbc -o output/            # hermes-dec exact .hasm
  2. Edit output/file.hbc.hasm in a text editor
  3. destruct assemble output/file.hbc.hasm -i file.hbc -o patched.hbc
     Only functions whose text actually changed are reassembled. Addresses
     are recalculated automatically; an Addr8 branch is promoted to its
     *Long form when an edit pushes its target out of byte range.

Examples:
  destruct jvm input.jar -o output/
  destruct dex classes.dex -o output/
  destruct dex app.apk -o output/
  destruct apk build decoded/ -o unsigned.apk --arch arm64-v8a
  destruct apk sign unsigned.apk -k release.jks -p "$KS_PASS" -o signed.apk
  destruct hermes index.android.bundle -o output/
  destruct assemble output/index.android.bundle.hasm -i index.android.bundle -o patched.hbc
  destruct elf libnative.so -o output/ --decompile  # AArch64 pseudocode, one file
  destruct elf libnative.so -o output/ --decompile --il2cpp-offsets game_dump/
  destruct elf libnative.so -o output/ --emit-pseudo --split-functions
  destruct elf recompile output/libnative.so_decompiled/ -o dummy
  destruct flutter libapp.so -o output/ --decompile
  destruct il2cpp libil2cpp.so global-metadata.dat -o output/
  destruct elf libnative.so -o output/
  destruct hex libil2cpp.so
  destruct hex lib.so -c "info" -c "disasm 0x1000 32"
  destruct hex lib.so -c "search \"UnityPlayer\"" -c "read 0x2000"`)
}
func handleJVM(ctx context.Context, args []string) error {
	opts, input := parseFlags(args)
	if opts.printOptions {
		return printOptionsJSON("jvm", opts)
	}
	if input == "" {
		return errors.New("input file required")
	}

	ext := strings.ToLower(filepath.Ext(input))
	if ext != ".class" && ext != ".jar" {
		return fmt.Errorf("unsupported JVM file format: %s (expected .class or .jar)", ext)
	}

	p := pipeline.New(pipeline.Options{
		Input:   input,
		Output:  opts.output,
		Format:  pipeline.FormatJVM,
		Verbose: opts.verbose,
		Deobf:   opts.deobfuscate,
		Project: opts.project,
	})

	if err := p.RunContext(ctx); err != nil {
		return err
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
	return nil
}

func handleDex(ctx context.Context, args []string) error {
	opts, input := parseFlags(args)
	if opts.printOptions {
		return printOptionsJSON("dex", opts)
	}
	if input == "" {
		return errors.New("input file required")
	}

	ext := strings.ToLower(filepath.Ext(input))
	if ext != ".dex" && ext != ".apk" {
		return fmt.Errorf("unsupported DEX file format: %s (expected .dex or .apk)", ext)
	}

	p := pipeline.New(pipeline.Options{
		Input:   input,
		Output:  opts.output,
		Format:  pipeline.FormatDEX,
		Verbose: opts.verbose,
		Deobf:   opts.deobfuscate,
		Project: opts.project,
	})

	if err := p.RunContext(ctx); err != nil {
		return err
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
	return nil
}

func handleHermes(ctx context.Context, args []string) error {
	opts, input := parseFlags(args)
	if opts.printOptions {
		return printOptionsJSON("hermes", opts)
	}
	if input == "" {
		return errors.New("input .hbc file required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := os.MkdirAll(opts.output, 0o755); err != nil {
		return err
	}

	data, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("reading %s: %w", input, err)
	}

	m, err := parser.Parse(data)
	if err != nil {
		return fmt.Errorf("parsing HBC: %w", err)
	}

	fmt.Printf("Parsed Hermes bytecode v%d (%d functions, %d strings)\n",
		m.Version, len(m.Functions), len(m.Strings))

	if opts.decompile {
		// Frozen during the internal/hermes refactor; the stub returns a
		// single explicit error (see internal/hermes/decompiler.go).
		return hermes.NewDecompiler(m).DecompileAllContext(ctx, io.Discard)
	}

	hasmPath := filepath.Join(opts.output, filepath.Base(input)+".hasm")
	f, err := os.Create(hasmPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Streaming write: real-world bundles produce 100+ MB of text, and
	// ctx is checked per function and per instruction.
	if err := disasm.WriteContext(ctx, f, m, disasm.Options{}); err != nil {
		return err
	}
	fmt.Printf("Disassembly (hermes-dec exact format): %s\n", hasmPath)

	for i := range m.Functions {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr := &m.Functions[i]
		if opts.verbose || i < 10 {
			fmt.Printf("  Function #%d: %s (%d bytes, %d params)\n",
				i, hdr.Name, hdr.BytecodeSizeInBytes, hdr.ParamCount)
		}
	}
	if len(m.Functions) > 10 && !opts.verbose {
		fmt.Printf("  ... and %d more functions (use -v for all)\n", len(m.Functions)-10)
	}
	return nil
}

// handleJS implements `destruct js <file.js>`: parse the input as
// JavaScript, run the internal/js deobfuscation pipeline (constant folding,
// IIFE unwrapping, debugger removal), and write the beautified result next
// to the input as <name>.deobf.js unless -o overrides the path.
func handleJS(args []string) error {
	opts, input := parseFlags(args)
	if opts.printOptions {
		return printOptionsJSON("js", opts)
	}
	if input == "" {
		return errors.New("input .js file required")
	}

	raw, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("reading %s: %w", input, err)
	}

	out, err := js.Deobfuscate(string(raw))
	if err != nil {
		return fmt.Errorf("deobfuscating %s: %w", input, err)
	}

	// Default output: a sibling file next to the input; -o overrides.
	outPath := opts.output
	if outPath == "output" {
		outPath = strings.TrimSuffix(input, filepath.Ext(input)) + ".deobf.js"
	}
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if err := os.WriteFile(outPath, []byte(out), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", outPath, err)
	}
	fmt.Printf("Deobfuscated: %s\n", outPath)
	return nil
}

func handleAssemble(args []string) error {
	opts, input := parseFlags(args)
	if opts.printOptions {
		return printOptionsJSON("assemble", opts)
	}
	if input == "" {
		return errors.New("input .hasm file required")
	}

	if opts.output == "output" {
		// Default: replace the .hasm extension with .hbc. When the
		// remaining name still carries the original extension (the CLI
		// disassembles file.hbc to file.hbc.hasm), insert .patched
		// instead of doubling it: file.hbc.hasm -> file.patched.hbc.
		base := strings.TrimSuffix(input, filepath.Ext(input))
		origExt := filepath.Ext(base)
		switch strings.ToLower(origExt) {
		case ".hbc", ".bundle":
			opts.output = strings.TrimSuffix(base, origExt) + ".patched" + origExt
		default:
			opts.output = base + ".hbc"
		}
	}

	// Assembly is always a patch against the original .hbc: the text
	// references that file's string/function/bigint tables and cannot be
	// assembled standalone. Only functions whose text actually changed
	// are reassembled.
	if opts.inputFile == "" {
		return errors.New("assembly requires the original .hbc/.bundle via -i/--input (the .hasm text references that file's string/function tables and cannot be assembled standalone)")
	}

	original, err := os.ReadFile(opts.inputFile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", opts.inputFile, err)
	}
	hasmData, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("reading %s: %w", input, err)
	}

	m, err := parser.Parse(original)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", opts.inputFile, err)
	}

	result, err := asm.Assemble(m, string(hasmData))
	if err != nil {
		return fmt.Errorf("assembling: %w", err)
	}
	if len(result.ChangedFunctions) == 0 {
		fmt.Println("No changes detected; output is identical to the input .hbc")
	} else {
		fmt.Printf("Patched %d function(s) (bytecode size change: %+d bytes)\n",
			len(result.ChangedFunctions), result.SizeDelta)
	}

	if err := os.WriteFile(opts.output, result.Data, 0o644); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	fmt.Printf("Wrote %s\n", opts.output)
	return nil
}

// handleInteractive opens a .hbc/.bundle file and starts a radare2-style
// interactive patching session (see internal/hermes/repl.go): seek,
// hexdump, disassemble, and write commands operating on an in-memory
// buffer with explicit save via 'w'/'wq'.
func handleInteractive(args []string) error {
	_, input := parseFlags(args)
	if input == "" {
		return errors.New("input .hbc/.bundle file required")
	}

	data, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("reading %s: %w", input, err)
	}

	r, err := hermes.NewRepl(data, input, os.Stdout)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", input, err)
	}
	if err := r.Run(os.Stdin); err != nil {
		return err
	}
	return nil
}

func handleFlutter(ctx context.Context, args []string) error {
	opts, input := parseFlags(args)
	if opts.printOptions {
		return printOptionsJSON("flutter", opts)
	}
	if input == "" {
		return errors.New("input file required")
	}

	ext := strings.ToLower(filepath.Ext(input))
	if ext != ".so" && ext != ".apk" {
		return fmt.Errorf("unsupported Flutter file format: %s (expected .so or .apk)", ext)
	}

	if _, err := os.Stat(input); err != nil {
		return fmt.Errorf("cannot read %s: %w", input, err)
	}

	p := pipeline.New(pipeline.Options{
		Input:   input,
		Output:  opts.output,
		Format:  pipeline.FormatFlutter,
		Verbose: opts.verbose,
		Deobf:   opts.deobfuscate,
		Project: opts.project,
	})

	if err := p.RunContext(ctx); err != nil {
		return err
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
	return nil
}

func handleELF(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "recompile" {
		return handleELFRecompile(ctx, args[1:])
	}
	opts, input := parseFlags(args)
	if input == "" {
		return errors.New("input file required")
	}

	// --cross-references implies --decompile for ELF, since it needs the
	// decompilation pass to analyse function bodies.
	if opts.crossReferences {
		opts.decompile = true
	}

	// --emit-llvm implies --decompile for ELF, since the LLVM exporter
	// consumes the lifted IR.
	if opts.emitLLVM {
		opts.decompile = true
	}

	// The IL2CPP output mode only exists for the AArch64 decompiler;
	// --emit-pseudo is the single, unified rendering mode.
	if opts.emitPseudo {
		opts.decompile = true
	}
	if opts.il2cppOffsets != "" || opts.regsAsVars {
		opts.decompile = true
	}

	// --decompile automatically enables enhancement output; use
	// --no-enhance / --no-location-comments to opt out.
	enhance := opts.decompile && !opts.noEnhance
	sourceLocations := opts.decompile && !opts.noLocationComments

	if opts.printOptions {
		return printOptionsJSON("elf", opts)
	}

	p := pipeline.New(pipeline.Options{
		Input:           input,
		Output:          opts.output,
		Format:          pipeline.FormatELF,
		Verbose:         opts.verbose,
		Deobf:           opts.deobfuscate,
		Project:         opts.project,
		Decompile:       opts.decompile,
		EnhanceComments: enhance,
		SourceLocations: sourceLocations,
		SplitFunctions:  opts.splitFunctions,
		CrossReferences: opts.crossReferences,
		SimplifyCFG:     opts.simplifyCfg,
		EmitLLVM:        opts.emitLLVM,
		IL2CPPOffsets:   opts.il2cppOffsets,
		EmitPseudo:      opts.emitPseudo,
		RegsAsVars:      opts.regsAsVars,
	})

	if err := p.RunContext(ctx); err != nil {
		return err
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
	return nil
}

// handleELFRecompile implements:
//
//	destruct elf recompile <decompiled_dir> -o <output_binary>
//
// It generates stubs.c for every unresolved extern in the decompiled
// directory, then invokes clang on every .c file in that directory
// (including stubs.c) to produce a dummy executable.
func handleELFRecompile(ctx context.Context, args []string) error {
	var dir, output string
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; arg {
		case "-o", "--output":
			if i+1 >= len(args) {
				return errors.New("missing value for -o/--output")
			}
			i++
			output = args[i]
		case "-h", "--help":
			fmt.Println(`Usage: destruct elf recompile <decompiled_dir> -o <output_binary>

Generates <decompiled_dir>/stubs.c and links every .c file in the
directory into a dummy executable with:

  clang -std=c11 -w -o <output_binary> <all .c files>`)
			return nil
		default:
			if strings.HasPrefix(arg, "-") {
				return fmt.Errorf("unknown option: %s", arg)
			}
			if dir != "" {
				return errors.New("exactly one decompiled directory is required")
			}
			dir = arg
		}
	}
	if dir == "" {
		return errors.New("usage: destruct elf recompile <decompiled_dir> -o <output_binary>")
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve decompiled directory: %w", err)
	}
	info, err := os.Stat(absDir)
	if err != nil {
		return fmt.Errorf("stat decompiled directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", absDir)
	}

	if output == "" {
		output = filepath.Join(absDir, "decompiled_dummy")
	}
	absOut, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output binary: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absOut), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	stubsPath := filepath.Join(absDir, "stubs.c")
	fmt.Printf("Generating link stubs: %s\n", stubsPath)
	stubInfo, err := arm64lift.GenerateLinkStubsDir(absDir, stubsPath)
	if err != nil {
		return fmt.Errorf("generate link stubs: %w", err)
	}
	fmt.Printf("Stubs: %d libc wrappers, %d generic functions, %d variables, main=%v\n",
		len(stubInfo.LibcWrappers), len(stubInfo.GenericFunctions),
		len(stubInfo.Variables), stubInfo.AddedMain)

	files, err := collectCFiles(absDir, absOut)
	if err != nil {
		return fmt.Errorf("collect .c files: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no .c files found in %s", absDir)
	}

	clangPath, err := exec.LookPath("clang")
	if err != nil {
		return fmt.Errorf("clang not found in PATH: %w", err)
	}
	clangArgs := make([]string, 0, len(files)+4)
	clangArgs = append(clangArgs, "-std=c11", "-w", "-o", absOut)
	clangArgs = append(clangArgs, files...)

	fmt.Printf("Compiling %d C files with %s...\n", len(files), clangPath)
	cmd := exec.CommandContext(ctx, clangPath, clangArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("clang failed: %w", err)
	}

	fmt.Printf("Successfully compiled dummy executable: %s\n", absOut)
	return nil
}

// collectCFiles returns every .c file under dir, sorted for deterministic
// clang invocations. exclude (the output binary, when it happens to live
// in the same directory) is skipped.
func collectCFiles(dir, exclude string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".c") {
			absPath, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			if absPath == exclude {
				return nil
			}
			files = append(files, absPath)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// handleIL2CPP implements `destruct il2cpp`, which dumps both a Unity
// global-metadata.dat and the matching libil2cpp.so into dump.cs.
//
// Usage: destruct il2cpp <libil2cpp.so> <global-metadata.dat> [-o output/]
// The two positional arguments may be given in either order; they are
// detected from their magic numbers.
func handleIL2CPP(ctx context.Context, args []string) error {
	output := "output"
	verbose := false
	printOptions := false
	var positionals []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o", "--output":
			if i+1 < len(args) {
				i++
				output = args[i]
			}
		case "-v", "--verbose":
			verbose = true
		case "--print-options":
			printOptions = true
		default:
			if !strings.HasPrefix(args[i], "-") {
				positionals = append(positionals, args[i])
			}
		}
	}

	if printOptions {
		cfg := map[string]interface{}{
			"command": "il2cpp",
			"output":  output,
			"verbose": verbose,
		}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	if len(positionals) < 2 {
		return errors.New("both libil2cpp.so and global-metadata.dat are required\nUsage: destruct il2cpp <libil2cpp.so> <global-metadata.dat> [-o output/]")
	}
	lib, meta := positionals[0], positionals[1]
	if looksLikeMetadata(lib) && looksLikeELF(meta) {
		lib, meta = meta, lib
	}

	// RunContext threads ctx through the metadata parse, registration
	// search, init and per-type dump loops, so an in-flight dump aborts at
	// the next boundary.
	result, err := il2cpp.RunContext(ctx, il2cpp.Options{
		LibPath:      lib,
		MetadataPath: meta,
		OutputDir:    output,
		Verbose:      verbose,
	})
	if err != nil {
		return err
	}

	fmt.Printf("IL2CPP dump complete. Metadata v%.1f, IL2CPP %.1f\n", result.MetadataVersion, result.IL2CPPVersion)
	fmt.Printf("Images: %d, TypeDefs: %d, Methods: %d\n", result.ImageCount, result.TypeDefCount, result.MethodCount)
	fmt.Printf("CodeRegistration: 0x%X, MetadataRegistration: 0x%X\n", result.CodeRegistration, result.MetadataRegistration)
	fmt.Printf("Output: %s/dump.cs\n", output)
	return nil
}

func looksLikeMetadata(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false
	}
	return magic[0] == 0xAF && magic[1] == 0x1B && magic[2] == 0xB1 && magic[3] == 0xFA
}

func looksLikeELF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false
	}
	return string(magic[:]) == "\x7fELF"
}

func handlePE(ctx context.Context, args []string) error {
	opts, input := parseFlags(args)
	if opts.printOptions {
		return printOptionsJSON("pe", opts)
	}
	if input == "" {
		return errors.New("input file required")
	}

	p := pipeline.New(pipeline.Options{
		Input:   input,
		Output:  opts.output,
		Format:  pipeline.FormatPE,
		Verbose: opts.verbose,
		Deobf:   opts.deobfuscate,
		Project: opts.project,
	})

	if err := p.RunContext(ctx); err != nil {
		return err
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
	return nil
}

func cliOptionsMap(opts cliOpts) map[string]interface{} {
	return map[string]interface{}{
		"output":             opts.output,
		"verbose":            opts.verbose,
		"deobfuscate":        opts.deobfuscate,
		"project":            opts.project,
		"decompile":          opts.decompile,
		"hermesDec":          opts.hermesDec,
		"inputFile":          opts.inputFile,
		"printOptions":       opts.printOptions,
		"noEnhance":          opts.noEnhance,
		"noLocationComments": opts.noLocationComments,
		"splitFunctions":     opts.splitFunctions,
		"crossReferences":    opts.crossReferences,
		"simplifyCfg":        opts.simplifyCfg,
		"emitLLVM":           opts.emitLLVM,
		"il2cppOffsets":      opts.il2cppOffsets,
		"emitPseudo":         opts.emitPseudo,
		"regsAsVars":         opts.regsAsVars,
	}
}

func printOptionsJSON(command string, opts cliOpts) error {
	cfg := cliOptionsMap(opts)
	cfg["command"] = command
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

type cliOpts struct {
	output             string
	verbose            bool
	deobfuscate        bool
	project            bool
	decompile          bool
	hermesDec          bool
	inputFile          string
	printOptions       bool
	noEnhance          bool
	noLocationComments bool
	splitFunctions     bool
	crossReferences    bool
	simplifyCfg        bool
	emitLLVM           bool
	il2cppOffsets      string
	emitPseudo         bool
	regsAsVars         bool
}

func parseFlags(args []string) (cliOpts, string) {
	opts := cliOpts{
		output:  "output",
		project: true,
	}
	var input string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-o", "--output":
			if i+1 < len(args) {
				i++
				opts.output = args[i]
			}
		case "-i", "--input":
			if i+1 < len(args) {
				i++
				opts.inputFile = args[i]
			}
		case "-v", "--verbose":
			opts.verbose = true
		case "--deobfuscate":
			opts.deobfuscate = true
		case "--decompile":
			opts.decompile = true
		case "--hermes-dec":
			// Accepted no-op alias: the hermes-dec exact format is
			// always used.
			opts.hermesDec = true
		case "--print-options":
			opts.printOptions = true
		case "--no-enhance":
			opts.noEnhance = true
		case "--no-location-comments":
			opts.noLocationComments = true
		case "--split-functions", "-sf":
			opts.splitFunctions = true
		case "--cross-references", "-x":
			opts.crossReferences = true
		case "--simplify-cfg":
			opts.simplifyCfg = true
		case "--emit-llvm":
			opts.emitLLVM = true
		case "--il2cpp-offsets":
			if i+1 < len(args) {
				i++
				opts.il2cppOffsets = args[i]
			}
		case "--emit-pseudo":
			opts.emitPseudo = true
		case "--regs-as-vars":
			opts.regsAsVars = true
		case "--no-project":
			opts.project = false
		default:
			if !strings.HasPrefix(arg, "-") {
				input = arg
			}
		}
	}

	return opts, input
}
