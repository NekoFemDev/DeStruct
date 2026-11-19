package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

const version = "1.0.0-beta.4"

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
	case "version", "--version", "-V":
		fmt.Printf("DeStruct v%s\n", version)
		return nil
	case "help", "--help", "-h":
		if len(args) > 1 {
			printCommandHelp(args[1])
			return nil
		}
		printUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "destruct: unknown command: %s\n", cmd)
		printUsage()
		return errUsage
	}
}

func printUsage() {
	fmt.Println(`DeStruct - Multi-format Decompiler & Reverse-Engineering Toolkit
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
  flutter     Disassemble Flutter libapp.so to readable ARM64 assembly
  elf         Disassemble ELF binaries to readable assembly (--decompile: AArch64-only pseudo-C)
  elf info <file>
              Print ELF header, sections, symbols, dependencies and hardening flags
  elf recompile <decompiled_dir> -o <binary>
              Generate link stubs and recompile all .c files into a dummy
              executable with clang
  il2cpp      Dump Unity IL2CPP metadata (global-metadata.dat + libil2cpp.so) to dump.cs
  version     Show version
  help        Show this help

Options:
  -o, --output          Output file/directory
  -i, --input           Original .hbc/.bundle (required for assemble: the
                         .hasm references that file's tables and is not
                         self-contained)
  -v, --verbose         Verbose output
  -h, --help            Show command help (also: destruct <command> -h)
  --deobfuscate         Accepted for compatibility; deobfuscation passes are
                         not implemented yet (except 'destruct js')
  --decompile           Use the decompiler (jvm/dex/elf). Hermes and Flutter
                         decompilation are not supported; use their
                         disassembly workflows instead.
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
  --il2cpp-metadata <path>
                         With --decompile (ELF), load Unity global-metadata.dat
                         to recover managed method, parameter and field names
                         (auto-detected next to libil2cpp.so)
  --emit-pseudo         With --decompile (ELF), select the unified pseudo-C
                         output explicitly (the default). The output is a
                         syntactically valid C translation unit: declarations,
                         uintptr_t casts, normalized labels and one dummy
                         function per lifted symbol
  --regs-as-vars        With --decompile (ELF), rename register placeholders
                         to arg0..arg7 / var_N / fvar_N (default keeps x0/w0)
  --no-location-comments Disable source-location comments when using --decompile (ELF)
  --print-options       Print the parsed configuration and exit
  --arch                With 'apk build', keep only lib/<arch>/ native
                         libraries (e.g. arm64-v8a, armeabi-v7a)
  --hermes-dec          Accepted no-op alias: the hermes-dec exact format is
                         always used for disassembly and assembly
  --version, -V         Show version

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
  destruct js bundle.js -o bundle.deobf.js
  destruct elf libnative.so -o output/ --decompile  # AArch64 pseudocode, one file
  destruct elf libnative.so -o output/ --decompile --il2cpp-offsets game_dump/
  destruct elf libil2cpp.so -o output/ --decompile --il2cpp-metadata global-metadata.dat
  destruct elf libnative.so -o output/ --emit-pseudo --split-functions
  destruct elf info libnative.so
  destruct elf recompile output/libnative.so_decompiled/ -o dummy
  destruct flutter libapp.so -o output/
  destruct il2cpp libil2cpp.so global-metadata.dat -o output/
  destruct elf libnative.so -o output/
  destruct hex libil2cpp.so
  destruct hex lib.so -c "info" -c "disasm 0x1000 32"
  destruct hex lib.so -c "search \"UnityPlayer\"" -c "read 0x2000"`)
}
func handleJVM(ctx context.Context, args []string) error {
	opts, input, err := parseFlags(args)
	if err != nil {
		return commandUsageError("jvm", err)
	}
	if opts.help {
		printCommandHelp("jvm")
		return nil
	}
	if opts.printOptions {
		return printOptionsJSON("jvm", opts)
	}
	if input == "" {
		return commandUsageError("jvm", errors.New("input file required"))
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
	opts, input, err := parseFlags(args)
	if err != nil {
		return commandUsageError("dex", err)
	}
	if opts.help {
		printCommandHelp("dex")
		return nil
	}
	if opts.printOptions {
		return printOptionsJSON("dex", opts)
	}
	if input == "" {
		return commandUsageError("dex", errors.New("input file required"))
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
	opts, input, err := parseFlags(args)
	if err != nil {
		return commandUsageError("hermes", err)
	}
	if opts.help {
		printCommandHelp("hermes")
		return nil
	}
	if opts.printOptions {
		return printOptionsJSON("hermes", opts)
	}
	if opts.decompile {
		return commandUsageError("hermes", errors.New("Hermes decompilation was removed; use the disassembly/assembly workflow (`destruct hermes` then `destruct assemble`)"))
	}
	if input == "" {
		return commandUsageError("hermes", errors.New("input .hbc file required"))
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
	opts, input, err := parseFlags(args)
	if err != nil {
		return commandUsageError("js", err)
	}
	if opts.help {
		printCommandHelp("js")
		return nil
	}
	if opts.printOptions {
		return printOptionsJSON("js", opts)
	}
	if input == "" {
		return commandUsageError("js", errors.New("input .js file required"))
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
	opts, input, err := parseFlags(args)
	if err != nil {
		return commandUsageError("assemble", err)
	}
	if opts.help {
		printCommandHelp("assemble")
		return nil
	}
	if opts.printOptions {
		return printOptionsJSON("assemble", opts)
	}
	if input == "" {
		return commandUsageError("assemble", errors.New("input .hasm file required"))
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
		return commandUsageError("assemble", errors.New("assembly requires the original .hbc/.bundle via -i/--input (the .hasm text references that file's string/function tables and cannot be assembled standalone)"))
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
	opts, input, err := parseFlags(args)
	if err != nil {
		return commandUsageError("interactive", err)
	}
	if opts.help {
		printCommandHelp("interactive")
		return nil
	}
	if input == "" {
		return commandUsageError("interactive", errors.New("input .hbc/.bundle file required"))
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
	opts, input, err := parseFlags(args)
	if err != nil {
		return commandUsageError("flutter", err)
	}
	if opts.help {
		printCommandHelp("flutter")
		return nil
	}
	if opts.printOptions {
		return printOptionsJSON("flutter", opts)
	}
	if opts.decompile {
		return commandUsageError("flutter", errors.New("Flutter decompilation was removed; use the disassembly output (`destruct flutter <libapp.so> -o output/`)"))
	}
	if input == "" {
		return commandUsageError("flutter", errors.New("input file required"))
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
	if len(args) > 0 {
		switch args[0] {
		case "help", "-h", "--help":
			printCommandHelp("elf")
			return nil
		case "recompile":
			return handleELFRecompile(ctx, args[1:])
		case "info":
			return handleELFInfo(ctx, args[1:])
		}
	}
	opts, input, err := parseFlags(args)
	if err != nil {
		return commandUsageError("elf", err)
	}
	if opts.help {
		printCommandHelp("elf")
		return nil
	}
	if input == "" {
		return commandUsageError("elf", errors.New("input file required"))
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
	if opts.il2cppOffsets != "" || opts.il2cppMetadata != "" || opts.regsAsVars {
		opts.decompile = true
	}

	// --decompile automatically enables source-location comments; use
	// --no-location-comments to opt out.
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
		SourceLocations: sourceLocations,
		SplitFunctions:  opts.splitFunctions,
		CrossReferences: opts.crossReferences,
		SimplifyCFG:     opts.simplifyCfg,
		EmitLLVM:        opts.emitLLVM,
		IL2CPPOffsets:   opts.il2cppOffsets,
		IL2CPPMetadata:  opts.il2cppMetadata,
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
			v, err := nextFlagValue(args, &i, arg)
			if err != nil {
				return commandUsageError("elf recompile", err)
			}
			output = v
		case "-h", "--help":
			printCommandHelp("elf recompile")
			return nil
		default:
			if strings.HasPrefix(arg, "-") {
				return commandUsageError("elf recompile", fmt.Errorf("unknown option: %s", arg))
			}
			if dir != "" {
				return commandUsageError("elf recompile", errors.New("exactly one decompiled directory is required"))
			}
			dir = arg
		}
	}
	if dir == "" {
		return commandUsageError("elf recompile", errors.New("decompiled directory required"))
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
	help := false
	var positionals []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			help = true
		case "-o", "--output":
			v, err := nextFlagValue(args, &i, args[i])
			if err != nil {
				return commandUsageError("il2cpp", err)
			}
			output = v
		case "-v", "--verbose":
			verbose = true
		case "--print-options":
			printOptions = true
		default:
			if strings.HasPrefix(args[i], "-") {
				return commandUsageError("il2cpp", fmt.Errorf("unknown option: %s", args[i]))
			}
			positionals = append(positionals, args[i])
		}
	}

	if help {
		printCommandHelp("il2cpp")
		return nil
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
		return commandUsageError("il2cpp", errors.New("both libil2cpp.so and global-metadata.dat are required"))
	}
	if len(positionals) > 2 {
		return commandUsageError("il2cpp", fmt.Errorf("unexpected extra argument: %s", positionals[2]))
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
		"noLocationComments": opts.noLocationComments,
		"splitFunctions":     opts.splitFunctions,
		"crossReferences":    opts.crossReferences,
		"simplifyCfg":        opts.simplifyCfg,
		"emitLLVM":           opts.emitLLVM,
		"il2cppOffsets":      opts.il2cppOffsets,
		"il2cppMetadata":     opts.il2cppMetadata,
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
	help               bool
	noLocationComments bool
	splitFunctions     bool
	crossReferences    bool
	simplifyCfg        bool
	emitLLVM           bool
	il2cppOffsets      string
	il2cppMetadata     string
	emitPseudo         bool
	regsAsVars         bool
}

// parseFlags parses the shared command-line flags used by most
// subcommands. It returns an error for an unknown flag, a flag missing
// its value, or a second positional argument instead of silently
// ignoring them.
func parseFlags(args []string) (cliOpts, string, error) {
	opts := cliOpts{
		output:  "output",
		project: true,
	}
	var input string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-h", "--help":
			opts.help = true
		case "-o", "--output":
			v, err := nextFlagValue(args, &i, arg)
			if err != nil {
				return opts, "", err
			}
			opts.output = v
		case "-i", "--input":
			v, err := nextFlagValue(args, &i, arg)
			if err != nil {
				return opts, "", err
			}
			opts.inputFile = v
		case "-v", "--verbose":
			opts.verbose = true
		case "--deobfuscate":
			// Accepted for compatibility; the deobfuscation passes are
			// not implemented yet.
			opts.deobfuscate = true
		case "--decompile":
			opts.decompile = true
		case "--hermes-dec":
			// Accepted no-op alias: the hermes-dec exact format is
			// always used.
			opts.hermesDec = true
		case "--print-options":
			opts.printOptions = true
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
			v, err := nextFlagValue(args, &i, arg)
			if err != nil {
				return opts, "", err
			}
			opts.il2cppOffsets = v
		case "--il2cpp-metadata":
			v, err := nextFlagValue(args, &i, arg)
			if err != nil {
				return opts, "", err
			}
			opts.il2cppMetadata = v
		case "--emit-pseudo":
			opts.emitPseudo = true
		case "--regs-as-vars":
			opts.regsAsVars = true
		case "--no-project":
			opts.project = false
		default:
			if strings.HasPrefix(arg, "-") {
				return opts, "", fmt.Errorf("unknown option: %s", arg)
			}
			if input != "" {
				return opts, "", fmt.Errorf("unexpected extra argument: %s", arg)
			}
			input = arg
		}
	}

	return opts, input, nil
}
