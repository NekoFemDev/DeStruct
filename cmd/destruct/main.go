package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/destruct/destruct/internal/hermes"
	"github.com/destruct/destruct/internal/il2cpp"
	"github.com/destruct/destruct/internal/pipeline"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		if !errors.Is(err, errUsage) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}

// errUsage marks a usage error whose message has already been printed by
// printUsage; main exits non-zero without printing it again.
var errUsage = errors.New("invalid usage")

// run dispatches a single CLI invocation. Command handlers return errors
// instead of terminating the process, which keeps them testable.
func run(args []string) error {
	if len(args) < 1 {
		printUsage()
		return errUsage
	}

	switch cmd := args[0]; cmd {
	case "jvm":
		return handleJVM(args[1:])
	case "dex":
		return handleDex(args[1:])
	case "hermes":
		return handleHermes(args[1:])
	case "assemble":
		return handleAssemble(args[1:])
	case "patch":
		return handlePatch(args[1:])
	case "interactive", "repl":
		return handleInteractive(args[1:])
	case "flutter":
		return handleFlutter(args[1:])
	case "elf":
		return handleELF(args[1:])
	case "il2cpp":
		return handleIL2CPP(args[1:])
	case "pe":
		return handlePE(args[1:])
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
  jvm       Decompile JVM .class/.jar files to Java source code
  dex       Decompile Android .dex/.apk files to Java source code
  hermes    Disassemble/decompile Hermes .hbc bytecode to JS
  assemble  Assemble .hasm back to .hbc bytecode (with address recalculation)
  patch     Search/patch Hermes .hbc bytecode
  flutter   Disassemble Flutter libapp.so to readable Dart bytecode
  elf       Disassemble ELF binaries to readable assembly (--decompile: AArch64-only pseudocode)
  il2cpp    Dump Unity IL2CPP metadata (global-metadata.dat + libil2cpp.so) to dump.cs
  pe        Disassemble PE binaries to readable assembly
  version   Show version
  help      Show this help

Options:
  -o, --output        Output file/directory
  -i, --input         Input HBC file (for assemble/patch)
  -v, --verbose       Verbose output
  --deobfuscate       Enable deobfuscation
  --decompile         Use decompiler (hermes: output .js, flutter: output .dart,
                       elf: output C-like pseudocode for every function in one
                       file - AArch64 binaries only)
  --split-functions, -sf
                      With --decompile (ELF), write each function to a
                       separate .c file under <input>_decompiled/ and emit
                       functions.json metadata (address, name, size, success)
  --cross-references, -x
                      With --decompile (ELF), add cross-reference comments
                       (callers/callees) and emit an xrefs.json file
  --simplify-cfg      Run CFG simplification / unreachable-block removal
                        for AArch64 ELF decompilation (experimental)
  --emit-llvm           With --decompile (ELF), also export every lifted
                        function as LLVM IR to <input>.decompiled.ll
  --no-enhance        Disable enhanced comments when using --decompile (ELF)
  --no-location-comments Disable source-location comments when using --decompile (ELF)
  --print-options     Print the parsed configuration and exit
  -s, --search        Search for string in bytecode
  -t, --patch-string  Quick patch: replace instruction with string operand (true/false/nop)
  -p, --patch         Generate simplified format for manual patching
  --hex               Hex-editor-friendly disassembly (absolute file offsets)
  --patch-map         Hermes-dec format plus per-operand file offset/byte map,
                       for patching in a hex editor without reassembling
  --hermes-dec        (default on "hermes") hermes-dec-exact disassembly format;
                       on "assemble", assemble THAT format instead of the
                       older simplified one (requires -i with the original
                       .hbc/.bundle - the text references its string/
                       function tables and isn't self-contained)

Workflow for manual patching (small, same-size edits):
  1. destruct hermes file.hbc -o output/ --patch-map  # Exact per-byte offsets
  2. Locate the bytes to change with a hex editor       Edit them in place
  3. No reassembly needed - the .hbc file offsets are absolute

Workflow for structural edits (add/remove/reorder instructions):
  1. destruct hermes file.hbc -o output/          # Exact hermes-dec format
  2. Edit output/file.hbc.hasm in a text editor
  3. destruct assemble output/file.hbc.hasm -i file.hbc -o patched.hbc --hermes-dec
     (only functions whose text actually changed are reassembled; addresses
     are recalculated automatically, promoting Addr8 branches to their
     *Long form if an edit pushes a jump target out of byte range)

Quick patch workflow:
  destruct patch file.hbc -t "isPro" --check-only  # Only patch CHECK instructions (safe)
  destruct patch file.hbc -t "isPro"                # Patch ALL instructions (may break things)

Examples:
  destruct jvm input.jar -o output/
  destruct dex classes.dex -o output/
  destruct dex app.apk -o output/
  destruct elf libnative.so -o output/ --decompile  # AArch64 pseudocode, one file
  destruct hermes index.android.bundle -o output/ --decompile
  destruct hermes index.android.bundle -o output/ -p  # Simplified format
  destruct assemble output/file.hbc.hasm -i file.hbc -o patched.hbc --hermes-dec
  destruct assemble output/file.hbc.hasm -i file.hbc -o patched.hbc  # Simplified format
  destruct patch file.hbc -t "isPro"
  destruct flutter libapp.so -o output/ --decompile
  destruct il2cpp libil2cpp.so global-metadata.dat -o output/
  destruct elf libnative.so -o output/`)
}

func handleJVM(args []string) error {
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

	if err := p.Run(); err != nil {
		return err
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
	return nil
}

func handleDex(args []string) error {
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

	if err := p.Run(); err != nil {
		return err
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
	return nil
}

func handleHermes(args []string) error {
	opts, input := parseFlags(args)
	if input == "" {
		return errors.New("input .hbc file required")
	}

	if err := os.MkdirAll(opts.output, 0o755); err != nil {
		return err
	}

	file, err := hermes.ParseFile(input)
	if err != nil {
		return fmt.Errorf("parsing HBC: %w", err)
	}

	fmt.Printf("Parsed Hermes bytecode v%d (%d functions, %d strings)\n",
		file.Header.Version, file.Header.FunctionCount, file.Header.StringCount)

	if opts.decompile {
		// Use decompiler
		d := hermes.NewDecompiler(file)
		dasmPath := filepath.Join(opts.output, filepath.Base(input)+".js")
		f, err := os.Create(dasmPath)
		if err != nil {
			return err
		}
		defer f.Close()
		d.DecompileAll(f)
		fmt.Printf("Decompiled: %s\n", dasmPath)
	} else {
		// Use disassembler
		d := hermes.NewDisassembler(file)
		hasmPath := filepath.Join(opts.output, filepath.Base(input)+".hasm")
		f, err := os.Create(hasmPath)
		if err != nil {
			return err
		}
		defer f.Close()

		// Use simplified format for patching
		if opts.patch {
			d.DisassembleAllPatch(f)
			fmt.Printf("Simplified disassembly (for patching): %s\n", hasmPath)
		} else if opts.hex {
			d.DisassembleAllHex(f)
			fmt.Printf("Hex-editor disassembly: %s\n", hasmPath)
		} else if opts.patchMap {
			d.DisassembleAllPatchMap(f)
			fmt.Printf("Hex-editor patch map (absolute file offsets per operand): %s\n", hasmPath)
		} else {
			// hermes-dec-exact format: matches the reference Python
			// hermes-dec disassembler's text output byte for byte on
			// bytecode versions 97-99 (the opcode table DeStruct ships
			// targets that range; older versions will decode structurally
			// but instruction mnemonics may not match).
			d.DisassembleAllExact(f)
			fmt.Printf("Disassembly (hermes-dec exact format): %s\n", hasmPath)
		}
	}

	// Print summary
	for i, hdr := range file.FunctionHeaders {
		name := "<unknown>"
		if int(hdr.FunctionName) < len(file.Strings) {
			name = file.Strings[hdr.FunctionName]
		}
		if opts.verbose || i < 10 {
			fmt.Printf("  Function #%d: %s (%d bytes, %d params)\n",
				i, name, hdr.BytecodeSizeInBytes, hdr.ParamCount)
		}
	}
	if len(file.FunctionHeaders) > 10 && !opts.verbose {
		fmt.Printf("  ... and %d more functions (use -v for all)\n",
			len(file.FunctionHeaders)-10)
	}
	return nil
}

func handleAssemble(args []string) error {
	opts, input := parseFlags(args)
	if input == "" {
		return errors.New("input .hasm file required")
	}

	if opts.output == "output" {
		opts.output = strings.TrimSuffix(input, filepath.Ext(input)) + ".hbc"
	}

	if opts.hermesDec {
		// Exact hermes-dec-format assembly: always patches an existing
		// .hbc/.bundle (the text format references string_id/
		// function_id/bigint_id indices into that file's own tables, so
		// it's never self-contained), diffing against the file's
		// current disassembly to find and reassemble only the functions
		// that actually changed.
		if opts.inputFile == "" {
			return errors.New("--hermes-dec assembly requires the original .hbc/.bundle via -i/--input (the .hasm text references that file's string/function tables and cannot be assembled standalone)")
		}
		f, err := hermes.ParseFile(opts.inputFile)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", opts.inputFile, err)
		}
		asm := hermes.NewHermesDecAssembler(f)
		result, err := asm.AssembleAndPatch(input)
		if err != nil {
			return fmt.Errorf("assembling: %w", err)
		}
		if len(result.ChangedFunctions) == 0 {
			fmt.Println("No changes detected; output is identical to the input .hbc")
		} else {
			fmt.Printf("Patched %d function(s): %v (bytecode size change: %+d bytes)\n",
				len(result.ChangedFunctions), result.ChangedFunctions, result.SizeDelta)
		}
		if err := f.Write(opts.output); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		fmt.Printf("Wrote %s\n", opts.output)
		return nil
	}

	// Use smart assembler with address recalculation
	sa := hermes.NewSmartAssembler()
	instrs, err := sa.ParseSimple(input)
	if err != nil {
		return fmt.Errorf("parsing HASM: %w", err)
	}

	fmt.Printf("Parsed %d instructions from %s\n", len(instrs), input)

	// Check if we have an input HBC file for full patching
	if opts.inputFile != "" {
		// Full patching mode
		if err := sa.PatchFile(opts.inputFile, input, opts.output); err != nil {
			return fmt.Errorf("patching: %w", err)
		}
		fmt.Printf("Patched %s -> %s\n", opts.inputFile, opts.output)
	} else {
		// Standalone assembly mode
		bytecode, err := sa.AssembleWithRecalc(instrs)
		if err != nil {
			return fmt.Errorf("assembling: %w", err)
		}

		if err := os.WriteFile(opts.output, bytecode, 0644); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		fmt.Printf("Assembled %d bytes -> %s\n", len(bytecode), opts.output)
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

	file, err := hermes.ParseFile(input)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", input, err)
	}

	r := hermes.NewRepl(file, input, os.Stdout)
	if err := r.Run(os.Stdin); err != nil {
		return err
	}
	return nil
}

func handlePatch(args []string) error {
	opts, input := parseFlags(args)
	if input == "" {
		return errors.New("input .hbc file required")
	}

	if opts.output == "output" {
		opts.output = strings.TrimSuffix(input, filepath.Ext(input)) + ".patched.hbc"
	}

	// Parse the HBC file
	file, err := hermes.ParseFile(input)
	if err != nil {
		return fmt.Errorf("parsing HBC: %w", err)
	}

	fmt.Printf("Parsed Hermes bytecode v%d (%d functions, %d strings)\n",
		file.Header.Version, file.Header.FunctionCount, file.Header.StringCount)

	// Create patcher
	ps := hermes.NewPatcher(file)

	// Search mode
	if opts.search != "" {
		fmt.Printf("Searching for: %s\n", opts.search)
		results := ps.SearchString(opts.search, true) // exact match
		if len(results) == 0 {
			fmt.Println("No matches found")
		} else {
			fmt.Printf("Found %d matches:\n", len(results))
			for _, r := range results {
				fmt.Printf("  Function #%d (%s) @ 0x%x\n", r.FuncIdx, r.FuncName, r.Offset)
			}
		}
		return nil
	}

	// Quick patch mode: patch string to true/false/nop
	if opts.patchString != "" {
		patchType := "true"
		fmt.Printf("Quick patching %q to %s (checkOnly=%v)\n", opts.patchString, patchType, opts.checkOnly)
		patched, err := ps.QuickPatchString(opts.patchString, patchType, opts.checkOnly)
		if err != nil {
			return err
		}
		fmt.Printf("Patched %d occurrences\n", patched)

		// Save output
		outPath := opts.output
		if outPath == "output" {
			outPath = strings.TrimSuffix(input, filepath.Ext(input)) + ".patched" + filepath.Ext(input)
		}
		if err := ps.Save(outPath); err != nil {
			return fmt.Errorf("saving: %w", err)
		}
		fmt.Printf("Saved to: %s\n", outPath)
		return nil
	}

	// List mode (verbose)
	if opts.verbose {
		for i := range file.FunctionHeaders {
			instrs := ps.ListFunction(i)
			name := "<unknown>"
			if int(file.FunctionHeaders[i].FunctionName) < len(file.Strings) {
				name = file.Strings[file.FunctionHeaders[i].FunctionName]
			}
			fmt.Printf("\nFunction #%d: %s (%d instructions)\n", i, name, len(instrs))
			for _, pi := range instrs {
				fmt.Printf("  %08x  %-28s %s\n", pi.Offset, pi.Inst.Name, pi.Format(file))
			}
		}
		return nil
	}

	// Patch mode: apply HASM file
	if opts.inputFile != "" {
		fmt.Printf("Applying patches from: %s\n", opts.inputFile)
		a := hermes.NewAssembler()
		instrs, err := a.ParseHASM(opts.inputFile)
		if err != nil {
			return fmt.Errorf("parsing HASM: %w", err)
		}

		// Group instructions by function
		// The HASM file has offsets starting from 0 for each function
		// We need to figure out which function each instruction belongs to
		funcOffsets := make([]uint32, len(file.FunctionHeaders))
		for i, hdr := range file.FunctionHeaders {
			funcOffsets[i] = hdr.Offset
		}

		applied := 0
		currentFunc := 0
		for _, instr := range instrs {
			// Track which function we're in based on offsets
			// If offset is small (< first function size), it's function 0
			// Otherwise, find the function
			relOffset := instr.Offset

			// Find which function this belongs to
			// Since offsets reset to 0 for each function in the HASM,
			// we need to track based on function boundaries
			for funcIdx, hdr := range file.FunctionHeaders {
				if relOffset < hdr.BytecodeSizeInBytes {
					currentFunc = funcIdx
					break
				}
			}

			if err := ps.PatchInstruction(currentFunc, relOffset, instr.Name+" "+strings.Join(instr.Operands, ", ")); err != nil {
				fmt.Printf("  Warning: %s @ 0x%x: %v\n", instr.Name, instr.Offset, err)
			} else {
				applied++
			}
		}

		fmt.Printf("Applied %d patches\n", applied)
	}

	// Save patched file
	if err := ps.Save(opts.output); err != nil {
		return fmt.Errorf("saving patched file: %w", err)
	}

	fmt.Printf("Patched file saved: %s\n", opts.output)
	return nil
}

func handleFlutter(args []string) error {
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

	if err := p.Run(); err != nil {
		return err
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
	return nil
}

func handleELF(args []string) error {
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
	})

	if err := p.Run(); err != nil {
		return err
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
	return nil
}

// handleIL2CPP implements `destruct il2cpp`, which dumps both a Unity
// global-metadata.dat and the matching libil2cpp.so into dump.cs.
//
// Usage: destruct il2cpp <libil2cpp.so> <global-metadata.dat> [-o output/]
// The two positional arguments may be given in either order; they are
// detected from their magic numbers.
func handleIL2CPP(args []string) error {
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

	result, err := il2cpp.Run(il2cpp.Options{
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

func handlePE(args []string) error {
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

	if err := p.Run(); err != nil {
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
		"search":             opts.search,
		"patch":              opts.patch,
		"hex":                opts.hex,
		"hermesDec":          opts.hermesDec,
		"patchMap":           opts.patchMap,
		"inputFile":          opts.inputFile,
		"patchString":        opts.patchString,
		"checkOnly":          opts.checkOnly,
		"printOptions":       opts.printOptions,
		"noEnhance":          opts.noEnhance,
		"noLocationComments": opts.noLocationComments,
		"splitFunctions":     opts.splitFunctions,
		"crossReferences":    opts.crossReferences,
		"simplifyCfg":        opts.simplifyCfg,
		"emitLLVM":           opts.emitLLVM,
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
	search             string
	patch              bool
	hex                bool
	hermesDec          bool
	patchMap           bool
	inputFile          string
	patchString        string
	checkOnly          bool
	printOptions       bool
	noEnhance          bool
	noLocationComments bool
	splitFunctions     bool
	crossReferences    bool
	simplifyCfg        bool
	emitLLVM           bool
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
		case "-s", "--search":
			if i+1 < len(args) {
				i++
				opts.search = args[i]
			}
		case "-t", "--patch-string":
			if i+1 < len(args) {
				i++
				opts.patchString = args[i]
			}
		case "--check-only":
			opts.checkOnly = true
		case "-p", "--patch":
			opts.patch = true
		case "--hex":
			opts.hex = true
		case "--hermes-dec":
			opts.hermesDec = true
		case "--patch-map":
			opts.patchMap = true
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
