package main

import (
	"fmt"
	"os"
)

// commandUsageLine returns a one-line usage synopsis for a subcommand.
// It is used both by `-h` help output and by usage errors, so the two
// never drift apart.
func commandUsageLine(cmd string) string {
	switch cmd {
	case "jvm":
		return "Usage: destruct jvm <input.class|input.jar> [-o <dir>] [-v] [--deobfuscate] [--no-project]"
	case "dex":
		return "Usage: destruct dex <classes.dex|app.apk> [-o <dir>] [-v] [--deobfuscate] [--no-project]"
	case "apk":
		return "Usage: destruct apk <build|sign> ... (run 'destruct apk --help' for details)"
	case "hermes":
		return "Usage: destruct hermes <file.hbc|file.bundle> [-o <dir>] [-v]"
	case "js":
		return "Usage: destruct js <file.js> [-o <out.js>] [-v]"
	case "assemble":
		return "Usage: destruct assemble <file.hasm> -i <original.hbc|original.bundle> [-o <out.hbc>] [-v]"
	case "interactive":
		return "Usage: destruct interactive <file.hbc|file.bundle>"
	case "hex":
		return hexUsageLine()
	case "flutter":
		return "Usage: destruct flutter <libapp.so|app.apk> [-o <dir>] [-v]"
	case "elf":
		return "Usage: destruct elf [info|recompile] <file.so> [-o <dir>] [--decompile] [-v]"
	case "elf info":
		return "Usage: destruct elf info <file.so>"
	case "elf recompile":
		return "Usage: destruct elf recompile <decompiled_dir> -o <binary>"
	case "il2cpp":
		return "Usage: destruct il2cpp <libil2cpp.so> <global-metadata.dat> [-o <dir>] [-v]"
	default:
		return ""
	}
}

// commandUsageError prints a concise error plus the command's usage line
// and returns errUsage (main exits with status 2 without printing it
// again).
func commandUsageError(cmd string, err error) error {
	fmt.Fprintf(os.Stderr, "destruct %s: %v\n", cmd, err)
	if line := commandUsageLine(cmd); line != "" {
		fmt.Fprintln(os.Stderr, line)
	}
	return errUsage
}

// printCommandHelp prints per-command help for `destruct <cmd> -h`.
func printCommandHelp(cmd string) {
	switch cmd {
	case "jvm":
		fmt.Println(`Usage: destruct jvm <input.class|input.jar> [-o <dir>] [-v] [--deobfuscate] [--no-project]

Decompiles JVM .class or .jar bytecode to Java source, reconstructing
packages and control flow (if/else, loops, switch, try/catch, lambdas).

Options:
  -o, --output <dir>   output directory (default: output)
  -v, --verbose        verbose progress
      --deobfuscate    accepted for compatibility (passes not implemented yet)
      --no-project     do not create project structure
      --print-options  print the parsed configuration and exit`)
	case "dex":
		fmt.Println(`Usage: destruct dex <classes.dex|app.apk> [-o <dir>] [-v] [--deobfuscate] [--no-project]

Decompiles Android DEX/APK bytecode to Java source. Multidex APKs are
processed class-by-class in streaming mode.

Options:
  -o, --output <dir>   output directory (default: output)
  -v, --verbose        verbose progress
      --deobfuscate    accepted for compatibility (passes not implemented yet)
      --no-project     do not create project structure
      --print-options  print the parsed configuration and exit`)
	case "apk":
		fmt.Println(apkUsage())
	case "hermes":
		fmt.Println(`Usage: destruct hermes <file.hbc|file.bundle> [-o <dir>] [-v]

Disassembles React Native Hermes bytecode to the hermes-dec exact .hasm
format. Decompilation to JavaScript is not supported; edit the .hasm and
reassemble with 'destruct assemble'.

Options:
  -o, --output <dir>   output directory (default: output)
  -v, --verbose        verbose progress
      --print-options  print the parsed configuration and exit`)
	case "js":
		fmt.Println(`Usage: destruct js <file.js> [-o <out.js>] [-v]

Runs the AST-based JavaScript deobfuscation/beautification pipeline
(constant folding, IIFE unwrapping, debugger removal). The default output
is <input>.deobf.js next to the input.

Options:
  -o, --output <path>  output path (default: <input>.deobf.js)
  -v, --verbose        verbose progress
      --print-options  print the parsed configuration and exit`)
	case "assemble":
		fmt.Println(`Usage: destruct assemble <file.hasm> -i <original.hbc|original.bundle> [-o <out.hbc>] [-v]

Reassembles an edited .hasm back into a patched Hermes bytecode file.
The original .hbc/.bundle is required: the .hasm references that file's
string/function tables and is not self-contained. Only functions whose
text changed are rebuilt; Addr8 branches are promoted to *Long when
needed.

Options:
  -i, --input <file>   original .hbc/.bundle (required)
  -o, --output <file>  output .hbc (default: <name>.patched.hbc)
  -v, --verbose        verbose progress
      --print-options  print the parsed configuration and exit`)
	case "interactive":
		fmt.Println(`Usage: destruct interactive <file.hbc|file.bundle>
       destruct repl <file.hbc|file.bundle>

Opens a radare2-style interactive Hermes patching session (seek, hexdump,
disassemble, write instructions, save).`)
	case "hex":
		printHexHelp()
	case "flutter":
		fmt.Println(`Usage: destruct flutter <libapp.so|app.apk> [-o <dir>] [-v]

Disassembles a Flutter libapp.so (Dart AOT) to readable ARM64 assembly and
per-function binary blobs. Flutter decompilation is not supported.

Options:
  -o, --output <dir>   output directory (default: output)
  -v, --verbose        verbose progress
      --print-options  print the parsed configuration and exit`)
	case "elf":
		fmt.Println(`Usage: destruct elf [info|recompile] <file.so> [-o <dir>] [--decompile] [-v]

Subcommands:
  info                 print ELF header, sections, symbols and security flags
  recompile            compile a split decompilation directory into a dummy binary

Without --decompile, prints an annotated assembly listing (ARM64, ARM32,
x86, x86-64). With --decompile, lifts AArch64 functions to pseudo-C.

Options:
  -o, --output <dir>          output directory (default: output)
  -v, --verbose               verbose progress
      --decompile             lift AArch64 to pseudo-C
      --split-functions, -sf  one .c per function + functions.json
      --cross-references, -x  caller/callee comments + xrefs.json
      --simplify-cfg          remove unreachable blocks / merge chains
      --emit-llvm             also export lifted IR to LLVM IR
      --emit-pseudo           select the unified pseudo-C mode (default)
      --regs-as-vars          rename register placeholders to argN/var_N
      --il2cpp-offsets <path> load an IL2CPP offsets.json/offset.hpp dump
      --il2cpp-metadata <path> load Unity global-metadata.dat for method/field names
      --no-location-comments  omit function location comments
      --print-options         print the parsed configuration and exit`)
	case "elf info":
		fmt.Println(`Usage: destruct elf info <file.so>

Prints a human-readable ELF summary: class, endianness, type, machine,
entry point, program headers, sections, dynamic dependencies, imported/
exported symbols, function counts and basic hardening flags (PIE, NX,
RELRO, stack canary).`)
	case "elf recompile":
		fmt.Println(`Usage: destruct elf recompile <decompiled_dir> -o <output_binary>

Generates <decompiled_dir>/stubs.c for unresolved externs and links every
.c file in the directory into a dummy executable with clang.`)
	case "il2cpp":
		fmt.Println(`Usage: destruct il2cpp <libil2cpp.so> <global-metadata.dat> [-o <dir>] [-v]

Dumps Unity IL2CPP metadata to dump.cs in Il2CppDumper format (images,
types, fields, properties, methods with RVA/Offset/VA/Slot, default values
and attributes).

Options:
  -o, --output <dir>   output directory (default: output)
  -v, --verbose        verbose progress
      --print-options  print the parsed configuration and exit`)
	default:
		printUsage()
	}
}
