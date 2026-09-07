# DeStruct

Multi-format decompiler: JVM `.class`/`.jar` → Java, Hermes `.hbc` → JS, ARM64 ELF → C-like pseudocode, Flutter `libapp.so` → Dart bytecode.

## Features

- **JVM** — Full Java decompiler with control flow recovery (if/else, while, for, switch, try/catch, generics, lambdas). Streaming `.jar` mode for large files.
- **Hermes** — Disassemble and decompile React Native Hermes bytecode (`.hbc`/`.bundle`) to readable JS. Includes assembler, interactive patcher, and hex-editor workflow.
- **ARM64 ELF** — Lift disassembled AArch64 instructions to C-like pseudocode with control flow recovery (if/else, while/do-while, struct field access, indirect calls). Cross-reference analysis, CFG simplification, per-function split output.
- **Flutter** — Disassemble Flutter `libapp.so` (Dart AOT) to readable ARM64 assembly + binary patching support.
- **PE** — Disassemble Windows PE binaries (basic).
- **ELF disassembly** — Capstone-based disassembler for ARM64, ARM32, x86, x86-64.

## Install

```bash
# Requires libcapstone-dev
git clone https://github.com/NekoFemDev/DeStruct.git
cd DeStruct
make build   # → ./destruct
```

Or directly:

```bash
go build -o destruct ./cmd/destruct
```

## Usage

```
destruct <command> [options]
```

### Commands

| Command | Description |
|---------|-------------|
| `jvm` | Decompile `.class`/`.jar` → Java source |
| `hermes` | Disassemble/decompile Hermes `.hbc` bytecode |
| `assemble` | Assemble `.hasm` back to `.hbc` (with address recalculation) |
| `patch` | Search/patch Hermes bytecode strings |
| `interactive` | Interactive radare2-style REPL for `.hbc` patching |
| `flutter` | Disassemble Flutter `libapp.so` to Dart bytecode |
| `elf` | Disassemble ELF binaries (ARM64/ARM32/x86/x64) |
| `pe` | Disassemble PE binaries |
| `version` | Show version |
| `help` | Show usage |

### Examples

```bash
# JVM
destruct jvm input.jar -o output/
destruct jvm SomeClass.class -o output/

# Hermes
destruct hermes index.android.bundle -o output/ --decompile
destruct hermes index.android.bundle -o output/ -p   # patching format

# ARM64 ELF
destruct elf libnative.so -o output/ --decompile
destruct elf libnative.so -o output/ --decompile --split-functions
destruct elf libnative.so -o output/ --decompile --cross-references
destruct elf libnative.so -o output/ --decompile --simplify-cfg

# Flutter
destruct flutter libapp.so -o output/
```

### Key Flags

| Flag | Description |
|------|-------------|
| `-o, --output` | Output file/directory |
| `-v, --verbose` | Verbose output |
| `--decompile` | Use decompiler (Hermes → .js, Flutter → .dart, ELF → C pseudocode) |
| `--split-functions` | Per-function output files + `functions.json` (ELF) |
| `--cross-references` | XREF comments + `xrefs.json` (ELF) |
| `--simplify-cfg` | CFG simplification / unreachable block removal (ELF, experimental) |
| `--no-enhance` | Disable enhanced comments (ELF) |
| `--hex` | Hex-editor-friendly disassembly (Hermes) |
| `--patch-map` | Per-operand file offset map (Hermes) |
| `--hermes-dec` | hermes-dec-exact format (default for Hermes) |

## Testing

```bash
make test      # go test ./...
make vet       # go vet ./...
```

## Architecture

```
cmd/destruct/       CLI entry point
internal/
  pipeline/         Orchestration: format detection, streaming, enhancements
  jvm/              JVM bytecode parser, decompiler, control flow recovery
  hermes/           Hermes bytecode parser, disassembler, decompiler, assembler, REPL
  arm64lift/        ARM64 instruction lifter → IR → C-like pseudocode
  native/           ELF parser, Capstone disassembler, PLT/GOT resolution
  java/             Java source generator from IR
  csharp/           C# source generator from IR
  ir/               Shared intermediate representation (AST nodes)
  flutter/          Flutter/Dart AOT disassembler (unflutter)
pkg/destruct/       Public Go API
```

## License

MIT
