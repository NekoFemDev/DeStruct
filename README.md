# DeStruct

Multi-format decompiler: JVM `.class`/`.jar` → Java, Android `.dex`/`.apk` → Java, Hermes `.hbc` → JS, ARM64 ELF → C-like pseudocode, Flutter `libapp.so` → Dart bytecode.

## Features

- **JVM** — Full Java decompiler with control flow recovery (if/else, while, for, switch, try/catch, generics, lambdas). Streaming `.jar` mode for large files.
- **DEX** — Android `.dex`/`.apk` → Java. Streaming per-class output, multidex support, MUTF-8 strings, switch/fill-array-data payloads, and structured control flow recovery (if/else, while, do-while, switch).
- **Hermes** — Disassemble and decompile React Native Hermes bytecode (`.hbc`/`.bundle`) to readable JS. Includes assembler, interactive patcher, and hex-editor workflow.
- **ARM64 ELF** — Lift disassembled AArch64 instructions to valid, recompilable pseudo-C with control flow recovery (if/else, while/do-while, struct field access, indirect calls). Offset comments, `CALL_VTABLE` macros, ASCII constants, goto reduction, per-function split output, generated link stubs, and one-command `elf recompile` linking into a dummy executable.
- **Flutter** — Disassemble Flutter `libapp.so` (Dart AOT) to readable ARM64 assembly + binary patching support.
- **IL2CPP** — Dump Unity `global-metadata.dat` + `libil2cpp.so` to `dump.cs` (images, types, fields, properties, methods with RVA/Offset/VA/Slot, default values, attributes).
- **PE** — Disassemble Windows PE binaries (basic).
- **ELF disassembly** — Capstone-based disassembler for ARM64, ARM32, x86, x86-64.
- **Hex editor** — `destruct hex`: mmap-based interactive hex editor with staged patches, atomic apply/save, search, ELF disassembly, AArch64 decompilation, and `-c` batch scripting.

## Install

```bash
git clone https://github.com/NekoFemDev/DeStruct.git
cd DeStruct
make build   # → ./destruct
```

Or directly:

```bash
go build -o destruct ./cmd/destruct
```

### Termux (Android)

`install-termux.sh` handles the whole chain — `pkg` dependencies, the
Capstone fetch + static-lib build, the cgo build, and installing to
`$PREFIX/bin`:

```bash
# fresh shell
curl -fsSL https://raw.githubusercontent.com/NekoFemDev/DeStruct/main/install-termux.sh | bash

# or from a clone
./install-termux.sh            # installs to $PREFIX/bin/destruct
./install-termux.sh --update   # fast-forward the checkout, then reinstall
./install-termux.sh --uninstall
make install-termux INSTALL_ARGS="--update --clean"
```

Termux-specific details the script handles:

- **Interpreter** — Termux has no `/usr/bin/env` and `/bin/sh` is Android's
  mksh, so the script names `$PREFIX/bin/bash` directly. `bash install-termux.sh`
  works from any shell.
- **`GOTOOLCHAIN=local`** — if `go.mod` asks for a newer Go than the Termux
  `golang` package ships, the go command's default auto-download pulls
  `golang.org/toolchain@…linux-arm64`, which is a Linux ELF and cannot exec on
  Android. Pinning to `local` turns that into a clear version message, and the
  script will `pkg upgrade golang` for you before giving up.
- **Toolchain** — `CC`/`AR` are passed to the Capstone sub-make on the command
  line, since its `CC ?= gcc` / `AR ?= ar` defaults are not present on a stock
  Termux install.
- **`-j` capped at 4** — Capstone's `AArch64Disassembler.c` is a ~2 MB
  translation unit and `-O3` on it peaks around half a gig per process. Raise it
  with `--jobs N` if the device has headroom.
- **Network** — `git` and the Capstone tarball download retry with backoff over
  HTTP/1.1; mobile links routinely reset HTTP/2 streams mid-clone.
- **No runtime deps** — Capstone is linked statically, so the installed binary
  is self-contained.

Keep `-o` targets under `$HOME`; Android scoped storage blocks `/sdcard`
unless you have run `termux-setup-storage`.

## Usage

```
destruct <command> [options]
```

### Commands

| Command | Description |
|---------|-------------|
| `jvm` | Decompile `.class`/`.jar` → Java source |
| `dex` | Decompile Android `.dex`/`.apk` → Java source |
| `hermes` | Disassemble Hermes `.hbc` bytecode (hermes-dec exact format) |
| `assemble` | Assemble an edited `.hasm` back into a patched `.hbc` |
| `interactive` | Interactive radare2-style REPL for `.hbc` patching |
| `flutter` | Disassemble Flutter `libapp.so` to Dart bytecode |
| `elf` | Disassemble ELF binaries (ARM64/ARM32/x86/x64) |
| `il2cpp` | Dump Unity IL2CPP metadata (`global-metadata.dat` + `libil2cpp.so`) to `dump.cs` |
| `pe` | Disassemble PE binaries |
| `hex` | Interactive hex editor (staged patching, ELF disasm/decompile) |
| `version` | Show version |
| `help` | Show usage |

### Examples

```bash
# JVM
destruct jvm input.jar -o output/
destruct jvm SomeClass.class -o output/

# DEX
destruct dex classes.dex -o output/
destruct dex app.apk -o output/

# Hermes
destruct hermes index.android.bundle -o output/
# Edit output/index.android.bundle.hasm, then reassemble (only changed
# functions are rebuilt; Addr8 branches auto-promote to their *Long form):
destruct assemble output/index.android.bundle.hasm -i index.android.bundle -o patched.hbc

# ARM64 ELF
destruct elf libnative.so -o output/ --decompile
destruct elf libnative.so -o output/ --decompile --split-functions
destruct elf libnative.so -o output/ --decompile --cross-references
destruct elf libnative.so -o output/ --decompile --simplify-cfg
destruct elf libnative.so -o output/ --decompile --emit-llvm
destruct elf recompile output/libnative.so_decompiled/ -o dummy

# Flutter
destruct flutter libapp.so -o output/

# IL2CPP
destruct il2cpp libil2cpp.so global-metadata.dat -o output/

# Hex editor
destruct hex libil2cpp.so
destruct hex libnative.so -c "info" -c "disasm 0x1000 32"
destruct hex libnative.so -c "search \"UnityPlayer\"" -c "read 0x2000"
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
| `--emit-llvm` | Export lifted IR to LLVM IR `<name>.decompiled.ll` (ELF, implies `--decompile`) |
| `--no-enhance` | Disable enhanced comments (ELF) |
| `--hermes-dec` | Accepted no-op alias: the hermes-dec exact format is always used for Hermes disassembly and assembly |

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
  dex/              DEX parser, Dalvik instruction decoder, IR converter, control flow recovery
  hermes/           Hermes bytecode: parser/, ir/, opcodes/, disasm/, asm/ (+ frozen decompiler)
  hermes/parser/    .hbc -> ir.Module (version detection, container, instruction decode)
  hermes/ir/        version-agnostic intermediate representation
  hermes/opcodes/   per-version opcode tables (generated) + registry
  hermes/disasm/    ir.Module -> hermes-dec exact .hasm
  hermes/asm/       .hasm + original .hbc -> patched .hbc (jump relaxation)
  arm64lift/        ARM64 instruction lifter → IR → C-like pseudocode
  native/           ELF parser, Capstone disassembler, PLT/GOT resolution
  java/             Java source generator from IR
  csharp/           C# source generator from IR
  ir/               Shared intermediate representation (AST nodes)
  flutter/          Flutter/Dart AOT disassembler (unflutter)
  il2cpp/           Unity IL2CPP dumper (global-metadata.dat + libil2cpp.so → dump.cs)
pkg/destruct/       Public Go API
```

## License

MIT
