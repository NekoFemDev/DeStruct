# DeStruct

[![CI](https://github.com/NekoFemDev/DeStruct/actions/workflows/ci.yml/badge.svg)](https://github.com/NekoFemDev/DeStruct/actions/workflows/ci.yml)

**Multi-format decompiler and reverse-engineering toolkit for Android, JVM, native binaries and Unity.**

DeStruct is a self-contained Go + Capstone CLI (and library) for offline
binary analysis, with optional Unicorn-based AArch64 function emulation. It decompiles JVM and Android bytecode to Java, lifts
AArch64 ELF functions to readable pseudo-C, dumps Unity IL2CPP metadata,
disassembles Flutter and Hermes bytecode, edits Hermes bytecode with an
assembler and REPL, provides a mapped hex editor, and can rebuild and sign
APKs. It is designed to work on a phone under Termux as well as on a
desktop, with no external runtime decompiler required.

**What it is not:** a debugger, a full-system emulator, a full x86-64
decompiler, or a replacement for Ghidra/IDA on every format. `PE`,
`Hermes → JS` and `Flutter → Dart` decompilation are intentionally out of
scope. AArch64 function emulation is available as an optional analysis aid.

**Tags:** `decompiler` `reverse-engineering` `android` `arm64` `aarch64`
`jvm` `java` `dex` `apk` `unity` `il2cpp` `hermes` `flutter` `elf`
`capstone` `golang` `termux` `binary-analysis` `mobile-security`

## Features

- **JVM** — Full Java decompiler with control flow recovery (if/else, while, for, switch, try/catch, generics, lambdas). Streaming `.jar` mode for large files.
- **DEX** — Android `.dex`/`.apk` → Java. Streaming per-class output, multidex support, MUTF-8 strings, switch/fill-array-data payloads, structured control flow recovery (if/else, while, do-while, switch), try/catch/finally and synchronized reconstruction, Java annotations, and debug_info parameter/local names.
- **ARM64 ELF** — Lift disassembled AArch64 instructions to valid, recompilable pseudo-C with control flow recovery (if/else, while/do-while, struct field access, byte/halfword loads, indexed array accesses, conditional selects, pair loads/stores, pre/post-indexed writeback, scalar FP/SIMD, multi-register `ld1/st1`, lane-wise vector arithmetic, `fmla/fmls`, CAS, indirect calls). DWARF function/parameter names/types, return types, declaration source comments and typed locals are used when available; stripped binaries get refined boundaries from call targets, prologues, returns and relative function pointers. Offset comments, `CALL_VTABLE` macros, ASCII constants, goto reduction, per-function split output, generated link stubs, original ELF load-image reconstruction (`ENI_ADDR` + `image.bin`), replayed `R_AARCH64_RELATIVE`/GOT relocations with function-pointer redirection, LLVM IR export, and one-command `elf recompile` linking into a dummy executable.
- **AArch64 emulation (optional)** — `elf emulate` runs original functions in Unicorn, with the original load image, applied relocations, imported-call stubs and register/return reporting. `elf verify` builds a host driver from decompiled C and differentially compares return values against the Unicorn oracle. Optional Unicorn build (`make unicorn build-unicorn`) is an analysis aid for verification, fuzzing and outlined-block context recovery.
- **Hermes** — Disassemble React Native Hermes bytecode (`.hbc`/`.bundle`) to the exact hermes-dec `.hasm` format, reassemble edited functions, and patch interactively. JavaScript decompilation is not supported by design — edit `.hasm` instead.
- **Flutter** — Disassemble Flutter `libapp.so` (Dart AOT) to readable ARM64 assembly + per-function binary blobs.
- **IL2CPP** — Dump Unity `global-metadata.dat` + `libil2cpp.so` to `dump.cs` (images, types, fields, properties, methods with RVA/Offset/VA/Slot, default values, attributes). The same metadata powers `elf --decompile --il2cpp-metadata` for real managed method/parameter/field names.
- **JS** — AST-based JavaScript deobfuscation/beautification (constant folding, IIFE unwrapping, debugger removal).
- **APK** — Rebuild an apktool project (`apk build`, with ABI filtering) and align/sign it (`apk sign`).
- **ELF analysis** — `elf info` prints header, sections, dependencies, symbols, function counts and hardening flags (PIE, NX, RELRO, canary, FORTIFY).
- **ELF disassembly** — Capstone-based disassembler for ARM64, ARM32, x86, x86-64.
- **Hex editor** — `destruct hex`: mmap-based interactive hex editor with staged patches, atomic apply/save, search, ELF disassembly, AArch64 decompilation, and `-c` batch scripting.

## Install

```bash
git clone https://github.com/NekoFemDev/DeStruct.git
cd DeStruct
make build   # → ./destruct
```

Optional AArch64 emulation (fetches/builds the pinned Unicorn 2.1.4,
AArch64-only static library; requires `cmake` and `curl`):

```bash
make build-unicorn   # → ./destruct with Unicorn support
./destruct elf emulate lib.so 0x1234 --args 1,2
```

Or, after fetching/building the pinned Capstone once:

```bash
make capstone
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

Every command accepts `-h`/`--help` for its own synopsis, and
`destruct --version` prints the version. Unknown flags and missing flag
values are reported as usage errors instead of being silently ignored.

### Commands

| Command | Description |
|---------|-------------|
| `jvm` | Decompile `.class`/`.jar` → Java source |
| `dex` | Decompile Android `.dex`/`.apk` → Java source |
| `apk` | Rebuild (`build`) or align/sign (`sign`) an APK |
| `hermes` | Disassemble Hermes `.hbc` bytecode (hermes-dec exact format) |
| `js` | Deobfuscate/beautify a JavaScript file |
| `assemble` | Assemble an edited `.hasm` back into a patched `.hbc` |
| `interactive` | Interactive radare2-style REPL for `.hbc` patching |
| `flutter` | Disassemble Flutter `libapp.so` to ARM64 assembly |
| `elf` | Disassemble ELF binaries (ARM64/ARM32/x86/x64) |
| `elf info` | Print ELF header/sections/symbols/security summary |
| `elf recompile` | Link split pseudo-C into a dummy executable |
| `il2cpp` | Dump Unity IL2CPP metadata to `dump.cs` |
| `hex` | Interactive hex editor (staged patching, ELF disasm/decompile) |
| `version` | Show version (`--version` also works) |
| `help` | Show usage |

### Examples

```bash
# JVM
destruct jvm input.jar -o output/
destruct jvm SomeClass.class -o output/

# DEX
destruct dex classes.dex -o output/
destruct dex app.apk -o output/

# APK rebuild + sign
destruct apk build decoded/ -o unsigned.apk --arch arm64-v8a
destruct apk sign unsigned.apk -k release.jks -p "$KS_PASS" -o signed.apk

# Hermes
destruct hermes index.android.bundle -o output/
# Edit output/index.android.bundle.hasm, then reassemble (only changed
# functions are rebuilt; Addr8 branches auto-promote to their *Long form):
destruct assemble output/index.android.bundle.hasm -i index.android.bundle -o patched.hbc

# JavaScript
destruct js bundle.js -o bundle.deobf.js

# ARM64 ELF
destruct elf libnative.so -o output/ --decompile
destruct elf libnative.so -o output/ --decompile --split-functions
destruct elf libnative.so -o output/ --decompile --cross-references
destruct elf libnative.so -o output/ --decompile --simplify-cfg
destruct elf libnative.so -o output/ --decompile --emit-llvm
destruct elf libil2cpp.so -o output/ --decompile --il2cpp-metadata global-metadata.dat
destruct elf info libnative.so
destruct elf recompile output/libnative.so_decompiled/ -o dummy
destruct elf emulate libnative.so 0x1234 --args 1,2,3
destruct elf emulate libnative.so sub_1234 --json   # requires build-unicorn
destruct elf verify libnative.so output/libnative.so_decompiled/ --limit 100

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
| `-h, --help` | Per-command help |
| `--decompile` | Use the decompiler (ELF AArch64; JVM/DEX always decompile; Hermes and Flutter are disassembly-only) |
| `--split-functions` | Per-function output files + `functions.json` (ELF) |
| `--cross-references` | XREF comments + `xrefs.json` (ELF) |
| `--simplify-cfg` | CFG simplification / unreachable block removal (ELF, experimental) |
| `--emit-llvm` | Export lifted IR to LLVM IR `<name>.decompiled.ll` (ELF, implies `--decompile`) |
| `--il2cpp-offsets` | Load an IL2CPP offsets dump for field names/offsets (ELF, implies `--decompile`) |
| `--il2cpp-metadata` | Load Unity `global-metadata.dat` to recover managed method/parameter/field names (ELF, implies `--decompile`) |
| `--no-location-comments` | Omit function location comments (ELF) |
| `--deobfuscate` | Accepted for compatibility; general deobfuscation passes are not implemented yet |
| `--hermes-dec` | Accepted no-op alias: the hermes-dec exact format is always used for Hermes disassembly and assembly |

## Go API

The `pkg/destruct` package exposes the pipeline for embedding:

```go
import "github.com/destruct/destruct/pkg/destruct"

err := destruct.Decompile(destruct.Options{
    Input:     "libnative.so",
    Output:    "output",
    Decompile: true, // pseudo-C for ELF; ignored for JVM/DEX
})
```

`.so`/`.elf` inputs default to the native ELF pipeline. Set `Flutter: true`
to treat a `.so`/`.apk` as a Flutter `libapp.so` bundle. `.dex`/`.apk` use the
DEX pipeline; `.class`/`.jar` use the JVM pipeline. `DecompileJVM` and
`GenerateCSharp` remain available for callers that want the shared IR or C#
output.

## Testing

```bash
make test        # go test ./...
make test-race   # go test -race ./...
make vet         # go vet ./...
```

CI runs formatting, build, vet and the race-enabled test suite on every
push and pull request (`.github/workflows/ci.yml`).

## Architecture

```
cmd/destruct/       CLI entry point (commands, help, elf info)
internal/
  pipeline/          Orchestration: format detection, streaming, output
  jvm/               JVM bytecode parser, decompiler, control flow recovery
  dex/               DEX parser, Dalvik instruction decoder, IR converter, control flow recovery
  hermes/            Hermes bytecode: parser/, ir/, opcodes/, disasm/, asm/, repl
  hermes/parser/     .hbc -> ir.Module (version detection, container, instruction decode)
  hermes/ir/         version-agnostic intermediate representation
  hermes/opcodes/    per-version opcode tables (generated) + registry
  hermes/disasm/     ir.Module -> hermes-dec exact .hasm
  hermes/asm/        .hasm + original .hbc -> patched .hbc (jump relaxation)
  arm64lift/         ARM64 instruction lifter -> IR -> C-like pseudocode
  emulate/           Optional Unicorn AArch64 function emulation (build tag `unicorn`)
  native/            ELF parser, Capstone disassembler, PLT/GOT resolution, ELF info
  java/              Java source generator from IR
  csharp/            C# source generator from IR (library API)
  ir/                Shared intermediate representation (AST nodes)
  flutter/           Flutter/Dart AOT disassembler (unflutter)
  il2cpp/            Unity IL2CPP dumper (global-metadata.dat + libil2cpp.so -> dump.cs)
  js/                JavaScript AST deobfuscator
  hexedit/           Interactive hex editor implementation
  llvm/              LLVM IR exporter
  archivelimits/     JAR/APK resource limits
  atomicfile/        Atomic output writes
pkg/destruct/        Public Go API
```

See [TODOS.md](TODOS.md) for the current roadmap (ARM64 instruction coverage,
DEX debug info / try-catch, IL2CPP metadata integration and analysis commands).

## License

GNU General Public License, Version 2 (GPLv2). See [LICENSE](LICENSE).

Optional AArch64 emulation links against Unicorn Engine (GPLv2); Unicorn is
fetched and built from the pinned source release described in
[NOTICE](NOTICE).
