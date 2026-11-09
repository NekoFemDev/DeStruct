# DeStruct — Command Reference

All commands run through the built binary `destruct` (`make build` → `./destruct <command> ...`),
except `lifttest`, which is built separately from `cmd/lifttest/`.

---

## `destruct jvm` — decompile JVM `.class`/`.jar` → Java

```

destruct jvm input.jar -o output/
destruct jvm SomeClass.class -o output/

```

Accepts `.class` (single file) or `.jar` (full archive, including streaming mode
for large files). Output is a tree of `.java` files with reconstructed package
structure.

---

## `destruct dex` — decompile Android `.dex`/`.apk` → Java

```

destruct dex classes.dex -o output/
destruct dex app.apk -o output/

```

Accepts `.dex` (including individual multidex files) or `.apk` (all `classes*.dex`
inside the archive; duplicate classes across multidex are skipped). Output is a
tree of `.java` files with reconstructed package structure, fields, methods, and
structured control flow (`if`/`else`, `while`, `do-while`, `switch`).

Supports standard DEX 035–039, including MUTF-8 strings, switch/fill-array-data
payloads, and the compact 4-byte 23x instruction encoding found in protected apps.

Current limitations: `try`/`catch`/`finally` and `synchronized` blocks are
partially reconstructed (exception handler code may be dropped); register names
stay as `vN`; local variable types are not inferred; non-standard packer opcodes
are skipped.

---

## `destruct hermes` — disassemble Hermes `.hbc` (React Native)

```

destruct hermes index.android.bundle -o output/   # exact hermes-dec format (.hasm)

```

**Flags:**
- `--hermes-dec` — accepted no-op alias: the hermes-dec exact format is always
  used for disassembly (and for assembly).
- `--decompile` — disabled for Hermes during the current refactor; the command
  returns an explicit error instead of emitting `.js`.

**Workflow for structural edits (add/remove/reorder instructions):**
```

destruct hermes file.hbc -o output/

edit output/file.hbc.hasm in a text editor

destruct assemble output/file.hbc.hasm -i file.hbc -o patched.hbc

```

For same-size edits you can also patch the raw bytes directly with
`destruct hex`/any hex editor: every instruction's function-relative offset is
shown in the `.hasm`, and function bytecode offsets are available via the
`interactive` session (`disasm` / `info` commands).

---

## `destruct assemble` — reassemble edited `.hasm` back to `.hbc`

```

destruct assemble output/file.hbc.hasm -i file.hbc -o patched.hbc

```

**Required:** `-i` with the original `.hbc`/`.bundle` — the `.hasm` text refers to
its string/function tables and is not self-contained.

Only functions whose text actually changed are reassembled. Addresses are
recomputed automatically, including `Addr8` → `*Long` promotion when an edit
pushes a jump target out of the signed byte range; switch jump tables are
re-placed out of line and their `arg2` offsets recomputed. All affected
function headers, the debug-info offset and the SHA1 footer are rewritten.

---

## `destruct interactive` (or `destruct repl`) — interactive radare2-like patcher

```

destruct interactive file.bundle
destruct repl file.bundle

```

Inside the REPL:

| Command | Action |
|---|---|
| `s <addr>` | seek to address |
| `sf <name\|#N>` | seek to function by name or index |
| `f [filter]` | list functions (optionally filtered by substring) |
| `i` | file info |
| `pf` | print current function |
| `px [n]` | hex dump |
| `pd [n]` | disassemble n instructions |
| `wx <hex>` | write raw bytes (no address recompute, fixed size) |
| `wi <instr>` | write instruction as text (full address recompute via LCS, size may change) |
| `w` | save changes to current file |
| `wq [path]` | save and quit (optionally to another file) |
| `q` | quit |
| `q!` | quit without saving |
| `help`, `?` | command list |

---

## `destruct hex` — interactive hex editor with deferred patching

```

destruct hex libil2cpp.so                                  # interactive session
destruct hex lib.so -c "info" -c "disasm 0x1000 32"        # one-shot, fail-fast
destruct hex lib.so -c "patch 0x1000 90909090" -y -c "apply"
destruct hex lib.so --read-only -c "search "UnityPlayer""

```

The file is mapped into memory **read-only** (not read into the heap whole —
100+ MB `.so` files are fine). Edits accumulate in memory and hit disk only on
`apply`/`save`. Patches are reflected in `read`/`search`/`disasm` immediately
after `patch` (changed lines are marked with `~`).

| Command | Action |
|---|---|
| `read [addr] [len]` | hex dump (default: cursor, 256 bytes; max 65536) |
| `disasm [addr] [cnt]` | disassemble (default: cursor, 16; ELF only) |
| `decompile <func\|addr>` | pseudocode of a function (AArch64 ELF only; address = containing function) |
| `search <pattern>` | search: `"ASCII"`, `48 65 6c`, `48656c`, `48 ?? 6c` (wildcard) |
| `goto <addr>` | move cursor |
| `patch <addr> <hex>` | queue a patch (nothing written to disk yet) |
| `diff` | list queued patches with indices |
| `drop <index>` / `clear` | drop one patch / all patches |
| `apply` | write patches to the original file (atomically, after confirmation) |
| `save [path]` | write patches to another file (original untouched) |
| `info` | format, architecture, section table |
| `exit` / `quit` / `q` | quit (`q` refuses if patches are queued) |
| `q!` | quit, discarding patches |

**Addresses:** numbers are hexadecimal by default. `f:0x1234` — file offset
(default; this is where patches go), `v:0x1234` — virtual address (ELF only;
both are shown when they differ). Counters (`len`, `cnt`) are decimal, `0x`
for hex.

**Flags:**
- `-c, --command <cmd>` — run a command and exit; repeatable, fail-fast.
  Exit codes: 0 — success, 1 — command error, 2 — usage error.
- `-y, --yes` — skip confirmation for `apply`/`save` (for scripts).
- `--read-only` — forbid `patch`/`apply`/`save`.

**v0.1 limitations:**
- `disasm` — any recognized ELF (ARM/ARM64/x86/x86-64); `decompile` —
  AArch64 ELF only. For other formats the error message points to the right
  subcommand (`destruct jvm`, `destruct dex`, `destruct hermes`).
- `apply` replaces the original file wholesale (atomic rename) and does not
  create a backup: the full `diff` is shown, then confirmation is requested.
  If file size/mtime changed since open, `apply` refuses to write.
  `save <path>` is the safe variant.
- A patch cannot change file size (byte overwrite only).
- The mapped file must not be truncated externally: access past the new end
  triggers SIGBUS. After external changes, reopen the session.

---

## `destruct flutter` — disassemble Flutter `libapp.so` (Dart AOT)

```

destruct flutter libapp.so -o output/
destruct flutter libapp.so -o output/ --decompile   # output .dart instead of assembly

```

Requires the file to actually exist and have a `.so`/`.apk` extension —
validated before launch.

---

## `destruct elf` — disassemble ELF binaries (native .so, ARM/ARM64/x86)

```

destruct elf libnative.so -o output/
destruct elf libnative.so -o output/ --decompile                    # AArch64 pseudocode + enhancements
destruct elf libnative.so -o output/ --decompile --no-enhance        # without enhanced comments
destruct elf libnative.so -o output/ --decompile --no-location-comments # without location comments
destruct elf libnative.so -o output/ --decompile --split-functions   # one .c per function + functions.json
destruct elf libnative.so -o output/ --decompile --cross-references  # XREF comments + xrefs.json
destruct elf libnative.so -o output/ --decompile --simplify-cfg      # CFG simplification + unreachable block removal
destruct elf libnative.so -o output/ --decompile --emit-llvm           # also export lifted IR to LLVM IR (<name>.decompiled.ll)
destruct elf recompile output/libnative.so_decompiled/ -o dummy        # stubs.c + clang link into a dummy executable

```

Produces a readable assembly listing of all code sections annotated with symbols
(if `.symtab` is present).

**`--decompile`** (AArch64 only): instead of assembly listing, lifts every function
through the ARM64→pseudocode lifter (`internal/arm64lift`) and writes one file —
`<name>.decompiled.c` — containing all functions in sequence, each under its own
`// symbol_name`.

**`--split-functions`** / **`-sf`** (AArch64 + `--decompile` only): creates a
`<input_name>_decompiled/` directory, writes each function to its own `.c` file
(`sub_<addr>.c` or `<symbol>_<addr>.c`), and generates `functions.json` with
metadata: `address`, `name`, `size`, `success`. Useful for per-function analysis
and integration with external tools.

**`--cross-references`** / **`-x`** (AArch64 + `--decompile` only): prepends
`// XREF from:` / `// XREF to:` comments to each function listing callers and
callees, and generates `xrefs.json` (next to `.decompiled.c`, or inside
`_decompiled/` when `--split-functions` is used). Works via direct `bl #imm`
call analysis across all functions.

**`--simplify-cfg`** (AArch64 + `--decompile` only, experimental): runs a CFG
simplification pass before lifting — removes unreachable basic blocks and merges
linear chains (single predecessor + single successor). Does not touch loop
back-edges to avoid breaking `while`/`if` recognition. May improve output, but
in complex cases interacts unpredictably with the heuristic lifter, so it is
opt-in.

**`elf recompile <decompiled_dir> -o <binary>`**: post-processes a split
decompilation. Scans every `.c` file for unresolved `extern` declarations,
generates `<decompiled_dir>/stubs.c` (libc wrappers, generic zero-return
function stubs, variable stubs and a dummy `main`), then invokes:

```
clang -std=c11 -w -o <binary> <all .c files>
```

The output binary is a dummy executable suitable for link-time validation, not
a functional reimplementation of the original library. If `-o` is omitted the
binary is written to `<decompiled_dir>/decompiled_dummy`.

**`--emit-llvm`** (AArch64 only; implies `--decompile`): in addition to
`.decompiled.c`, writes `<name>.decompiled.ll` — each lifted function as LLVM IR
(`internal/llvm`): all values modeled as `i64`, locals as allocas in `entry`
with load/store (clang `-O0` style), structured control flow lowered to explicit
basic blocks and branches (`if`/`while`/`switch`, merge labels
`L_<addr>_<n>:` + `goto` translated to LLVM labels/branches 1:1). String literals
are lifted to private globals. The format targets `llvm-as`/`opt` or disassemblers,
not verified compilation — the lifted IR has no exact type system.

With `--decompile`, enhanced comments (`--enhance`) and location comments
(`--location-comments`) are enabled automatically. Disable with `--no-enhance` /
`--no-location-comments`.

**`--print-options`** — print parsed configuration and exit.

**Supported disassembler architectures:** `destruct elf` without `--decompile`
disassembles ARM64, ARM32, and x86/x86-64 ELF files, picking the Capstone mode
from the ELF header's machine field.

```

destruct elf libnative.so -o output/ --decompile

```

Reconstructs real control flow (if/else, while/do-while, calls, local variables,
struct field access through pointers) rather than a flat instruction listing. For
non-AArch64 binaries it exits with a clear error — use plain `destruct elf`
(without the flag) for raw disassembly of any architecture. A function that fails
to lift (panic inside the lifter) does not abort the run — it is marked with a
`// [failed to decompile: ...]` comment in the output file, and the run continues
with the next one.

---

## `destruct il2cpp` — dump Unity IL2CPP (`global-metadata.dat` + `libil2cpp.so`) → `dump.cs`

```

destruct il2cpp libil2cpp.so global-metadata.dat -o output/
destruct il2cpp global-metadata.dat libil2cpp.so -o output/   # argument order does not matter
destruct il2cpp libil2cpp.so global-metadata.dat -v            # diagnose registration search

```

Reads the "IL2CPP library + Unity metadata" pair directly from files (no app
launch, no root) and generates `dump.cs` in Il2CppDumper format: image list,
all types/fields/properties/methods with RVA/Offset/VA, virtual method Slot,
default values, and custom attributes.

What happens internally:
1. Parse `global-metadata.dat` (metadata versions 16–31 supported, including
   compressed v29+ custom-attribute blobs).
2. Find `Il2CppCodeRegistration` and `Il2CppMetadataRegistration` in
   `libil2cpp.so` (heuristic search via `mscorlib.dll` references, fallback to
   `g_CodeRegistration`/`g_MetadataRegistration` symbols) accounting for
   structure variations across adjacent IL2CPP versions.
3. Apply dynamic relocations (AArch64/x86-64/ARM/x86), unroll codeGen modules,
   types, field offsets, and generic instances.
4. Write `dump.cs`.

Flags:
- `-o, --output` — directory for `dump.cs` (default `output/`).
- `-v, --verbose` — print metadata version, registration addresses, etc.
- `--print-options` — print configuration and exit.

Both positional arguments are order-optional: `.so` and `global-metadata.dat`
are recognized by magic bytes, so they cannot be swapped.

Limitations: output is file-dump oriented (RVA == VA in image); `dump.cs` is
written without recovering method bodies — for disassembling code, use
`destruct elf` on the same RVAs.

---

## `destruct pe` — disassemble PE binaries (Windows `.exe`/`.dll`)

```

destruct pe program.exe -o output/

```

Same principle as `elf`, but for PE format.

---

## `destruct version` / `destruct help`

```

destruct version   # version
destruct help       # full usage text (embedded in the binary)

```

---

## Common flags (apply to most commands)

| Flag | Meaning |
|---|---|
| `-o, --output` | output file/directory |
| `-i, --input` | input `.hbc` file (for `assemble`/`patch`) |
| `-v, --verbose` | verbose output |
| `--deobfuscate` | enable deobfuscation |
| `--decompile` | use decompiler (JVM/Flutter/ELF AArch64) |
| `--enhance` | enhanced comments for AArch64 ELF decompilation |
| `--location-comments` | add address/location comments for AArch64 ELF |
| `--print-options` | print current configuration and exit |
| `--no-enhance` | disable enhanced comments for AArch64 ELF decompilation |
| `--no-location-comments` | disable location comments for AArch64 ELF decompilation |
| `--split-functions`, `-sf` | write each function to its own `.c` file and generate `functions.json` (ELF AArch64 with `--decompile` only) |
| `--cross-references`, `-x` | add `// XREF:` comments and generate `xrefs.json` (ELF AArch64 with `--decompile` only) |
| `--simplify-cfg` | run CFG simplification / unreachable block removal (ELF AArch64 with `--decompile` only, experimental) |
| `--emit-llvm` | export lifted IR as LLVM IR `<name>.decompiled.ll` (AArch64 only, implies `--decompile`) |
| `--no-project` | do not create project structure |

---

## `lifttest` — test driver for the ARM64→C lifter (experimental, separate binary)

Not part of the main `destruct` CLI — built separately from `cmd/lifttest/`:

```

go build -o lifttest ./cmd/lifttest/
./lifttest <path_to_ELF> <mangled_symbol_name> [param_names...]

```

**Example:**
```

./lifttest il2cpp_memory_dumper _ZN5utils7is_rootEv

// _ZN5utils7is_rootEv

return .geteuid() == 0;

./lifttest il2cpp_memory_dumper _ZN5utils10write_fileE... path data size

```

Find the symbol name for the second argument in advance, e.g. via
`readelf -s <file> | grep FUNC`.

**Status:** for one-off checks of a single function, `lifttest` is more convenient;
for decompiling a whole binary into one file — `destruct elf <file> --decompile`
(see above, already part of the main CLI). The lifter reconstructs if/else,
while/do-while (including arbitrary nesting and compound `&&`/`||` conditions of
any depth), local variables, struct field access through pointers, and indirect
calls (`blr`/`br`, including C++ vtable thunks) — on the test binary
(`test/il2cpp_memory_dumper`) all 177 functions decompile without empty output
and without panics. Remaining limitations (no full type system — names like
`field_8`/`local_16` are synthetic, not real; indexed and pre/post-indexed
addressing are not distinguished from plain offset addressing) are listed in
`internal/arm64lift/lift.go`, in the `TODO` block at the end.

---

## Build

```

make build     # build destruct -> ./destruct
make test      # run tests
make vet       # go vet
make clean     # remove binary and output/

```

Requires `libcapstone-dev` on the system (for the ELF/PE disassembler and `lifttest`).