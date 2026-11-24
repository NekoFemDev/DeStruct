# DeStruct — Roadmap & TODOs

Last updated: 2026-11-23.

## Scope decisions

- **Removed:** Hermes → JS decompiler, Flutter → Dart decompiler, PE support.
  These were advertised but not implemented (or were a stub); disassembly-only
  Hermes/Flutter workflows remain.
- **Focus:** AArch64 ELF decompilation, Android (DEX/APK), Unity IL2CPP, and
  analysis tooling that can run self-contained on Termux.
- **Non-goals for now:** a full x86-64 decompiler, a full-system/debugger
  emulator, and a replacement for apktool/Ghidra on every format. Function-level
  AArch64 emulation is supported as an optional analysis aid.

## Done — quick wins (2026-11-19)

- [x] Removed the no-op `.decompiled.c.enhanced` duplicate and the obsolete
      `--enhance`/`--no-enhance` path.
- [x] Synced `README.md`/`COMMANDS.md` with the actual command set and removed
      the Hermes/Flutter/PE decompilation claims.
- [x] CLI: unknown flags and missing values are now errors; every subcommand
      has `-h`/`--help`; added `--version`/`-V`.
- [x] Fixed the public `pkg/destruct` API: `.so`/`.elf` now map to ELF, DEX/APK
      map to DEX, and Flutter requires an explicit option.
- [x] Added GitHub Actions CI (format, build, vet, `go test -race`).
- [x] Added `destruct elf info` (header, sections, dependencies, symbols,
      functions, hardening flags).

## ARM64 lifter (`internal/arm64lift`)

Coverage now includes the common integer ALU/shift ops, plain and
byte/halfword/unscaled loads and stores, register-indexed addressing,
`movz/movk/movn`, the flag/select family, general `ldp/stp`,
pre/post-indexed writeback, `madd/msub`, `udiv/sdiv`, bitfields,
sign/zero extension, signed loads, basic acquire/release/exclusive
accesses, x29-relative stack slots, scalar FP arithmetic/conversions
(`fadd/fsub/fmul/fdiv`, `fcmp`, `fcsel`, `scvtf`, `fcvtzs`, `fmov`
bitcasts, typed float/double loads/stores), the `cas` family, and
single/multi-register `ld1/st1` with lane-wise vector arithmetic.
DWARF supplies function/parameter names, declaration source comments
and simple frame-local names/types; slots without DWARF get a
width-derived int8/16/32/64 type. For stripped binaries, gap-based
`.eh_frame` boundaries are refined using direct call targets, prologue
shapes, return-followed-by-prologue boundaries and writable relative
function pointers; direct `bl` targets become independently lifted
functions and absolute data addresses are mapped through the original
load image. Remaining gaps are exact type recovery, full signatures
beyond the eight ABI argument slots, quad-precision arithmetic and
behavioral fidelity for split blocks that depended on a caller's
callee-saved registers/stack.

### P1 — instruction coverage

Sprint 1 (2026-11-19) is complete:
`movz/movk/movn`, `ldrb/strb`, `ldrh/strh`, `ldur/stur`,
`tst/subs/adds/ands`, the `csel/csinc/csinv/csneg` family and
register-indexed addressing (`[xN, xM, lsl #N]`).

Sprint 2 (2026-11-19) is complete:
pre/post-indexed writeback, general `ldp/stp`, `ldar/stlr`,
`ldaxr/ldxr/stxr/stlxr`, `ldrsb/ldrsh/ldrsw`, `madd/msub`,
`udiv/sdiv`, `ubfx/sbfx`, `sxtb/sxth/sxtw/uxtb/uxth/uxtw`, and
sxtw/uxtw memory-index extenders.

Sprint 3 (2026-11-19) is complete:
x29-relative stack-slot normalization, `cmn/neg/negs/bics`, `mneg`,
`extr`, `ubfiz/sbfiz`, byte/halfword exclusive atomics, and a core
FP/SIMD subset (`fadd/fsub/fmul/fdiv`, `fcmp/fcmpe`, `fcsel`,
`fneg/fabs`, `scvtf/ucvtf`, `fcvtzs/fcvtzu`, `fmov` including
int↔FP bitcasts, and float/double-typed `ldr`/`str`). Tests live in
`internal/arm64lift/lift_sprint1_test.go`, `lift_sprint2_test.go` and
`lift_sprint3_test.go`. On `test/liblun.so` the decompilation still
reports 426 functions / 0 failed; raw `x29` dereferences dropped from
2 to 0, `cond` placeholders dropped from 141 to 60, and the split
output still links through `elf recompile`.

Sprint 4 (2026-11-19) is complete:
DWARF function discovery/names, parameter names, declaration source
comments, `DW_OP_fbreg` local names/types for x29-relative slots, and
width-based local type inference (int8/16/32/64) for slots without
debug info. `elf info` reports the DWARF summary. On `test/liblun.so`
(no DWARF) the decompilation still reports 426 functions / 0 failed,
69 locals now get a narrower inferred type, and the split output still
links through `elf recompile`.

Sprint 5 (2026-11-19) is complete:
DWARF parameter names/types are used in function signatures (still
eight ABI slots, with the recovered prefixes typed), single-register
`ld1/st1` vector loads/stores, and the `cas/casa/casl/casal`,
`casb/cash` compare-and-swap family. Tests live in
`lift_sprint3_test.go` and `pipeline_test.go`.

Sprint 6 (2026-11-19) is complete:
multi-register `ld1/st1`, lane-wise vector `add/sub` and
`fadd/fsub/fmul/fdiv` for 4s/2d/16b/8h, `fmla/fmls`, `dup`, and
DWARF-derived function return types. Tests live in
`lift_sprint4_test.go` and `lift_sprint3_test.go`. On `test/liblun.so`
the decompilation still reports 426 functions / 0 failed and the split
output still links through `elf recompile`.

Sprint 7 (2026-11-19) is complete:
`il2cpp.MetadataIndex` maps native method RVAs back to managed
type/method/parameter names and instance fields (including base-class
field lookup), with `--il2cpp-metadata` and auto-detection next to
`libil2cpp.so`. Tests live in `internal/il2cpp/index_test.go`.

Sprint 8 (2026-11-19) is complete:
DEX try/catch/finally reconstruction, `synchronized` blocks from
monitor-enter/monitor-exit pairs, Java annotations (class, field, method
and parameter), debug_info parameter/local names and decoded line tables.
Tests live in `internal/dex/try_debug_test.go` and
`internal/dex/syntax_test.go`; the `zenin` fixture validates try_item,
handler, annotation and monitor parsing.

Sprint 9 (2026-11-20) is complete:
valid C floating literals (`1.0f` instead of `1f`), integer-backed
stack slots with `DS_BITCAST_*` access for mixed int/FP views (so one
slot no longer splits into `local_N`/`dlocal_N`), bitcasts for integer
ALU ops on `d`/`s` registers, tail-call forwarding of untouched ABI
argument registers, unresolved executable tail targets kept as calls,
`b.mi`/`b.pl` condition mapping, and capped indentation for extremely
deep control flow. Regression tests live in
`internal/arm64lift/quazar_regression_test.go` and `render_test.go`.
On `test/quazar_arm64` (761 `.eh_frame` functions) decompilation
reports 761/761 functions with 0 empty/0 failed, all 761 generated
translation units compile as AArch64 objects, and `elf recompile`
links a dummy executable successfully.

Sprint 10 (2026-11-20) is complete:
original ELF load-image reconstruction (`image.bin` + `image.c`) and
`DS_ADDR` rewriting for absolute data references; `.rela.dyn`
`R_AARCH64_RELATIVE` and `GLOB_DAT`/`ABS64` relocation replay in
`image_relocs.c` (data pointers rebased into the image, function
pointers redirected to lifted `sub_*` or generated `ext_*` stubs);
function-address arguments render as `&sub_*` / `&ext_*`; tail calls now
emit `return callee(...)` instead of discarding the result; `ret` with
no explicit write returns the incoming `x0`. On `quazar_arm64`: 32,971
absolute references map inside the 11 MiB image, 1,699 relative/GOT
relocations are replayed at startup, and vtables/init arrays/atexit
handlers point at decompiled functions. Remaining: 569 `bl` targets
inside existing function ranges (outlined blocks) and ~1.5k unresolved
`func_*` stubs.

Sprint 11 (2026-11-20) is complete:
function-boundary refinement for stripped binaries. `.eh_frame` gap
sizes are re-split using direct `bl` targets, prologue-shaped branch
targets, `ret`-followed-by-prologue boundaries, writable relative
function pointers, and cross-function tail branches. Every call target,
including tail-jump alias entries, becomes a lifted function;
straight-line intra-function calls are inlined when not split.
Conditional-compare coverage now includes `fccmp`/`fccmpe` and `ccmn`.
On `quazar_arm64` this raised recovery from 761 to 1721 entries, with
0 unresolved `func_*` targets, 0 unresolved `cond` placeholders, 8
empty ret-only entries, 0 failed, and all 1723 generated units (plus
image/relocation units) compiling for AArch64. Tests live in
`internal/arm64lift/quazar_regression_test.go`.

Remaining:
- [ ] Per-statement source-line comments.
- [ ] Smali output/assembly and APK rebuild integration.

### P1 — types and debug info

- [x] Parse DWARF (`.debug_info`/`.debug_line`): function names,
      parameter names, declaration source, simple `DW_OP_fbreg` local
      names/types.
- [x] Lightweight type inference: locals are declared from DWARF types
      or the widest stack access (int8/16/32/64, float/double).
- [ ] Better stack-slot recovery: detect arrays/structs and normalize
      remaining sp-relative naming.
- [x] Recover parameter names/types from DWARF and the function return
      type (the signature still keeps eight ABI slots).
- [ ] Per-statement source-line comments.
- [ ] Full type recovery for structs/arrays/pointers.

### P2 — performance and output

- [ ] `--jobs N`: lift functions in parallel with deterministic output order.
- [ ] Memory-map ELF inputs (the hex editor already mmaps; `native.NewELFParser`
      still uses `os.ReadFile`).
- [ ] Golden-output regression tests for representative functions and the
      `docs/bugs` reproducer set.
- [ ] Update/close the stale reports in `docs/bugs/` once each is verified.

## Android / DEX / APK

- [x] Reconstruct `try`/`catch`/`finally` from `encoded_catch_handler`
      (including catch-all handlers) and `synchronized` blocks from
      monitor-enter/monitor-exit pairs.
- [x] Parse `debug_info_item`: parameter/local names and decoded line
      tables.
- [x] Emit Java annotations from DEX `annotations_directory_item`
      (class, field, method and parameter annotations).
- [ ] Improve local-variable type inference and declaration placement.
- [ ] Add smali output/assembly (`dex → .smali`, `.smali → .dex`) for reliable
      patching when Java decompilation is imperfect.
- [ ] `destruct dex info`: DEX version, class/method counts, checksum/signature.
- [ ] `destruct apk info`: parse binary `AndroidManifest.xml` (package,
      versionCode/Name, min/target SDK, permissions, activities, ABIs).
- [ ] `destruct apk verify` (apksigner verify), `apk list`, `apk extract`.
- [ ] `apk sign`: support `--password-file`/stdin and keystore alias selection.
- [ ] End-to-end workflow: decompile → patch → rebuild → sign → install.

## Emulation / verification

Sprint 12 (2026-11-23) is complete:
project relicensed to GPLv2; optional Unicorn Engine 2.1.4 backend
(AArch64-only static build, `unicorn` Go build tag); `elf emulate`
loads the original ELF image, applies relative/GOT/PLT relocations,
redirects imported functions to a return-0 trampoline and reports final
registers/return via text or JSON. Emulation immediately exposed a real
pseudo-C bug: 32-bit `wN` parameter views were separate uninitialized
locals; they are now seeded as `(uint32_t)xN` views, and `x0..x7` are
always seeded from the function signature.

Sprint 13 (2026-11-23) is complete:
`elf verify` builds a host driver from the decompiled C and compares it
against the Unicorn oracle; pointer-only return differences are separated
from semantic mismatches. Emulator-guided review added `movi` vector-zero
initialization, zero-extension of 32-bit register returns/call arguments,
two-operand immediate shifts (`asr/lsl/lsr #imm`), correct GOT/data-slot
loads when the resolver only has a section label, a default `return x0`
for functions that end without an explicit return, and zero-initialized
synthesized locals/registers. On `quazar_arm64`, `sub_9e002c`,
`sub_90f934`, `sub_916820` and `sub_90f9bc` now match the oracle.

Sprint 14 (2026-11-23) is complete:
emulation-guided outlined-context recovery. `mrs xN, TPIDR_EL0` now maps
to a zero-initialized `ds_tls` block (`DS_TLS_BASE`) on both the host
and the Unicorn side, so Android stack-canary/TLS reads no longer become
null dereferences. Direct-branch targets that have no prologue/BTI entry
evidence are folded back into the surrounding function instead of being
emitted as context-less fragments. Fixed-address table bases (`adrp`/`add`
followed by an indexed load) keep their `DS_ADDR` expression instead of
degrading to an uninitialized placeholder register. `bti j` jump-table
case bodies that read inherited callee-saved registers now reload them
from `ds_outlined_ctx`; their dispatcher materializes and saves x19..x28
immediately before the indirect branch. On the zero-argument
`quazar_arm64` profile this raised exact return matches from 226 to 321,
pointer-only matches from 28 to 67, and reduced both-faulted functions
from 246 to 219 and host faults from 1,211 to 1,057 (1,666 tested functions
after fragment folding).

Sprint 15 (2026-11-23) is complete:
outlined stack-context recovery. A dispatcher that reaches a stack-using
outlined entry now gets a fresh zeroed `ds_outlined_stack` frame and
models sp/x29 as real pointers; `sub sp`/`add sp` and frame-pointer
save/restore adjustments are materialized so frame slots stay
addressable. The entry reloads sp/x29 from `ds_outlined_sp`/
`ds_outlined_fp` and addresses the same bytes as its dispatcher.
`DS_TARGET` resolves jump-table targets back from host image pointers
to original VAs and calls the lifted `sub_*` function, so the saved
context is actually consumed. Generated helper calls now use the
preamble's `DS_V*`/`DS_BITCAST_*` definitions instead of unresolved
`ext_` stubs, and link-stub generation recognizes the support globals.
The zero-argument `quazar_arm64` profile reports 325 exact matches, 70
pointer-only, 217 both-faulted and 1,050 host faults.

- [x] Optional Unicorn backend behind the `unicorn` build tag
      (`make unicorn build-unicorn`).
- [x] `elf emulate` with image/relocation/import setup.
- [x] `elf verify` host-vs-emulator differential runner.
- [x] 32-bit parameter-view seeding and zero-extended returns.
- [x] TPIDR_EL0 / TLS modeling.
- [x] Outlined jump-table context (`ds_outlined_ctx`) for callee-saved
      registers.
- [x] Fold prologue-less direct-branch fragments into their surrounding
      function.
- [x] Preserve fixed-address table bases in indexed accesses.
- [x] Outlined stack context (`ds_outlined_stack`): dispatchers model
      sp/x29 as real pointers, materialize prologue/epilogue sp
      adjustments, and entries reload the same frame.
- [x] Jump-table dispatcher resolver (`DS_TARGET`) so an outlined
      entry is called as lifted C instead of raw image bytes.
- [ ] Per-depth outlined stack frames (a nested dispatcher currently
      reuses the single shared frame).
- [ ] Extend outlined context recovery to non-`bti j` outlined
      subroutines.
- [ ] Reconstruct jump-table switches whose case bodies branch back into
      the dispatcher (e.g. `sub_94242c`).
- [ ] Structured fuzzing with pointer/struct argument profiles.
- [ ] Memory-effects comparison (writable image hash) in verify.

## Unity / IL2CPP

- [x] Implement `arm64lift.MetadataProvider` over `internal/il2cpp` so
      `elf --decompile` prints real method names, parameter names and field
      names (with base-class field lookup).
- [x] Auto-detect `global-metadata.dat` next to `libil2cpp.so`; expose
      `--il2cpp-metadata <path>`.
- [ ] Optional Il2CppDumper-compatible extras: `script.json`, `il2cpp.h`,
      `dummy.dll`.
- [ ] Handle protected/encrypted `global-metadata.dat` variants where feasible.
- [ ] Link `dump.cs` RVAs to the corresponding `elf` decompiled functions.

## Analysis commands

- [x] `elf info` (header/sections/symbols/dependencies/hardening).
- [ ] `destruct strings`: extract strings with addresses and code xrefs.
- [ ] `destruct callgraph`: DOT/Mermaid/JSON call graph, including vtable and
      indirect-call resolution where possible.
- [ ] `destruct diff old new`: compare functions (opcode/fuzzy hashes), strings,
      symbols and sizes across two builds.
- [ ] Data cross-references (adrp/add, literal pools, GOT) in addition to direct
      `bl` xrefs.
- [ ] FLIRT-style library-signature matching.
- [ ] `--json` / NDJSON output for every command (automation-friendly).

## Engineering and UX

- [x] CI: formatting, build, vet, `go test -race`.
- [ ] Golden tests, malformed-input regression fixtures and coverage reporting
      in CI; fuzz-smoke targets for the parsers.
- [ ] Replace package-level `fmt.Printf` progress output with injectable
      structured logging and a `--json` result-summary mode.
- [ ] Split `internal/pipeline/pipeline.go` (parsing, decompilation, rendering,
      file output are still concentrated in one file).
- [ ] Context cancellation for the Flutter in-process scan (`unflutter.Run`
      does not take a context).
- [ ] Stable public API (`pkg/destruct`): context-aware entry points and all
      supported formats.
- [ ] Document parser limits, error behavior, temp-file cleanup and atomic
      output guarantees.
- [ ] Remove or repurpose the dev-only `cmd/check`, `cmd/dump`, `cmd/lvtest`
      helpers; decide whether `internal/csharp` is a supported library feature.

## Historical ARM64 work (completed before this roadmap)

- [x] Control flow recovery: if/else, while/do-while, switch, break/continue,
      nested loops, compound `&&`/`||` conditions.
- [x] Merge points (`LabelStmt`/`GotoStmt`) and post-dominator analysis to avoid
      exponential fork duplication.
- [x] String dispatch through `strcmp` chains → `switch (x) { case "...": }`.
- [x] Calling-convention tracking (`resultRegs`) so call results are not reused
      as the next call's arguments.
- [x] Try/catch reconstruction for C++ exceptions
      (`__cxa_begin_catch`/`__cxa_end_catch`).
- [x] IL2CPP offset DB loading (`--il2cpp-offsets`) and named-field rendering.
- [x] LLVM IR export (`--emit-llvm`).
- [x] Per-function split output, `functions.json`, `xrefs.json`,
      `--cross-references`, `--simplify-cfg`.
- [x] Valid-C pseudo output, link stubs and `elf recompile`.
