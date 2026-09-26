# DeStruct - ARM64 ELF Decompilation Upgrade TODOs

## Current Status
- [x] Initial codebase exploration complete
- [x] Identified ARM64 test files (arm64.sh, elysium/arm64.sh, lunacy/arm64.sh)
- [x] Reviewed existing pipeline structure (internal/pipeline/pipeline.go)
- [x] Reviewed ARM64 lifting code (internal/arm64lift/lift.go)
- [x] Reviewed ELF parsing (internal/native/elf.go)

## Phase 1: Easy Fixes (Completed)
- [x] Create pipeline_enhancements.go with comment enhancement
- [x] Add EnhanceComments and SourceLocations options to Pipeline.Options
- [x] Update Pipeline.Run() to apply enhancements when --enhance flag is used
- [x] Add --enhance and --location-comments CLI flags to cmd/destruct/main.go
- [x] Fix compilation errors (flutter module missing)
- [x] Run existing tests to verify no regressions

## Phase 2: Medium Fixes (Completed)
- [x] Add --print-options flag to show current config
- [x] Add multi-architecture support (ARM32, x86)
- [x] Add .dynsym fallback for stripped binaries (improve function candidate discovery)
- [x] Add switch statement detection in arm64lift
- [x] Improve variable naming in decompiled output
- [x] Add `--split-functions` flag for ELF decompilation to output per-function files + `functions.json`
- [x] Add cross-reference analysis in decompiled output
- [x] Add full CFG simplification and unreachable block removal

## Phase 3: Hard Fixes (Completed)
- [x] Add **LLVM IR export** - Export enhanced decompilation output to LLVM IR format (`--emit-llvm`, `internal/llvm`, per-function defines + string globals)
- [x] Merge-точки в liftBlockGraph (LabelStmt/GotoStmt) — shared continuation lifted once via immediate post-dominators + do-while-tail joins (output ~2.5x smaller on real binaries)
- [x] String dispatch через strcmp — address tracking through `mov`, `else if` rendering, strcmp-chain folding into `switch (x) { case "...": }`
- [x] Calling convention: args must not carry over from the previous call (`resultRegs` tracking in the lifter)
- [x] Fix `else if` в dump.cs In the renderer — restore the RVA for interface methods (always emit `// RVA:` line, `-1` when abstract/unresolved)
- [x] Try/catch reconstruction для C++ exceptions (`__cxa_begin_catch`/`__cxa_end_catch` marker split into real TryStmt)

## Phase 4: Experement Fixes (Future)
- [ ] Add **RISC-V support** - Add similar enhancements for RISC-V architecture (No targets on mobile arm64)

## Code Review Findings (New)

### High Priority
- [x] Replace synthetic ARM64 source locations in `internal/pipeline/pipeline_enhancements.go` with real instruction/function addresses from the ELF parser and lifter. The current `0x400000 + lineNum*4` calculation can emit incorrect reverse-engineering metadata.
- [x] Add defensive bounds and allocation checks to all binary parsers, especially Hermes, DEX, ELF, and IL2CPP. Validate offset+size overflow, count*record-size overflow, alignment, and conversions from `uint64` to `int` before allocating or slicing.
- [x] Add archive resource limits for JAR/APK processing: maximum entry size, total uncompressed size, archive size, and class/file count. Apply limits consistently in `internal/jvm/pipeline.go`, `internal/dex/pipeline.go`, and `internal/pipeline/pipeline.go`.
- [x] Replace parser-triggerable panics in `internal/il2cpp/executor.go` with typed errors where malformed input can reach the code. The CLI should report the failing table/index and continue or fail cleanly instead of crashing.
- [x] Add fuzz tests for class, DEX, Hermes, ELF, and IL2CPP parsers. Fuzzing must verify no panic, excessive allocation, infinite loop, or out-of-bounds access on malformed input.

### Medium Priority
- [x] Make output writes atomic across `internal/pipeline/pipeline.go`, `internal/java/generator.go`, `internal/csharp/generator.go`, and `internal/il2cpp/dump.go`: write to a temporary file, sync/close it, then rename it into place.
- [x] Fix temporary-file ownership in `internal/pipeline/pipeline.go:extractLibapp`. Return cleanup ownership or delete the extracted `/tmp/libapp-*.so` after processing so repeated runs do not leak files.
- [x] Replace direct `os.Exit` calls in command handlers with `func run(args []string) error`; keep process termination only in `main`. This will improve CLI testing and library reuse.
- [x] Normalize file extensions at the pipeline boundary and validate file signatures where possible. `.JAR`, `.APK`, and similarly cased inputs should behave consistently.
- [x] Replace unsafe Capstone structure pointer arithmetic in `internal/native/disasm.go` with a small, version-stable C helper API. Add lifecycle checks for nil/repeated `Close` and document thread-safety.
  - [ ] Follow-up: Capstone 6.0.0-Alpha10 implements `cs_option(CS_OPT_DETAIL)` as `handle->detail_opt |= value` (cs.c), so `CS_OPT_OFF` is a no-op and detail mode cannot be turned back off on a handle. Decide whether to keep detail permanently on after the first detailed call or use separate handles for detailed vs text-only disassembly.
- [x] Add `context.Context` cancellation to long-running JAR/APK, ELF, Flutter, Hermes, and IL2CPP operations so Ctrl-C and API timeouts stop work cleanly.
  - [x] Pipeline-routed: JVM/APK/DEX/ELF/Flutter (`RunContext` + per-entry/per-function checks)
  - [x] Hermes/IL2CPP deep ctx threading (done via *Context variants in hermes/{decompiler,disasm,hermesdec}.go and il2cpp/{il2cpp,dump,executor,metadata,registration,elf}.go)
- [x] Add mid-scan ctx checks to internal/native/elf.go (the `elf` command parser) and internal/native/ehframe.go (.eh_frame_hdr function discovery). NewELFParser / DisassembleELFFile / DiscoverFunctions now have `*Context` variants (originals kept as wrappers) that check per section + every 4096 bytes in the symbol/relocation/eh_frame scans. Same treatment as il2cpp/elf.go.

### Maintainability and Tooling
- [ ] Separate parsing, decompilation, rendering, and file-output responsibilities currently concentrated in `internal/pipeline/pipeline.go`.
- [ ] Replace package-level `fmt.Printf` progress output with injectable structured logging and add a `--json` result-summary mode.
- [ ] Add `go test -race ./...`, fuzz targets, coverage reporting, malformed-input regression fixtures, and golden-output tests to CI.
- [ ] Document parser limits, error behavior, temporary-file cleanup, and output overwrite/atomicity guarantees in `README.md` and `COMMANDS.md`.

## Testing
- [x] Run `go build -o destruct ./cmd/destruct`
- [x] Run `go vet ./...`
- [x] Run `go test ./internal/pipeline/`
- [x] Run `./test_enhancements.sh`
- [x] Run `./test_pipeline_enhancements.sh`

## Documentation
- [x] ARM64_Enhancement_README.md - Phase 3 section added
- [x] Update COMMANDS.md with new flags (`--emit-llvm`)
