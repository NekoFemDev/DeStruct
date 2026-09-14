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

## Testing
- [x] Run `go build -o destruct ./cmd/destruct`
- [x] Run `go vet ./...`
- [x] Run `go test ./internal/pipeline/`
- [x] Run `./test_enhancements.sh`
- [x] Run `./test_pipeline_enhancements.sh`

## Documentation
- [x] ARM64_Enhancement_README.md - Phase 3 section added
- [x] Update COMMANDS.md with new flags (`--emit-llvm`)
