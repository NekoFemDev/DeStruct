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

## Phase 3: Hard Fixes (Future)
- [x] Add `--split-functions` flag for ELF decompilation to output per-function files + `functions.json`
- [x] Add cross-reference analysis in decompiled output
- [x] Add full CFG simplification and unreachable block removal
- [ ] Add machine learning-guided comment placement
- [ ] Add export to LLVM IR format
- [ ] Add ARM64 SME (Scalable Matrix Extension) support
- [ ] Add RISC-V architecture support

## Files to Create/Modify
- `internal/pipeline/pipeline_enhancements.go` - [DONE] Comment enhancement
- `internal/pipeline/pipeline.go` - [DONE] Add EnhanceComments option, .dynsym size fallback, split-function output
- `cmd/destruct/main.go` - [DONE] Add CLI flags
- `internal/flutter/unflutter-0.5.9/internal/output/output.go` - [DONE] Flutter output module
- `internal/arm64lift/lift.go` - [DONE] Variable naming hints + jump-table switch detection
- `internal/arm64lift/render.go` - [DONE] Switch statement rendering
- `internal/arm64lift/cfg_simplify.go` - [DONE] CFG simplification / unreachable-block removal
- `internal/native/elf.go` - [DONE] Multi-arch PLT fallback, DataReader for jump tables
- `internal/native/disasm.go` - [DONE] NewDisassemblerForMachine helper
- `test_enhancements.sh` - [DONE] Test script
- `test_pipeline_enhancements.sh` - [DONE] Test suite

## Testing
- [x] Run `go build -o destruct ./cmd/destruct`
- [x] Run `go vet ./...`
- [x] Run `go test ./internal/pipeline/`
- [x] Run `./test_enhancements.sh`
- [x] Run `./test_pipeline_enhancements.sh`

## Documentation
- [x] ARM64_Enhancement_README.md - [DONE]
- [x] Update COMMANDS.md with new flags
