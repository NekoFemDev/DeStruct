# fixed truncation turned into loop-unroll explosion (48x duplication, 1.4G output)

## Repro
```
destruct elf <binary> -o output/ --decompile --split-functions
destruct hex <binary> --read-only -c "decompile 0x1f88c4"
```

## Actual
- Function `0x1f88c4` (7296 bytes, ~1824 insns) decompiles to 16735 lines.
- It contains 48 copies of `__system_property_get(sp + 160 | 1, ...)` + `strtol(...)`, but the binary has only 2 static `bl __system_property_get` sites in that function (verified by opcode scan).
- Whole-binary output is 1.4G / ~12M lines from a 38M input (37x expansion); top-5 functions are 740KB–984KB each.
- The previous truncation bug (empty `while` cut the tail) is fixed, but the merge-point fix now duplicates the loop tail per iteration instead of lifting the loop once.

## Expected
Lift the decrypt/`prop_get` loop once as a `while`, with a single merge label after it (the `L_1f8ac8_1` / `L_1f8d54_2` join already exists in the CFG). Unrolling is acceptable for 2–3 iterations, not 48x. At minimum cap unrolling and fall back to a loop + `// [unrolled N x]` comment when the bound is dynamic.

## Context
- `functions.json` reports `size 7296, success true` — no failure signal despite the blowup.
- The 48 copies are textually identical (same `sp + 320 - 128`, same `strtol` args), confirming mechanical duplication rather than 48 distinct call sites.
