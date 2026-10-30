# elf `--decompile` truncates large function with empty `while` loop

## Repro
```
destruct elf <binary> -o output/ --decompile --split-functions
destruct hex <binary> --read-only -c "decompile 0x1f88c4"
```

## Actual
Function at `0x1f88c4` (reported as 7296 bytes by `hex info` / `decompile` header) lifts only its prologue plus the first `__system_property_get` / `strtol` block (~1.2KB of pseudocode), then stops:
```c
// sub_1f88c4 @ v:0x001f88c4 (f:0x001f88c4, 7296 bytes)
local_304 = d8;
...
if (.__system_property_get(sp + 160 | 1, sp + 320 - 128) < 1) {
    goto L_1f8ac8_1;
} else {
    ...
    .strtol(sp + 320 - 128, sp + 152, 10);
    goto L_1f8ac8_1;
}
L_1f8ac8_1:;
local_112 = .rodata+0xadf0;
.func_46e6f0();
.func_46e6fc();
while (!(.func_46e6f0().field_0 > xzr)) {
    if (.func_46e6f0().field_0 >= .func_46e6fc().field_0 + 1) {
    }
}
```
Everything after the empty `while` body is missing: the disassembly continues for ~1800 instructions (`bl 0x1738900` decrypt wrappers, `sub w10,#0x45` / `eor` string-decrypt loops, a second `__system_property_get` + `strtol`, `strncmp`, `getaddrinfo` setup), but none of it appears in the pseudocode. Same truncation in both `elf --split-functions` (`sub_1f88c4.c`) and `hex decompile`.

## Expected
Lift the whole function body (or at least continue past the empty loop), or emit a `// [truncated]` marker. An empty `while (...) { if (...) {} }` should not terminate lifting — the blocks after the loop merge point are reachable and contain the function's real logic (second half of the property/HWID check).

## Context
- ARM64 `ET_DYN`, stripped, `.text` `AX`.
- `disasm 0x1f88c4 100` shows a normal prologue (`sub sp,#0x1a0`, `stp x29/x30`, `mrs TPIDR_EL0`, `movk` key constants, `bl decrypt`, `ldrb/tbz`, `sub/eor/strb` decrypt loop, `bl __system_property_get`).
- Suspect: CFG simplifier / merge-point logic treats the empty loop as a terminator and drops all successors. `--simplify-cfg` was not used in this run; the bug reproduces with default flags.
- Workaround: none — `disasm` must be used for the tail.

## Update: `--simplify-cfg` does not help
Re-ran with `destruct elf <binary> -o output/ --decompile --split-functions --simplify-cfg` — `Decompiled 11551 functions (5 empty, 0 failed)`, but `sub_1f88c4.c` is still truncated (1177 bytes vs 1.2KB before, same cutoff at the empty `while`). `functions.json` size for `0x1f88c4` changed 32768 -> 7296, body identical.
