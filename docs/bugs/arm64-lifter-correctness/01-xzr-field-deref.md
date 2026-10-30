# lifter emits `xzr.field_N` dereference of the zero register

## Repro
```
destruct hex <binary> --read-only -c "decompile 0x1f88c4"
```

## Actual
7 occurrences in one function:
```c
if (xzr.field_40 != .sub_46e6fc().field_0) {
    .__stack_chk_fail();
} else {
    return .sub_46e6fc();
}
```
`xzr` is the AArch64 zero register (constant 0). `xzr.field_40` is invalid C and a wrong lift — the source is a `ldr x8,[xN,#0x28]` / `cbz` epilogue where the base register was constant-folded to zero, or a `tpidr_el0` guard slot. It should render as a null check, `0`, or the real base (`sp`/`x19`), never as a struct deref of `xzr`.

## Expected
Never emit `xzr.field_*`. If the base is provably zero, emit `0` / `NULL` with a null-deref guard comment; otherwise preserve the original base register.

## Context
- Same function ends correctly 7 times (unrolled tail duplicated), each copy carries the same `xzr.field_40` line, so it is systematic, not a one-off.
- `disasm` of the tail shows `ldr x8,[x19,#0x28]` / `cmp` / `stack_chk_fail`, no `xzr`-based load.
