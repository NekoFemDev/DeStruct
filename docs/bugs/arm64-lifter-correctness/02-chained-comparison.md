# lifter emits chained `a == b != 0` for `cmp/ccmp/csinv` sequences

## Repro
```
destruct hex <binary> --read-only -c "decompile 0x1f88c4"
```

## Actual
10+ occurrences:
```c
} else if (local_152 == sp + 320 - 128 != 0) {
```
In C this parses as `(local_152 == (sp+192)) != 0`, a boolean-vs-zero compare. The source is an ARM `cmp x8,x19` + `ccmp w9,#0,#0,ne` + `csinv` (two-condition AND: endptr check AND errno check after `strtol`). The lift collapses the two conditions into one chained `==...!=0`, which is both semantically wrong and unreadable.

## Expected
Split into explicit conjunction:
```c
} else if (local_152 == (sp + 192) && __errno_val != 0) {
```
or preserve the `ccmp` shape with temporaries. Never emit `a == b != 0`.

## Context
- Surrounding lines show the other half of the condition separately (`if (__errno().field_0 != 0)`), confirming the AND was split incorrectly across branches.
- Same pattern repeats in every unrolled copy, so one fix covers all sites.
