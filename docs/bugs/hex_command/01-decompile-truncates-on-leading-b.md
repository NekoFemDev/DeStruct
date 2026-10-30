# hex `decompile` truncates to 4 bytes when function starts with unconditional `b`

## Repro
```
destruct hex /data/data/com.termux/files/home/libunity.so --read-only -c "decompile v:0x643779c"
```

## Actual
```
// sub_643779c @ v:0x0643779c (f:0x0643379c, 4 bytes)
.asin();
```

## Expected
Decompile the containing function body (the real prologue starts at `v:0x64377a0`:
`stp x30,x21,[sp,#-0x20]! ...`, 92 bytes). A leading `b #plt` trampoline should not
cut the function to a single branch. At minimum `decompile` should skip a leading
`b` stub or report the fallthrough function, not a 4-byte `.asin()` stub.

## Context
- libunity.so ARM64, `.text` VA `0x535f940`, `v:0x643779c` = IL2CPP method wrapper.
- `disasm v:0x643779c 12` correctly shows the branch + full body after it.
- Workaround: `decompile v:0x64377a0` (address +4).
