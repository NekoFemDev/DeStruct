# hex `decompile` shows raw numeric bases (`200101888.field_3104`) instead of section names

## Repro
```
destruct hex /data/data/com.termux/files/home/libunity.so --read-only -c "decompile v:0x64377a0"
```

## Actual
```c
if ((w8 & 1) != 0) {
    x0.field_96 = 5434;
    return .func_639c410(x0, 200101888.field_3104.field_0, xzr);
} else {
    .func_6365ccc(200101888.field_3104);
    ...
}
```

## Expected
`200101888` is `0xBED...` (`.data.rel.ro`/holder region `0xc572...` family after ASLR
rebasing — exact base mapping is already known to `hex info`). Show it as a
section-qualified base (e.g. `.data.rel.ro+0x...` / holder name) instead of a bare
decimal, so the `ldr x21,[x21,#0xc20]` global behind it is traceable.

## Context
- Same pattern on all 12 `System.Object` wrappers (`199532544.field_1952`,
  `199503872.field_3576`, ...).
- `hex info` already prints the section table; `decompile` does not reuse it.
