# hex `disasm` prints spurious `; asin` comment on unconditional branch

## Repro
```
destruct hex /data/data/com.termux/files/home/libunity.so --read-only -c "disasm v:0x643779c 12"
```

## Actual
```
v:0x0643779c  05 2d 51 15  b        0xb882bb0 ; asin
```

## Expected
No `; asin` suffix (or a correct target annotation). `b 0xb882bb0` is a plain
unconditional branch into `.plt` (`0xb881e00..0xb882f80`). `asin` looks like a
leaked math-function name from enhanced comments / capstone detail mapping.

## Notes
- Only the first (branch) line carries the bad comment; following
  `stp/adrp/ldrb/tbnz/bl` lines are clean.
- Suspect: enhanced-comment path keys off the wrong instruction id or operand.
