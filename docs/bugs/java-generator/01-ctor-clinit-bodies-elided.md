# DEX decompile: constructor / `<clinit>` bodies render as `if (...) { ... } else { ... }` placeholders

## Repro
```
destruct dex xCode_1.0.3.apk -o out
cat out/local/skinchanger/F.java
```

## Actual
Constructor body elides every composite statement:

```java
public F(boolean p0, float p1, float p2, float p3, int p4) {
    super();
    this.a = p0;
    p0 = (local.skinchanger.I).m;
    p0 = local.skinchanger.U.f(p1);
    if (!p0) { ... } else { ... }
    this.b = p0;
    ...
    if (!p0) { ... } else { ... }
    this.c = p0;
    ...
}
```

`while` loops in constructors are likewise `while (true) { ... }`
(e.g. `local/skinchanger/XcodeCatalog.<init>(Context)`), as are `try`
blocks — every statement kind that `ir/string.go` renders as a
placeholder.

Only constructors and static initializers are affected; regular methods
render bodies fully (`XcodeInventoryScanner.find` etc. are complete).

## Expected
Constructor bodies decompile the same as regular methods:

```java
public F(boolean p0, float p1, float p2, float p3, int p4) {
    super();
    this.a = p0;
    p0 = local.skinchanger.U.f(p1);
    if (!p0) {
        p0 = 12.0f;
    } else {
        p0 = Math.max(1.0f, Math.min(100.0f, p2));
    }
    this.b = p0;
    ...
}
```

## Context
- Root cause is in `internal/java/generator.go`, not the DEX control-flow
  recovery (`internal/dex/controlflow.go` is correct — the IR contains
  the real statements, verified against smali).
- The `javaTemplate` renders ordinary method bodies with
  `{{renderStmt .}}` (generator.go:994), which recurses properly via
  `renderStmt` (generator.go:308, full `*ir.IfStmt`/`*ir.WhileStmt`/
  `*ir.TryStmt`/`*ir.BlockStmt` cases).
- But the `<init>` branch (`{{range ctorBodyStatements .}}... {{.}}`,
  generator.go:981–982) and the `<clinit>` branch (generator.go:986–987)
  print each statement with `{{.}}`, which falls through to
  `fmt.Sprint` → the `String()` methods in `internal/ir/string.go` —
  and those are deliberate single-line placeholders
  (`if (%s) { ... } else { ... }`, `while (%s) { ... }`,
  `try { ... } catch { ... }`, `BlockStmt` → `{ ... }`).
- `renderNestedClass` (generator.go:895–906) does the same wrong thing
  for ctors of nested classes: `renderStmt(stmt, 3)` — this one is
  actually correct; only the template path is broken.
- Fix direction: change the two template ranges to invoke `renderStmt`
  (expose it as a template func for ctors the same way it is for
  regular methods, honoring `isReturnVoid` filtering already in the
  range). The `{{.}}`-on-its-own-line form loses the depth-2 indent
  anyway, so switching to `renderStmt` also fixes indentation.
- Latent second gap: `renderStmt` has no `case *ir.ForStmt`, so if the
  DEX/JVM frontends ever emit `ForStmt` it falls to
  `default: fmt.Sprint` → the `for (...; %s; ...) { ... }` placeholder.
  Currently only `arm64lift` constructs `ForStmt`, and it renders via
  `internal/arm64lift/render.go`, so this is not user-visible today.
- Observed on: 14 classes in xCode_1.0.3.apk (20 placeholder sites),
  e.g. `local/skinchanger/F`, `XcodeCatalog`, `XcodeEspView`,
  `com/millymods/esp/EspScene`.
