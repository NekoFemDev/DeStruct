# DeStruct — ARM64 Lifter TODOs (IL2CPP / quazar decompiled output)

Source of truth: /data/data/com.termux/files/home/quazar/assets_decompile/quazar_arm64.decompiled.c
Metadata offsets: game_dump/offsets.json, game_dump/offset.hpp, game_dump/maps/*
Target binary: libapp.so / libunity.so (arm64-v8a, IL2CPP)

> Статус: пункты 1–10 закрыты в лифтёре/пайплайне (см. пометки под каждым пунктом).
> Биндинг RVA→method_rva.txt и подстановка имён из maps/*.tsv оставлены точкой
> подключения: лифтер принимает `arm64lift.MetadataProvider` (см. liftopts.go),
> в него подключается вывод внешнего дампера.

## Контекст: формат декомпелята

some_file.decompiled.c — не компилируемый C, а псевдо-C на стиль:
- `sub_XXXXXX` — метка функции с `// ELF function entry VA: 0xXXXXXX`
- `x0-x30`, `q0`, `s0-s31` — регистры используются как псевдо-переменные
- `local_NN` — стековые локальные переменные
- `field_NNNN` — индекс поля в IL2CPP metadata (не байтовое смещение!)
- `tmp0` — временные
- `(base + const).field_N` — адресная арифметика + доступ к полю
- `.__cxa_atexit(...)`, `.__libc_init()` — вызовы рантайма
- `10674176 + 4000` — ссылки в rodata/data (raw адреса без реlöвки)

Сопоставление: `field_NNNN` (индекс) ↔ `offsets.json` / `offset.hpp` (байтовое смещение от базы объекта IL2CPP).

## 1. Поле-доступы (field_NNNN → байтовое оффсетное смещение)

[x] Добавить загрузчик `game_dump/offsets.json` (или `offset.hpp`) в лифтер: `internal/arm64lift/offsetdb.go`
   - Карта: TypeDefIndex + имя поля → байтовое смещение (0x10, 0x18, ...)
   - Интерфейс: `FieldOffset(typeName string, fieldIndex int) (uint64, bool)`
   - Реализовано: `LoadOffsetDB` (авто-детект JSON/offset.hpp), `FieldOffsetByName`,
     `FieldOffset(typeName, fieldIndex)` (точные индексы — только если дамп их содержит,
     т.е. из maps/field_decl.tsv; plain offsets.json вернёт false), `FieldAtOffset`
     (обратный поиск имя/тип по смещению), `ClassByTypeDefIndex`.

[x] В рендерере (`internal/arm64lift/render.go`) заменить `field_NNNN` на реальное смещение:
   - `x8.field_952` → `*(uint64*)(x8 + 0x952)` или `obj->field952` при известном типе
   - Поддержка цепочек: `(x0 + 4).field_0` → `*(uint64_t*)((uintptr_t)x0 + 4 + 0x0)`
   - Реализовано в едином C-рендерере (`render.go`, `RenderCFunction`): режим
     pseudo печатает явные pointer-deref'ы с `uintptr_t` (п. 8).
     Цепочки: `(x0 + 4).field_0` → `*(uint64_t*)((uintptr_t)x0 + 4 + 0x0)`; именованное поле →
     `obj->fieldName` при наличии типа (MetadataProvider).
   - Уточнение к примеру: `field_960`/`field_952` — это ДЕСЯТИЧНЫЕ displacement'ы,
     т.е. реальные байтовые смещения 0x3c0/0x3b8; рендер идёт с истинным значением
     (`+ 0x3b8`), а не с ошибочным `0x952` из примера.

[x] Добавить флаг `--il2cpp-offsets <path>` в `cmd/destruct/main.go` для подключения дампа оффсетов.
   - Принимает файл (offsets.json / offset.hpp) или каталог (ищет offsets.json → offset.hpp).
   - Отдельный `.il2cpp.h` больше не генерируется: единый режим не создаёт
     структур и заголовков.

## 2. Регистры как переменные (x0-x30, q0, s0-s31)

[x] Текущий lifter уже трекит регистры (`regs map[string]...`), но в декомпеляте они ведут себя как SSA-переменные внутри функции.
   - Добавить явное переименование регистров в `var_0`, `var_1`... при первом использовании как lvalue
   - Сохранять связь `x0 = arg0` (AAPCS64: x0-x7 — аргументы) для рендеринга сигнатур
   - Реализовано: `LiftOptions.RegsAsVars` (`--regs-as-vars`, автоматически в
     `--regs-as-vars`): x0–x7/w0–w7 → `arg0..arg7` (если не подставлены реальные
     имена параметров из метаданных), остальные целые → `var_N` (стабильно на весь
     регистр, нумерация с первого lvalue), имена общие для всех fork'ов лифта.

[x] Обрабатывать `q0`, `s0-s31` (SIMD/float) как отдельный класс переменных, не путать с целочисленными.
   - Отдельный счётчик и класс: `q/d/s/h/b0-31` → `fvar_N`; `xN/wN` алиасятся в один
     ключ, SIMD-регистры — в `vN`, пересечения классов нет.

## 3. Адресная арифметика + поле

[x] Паттерн `(x0 + C).field_N` → распознавать как `ptr = x0 + C; *(fieldType*)(ptr + fieldOffset)`
   - Пропускать через `offsetdb` для разрешения `field_N` → смещение
   - Рендерить как `(*(uint32_t*)((uintptr_t)x0 + 4 + 0x44))` или с именованным полем если тип известен
   - В едином C-режиме любой FieldAccess с известным displacement рендерится как
     `*(uintW_t*)((uintptr_t)base + 0xoff)` (W = ширина доступа: x/w/q/d/s/h/b);
     именованный — `((Class*)base)->field`; смещение само по себе и есть байтовый
     offset из `offsets.json`, доuточного сопоставления индексов не требуется.

## 4. Метки функций и вызовы

[x] Парсить `sub_XXXXXX` и `// ELF function entry VA: 0xXXXXXX` как функциональные границы
   - Связывать вызов `.sub_910ef8(x0, x1, ...)` с RVA/VA цели
   - При известном символе — подставлять имя, иначе `sub_<rva>`
   - Уже было: границы (symtab / .eh_frame_hdr) и `sub_<addr>`-резолвер; проверено
     на quazar_arm64 (761 функция из eh_frame).

[x] Обрабатывать точки в начале вызова: `.__cxa_atexit`, `.__libc_init` — IL2CPP/рантайм хелперы, рендерить как есть без попыток «исправить».
   - Рендерятся как есть (`.name` — следствие пустого Class у StaticMethodCall, не баг).

## 5. Rodata / data ссылки

[x] Литералы вида `10674176 + 4000` → разрешать через `.rodata` / `.data` секцию ELF
   - `internal/native/elf.go` — добавить резолвер адреса → строка/константа
   - Рендерить как `"строка"` или `0xXXXXXXXX` с комментарием адреса
   - Реализовано: `native.ELFParser.AnnotateAddr` (`.section+0xoff`),
     `annotatedELFResolver` в пайплайне, `lifter.resolveAddrExpr` (строка →
     символ → label → `AddrLit` в hex). На quazar: `10674176 + 4000` → `.data+0x0`,
     `__cxa_atexit(9501068, ...)` → `.__cxa_atexit(0x90f98c, ...)`.

## 6. IL2CPP объектная модель в памяти

[x] Документировать/реализовать модель доступа к полю managed-объекта:
   ```
   адрес_поля = адрес_объекта + 16 (заголовок IL2CPP) + поле_смещение_из_offsets
   ```
   - В `offsets.json` смещения уже от базы объекта (после заголовка), подтвердить экспериментально на `libapp.so`
   - Подтверждено по field_decl.tsv: первый instance-field (`_unknownFields`) имеет
     offset 0x10 — т.е. смещения уже включают 16-байтовый заголовок объекта, ровно
     как displacement в `ldr/str`. Документировано в `offsetdb.go`; на quazar_arm64
     метаданные не совпадают по адресам (дамп от другого билда/бинаря), поэтому
     экспериментальная сверка на libapp.so/libunity.so остаётся за тобой.

[—] Генератор C-заголовков для структур из `offsets.json` (PlayerAchievement, AchievementDefinition и т.д.) — удалён вместе с `--emit-il2cpp-c`.
   - `arm64lift.GenerateIL2CPPHeader` (`cheader.go`) остаётся только legacy-кодом;
     пайплайн его не вызывает. Для синтаксической валидности pseudo-C структуры
     не нужны: касты полей идут через `uintptr_t`/байтовые offset'ы.

## 7. Интеграция с конвейером DeStruct

[x] `internal/pipeline/pipeline.go` — добавить этап post-lift для IL2CPP-декомпелята: подгрузка `offsets.json`, замена `field_NNNN`, привязка RVA к `method_rva.txt`
   - Подгрузка и post-lift rewrite — сделано (в едином режиме: single-file и
     `--split-functions`; каждый файл — самостоятельный translation unit).
   - Привязка RVA к `method_rva.txt` — интерфейс готов (`LiftOptions.Metadata`,
     `MetadataProvider`), конкретный загрузчик maps/*.tsv не писал: дампер живёт
     отдельным проектом (по твоему указанию).

[ ] `internal/il2cpp/` — переиспользовать существующие парсеры metadata (`typedef_decl.tsv`, `field_decl.tsv`, `method_decl.tsv`) для восстановления имён полей вместо `field_NNNN`
   - Не делал (после твоего «дампер не писать»): достаточно реализовать
     `MetadataProvider` поверх твоего дампера — после этого имена полей/параметры
     подставляются автоматически (см. тест `TestLiftFunction_MetadataFieldName`).

## 8. Вывод

[x] `--emit-il2cpp-c` удалён. Генерация «идеально компилируемого C» с
   восстановленными структурами и заголовками — отдельная исследовательская
   задача (типы, layout'ы, ABI), которая не оправдывает второй режим
   рендеринга. Остаётся один режим — `--emit-pseudo` (он же дефолт для
   `--decompile`).

[x] Единый `--emit-pseudo` выдаёт синтаксически корректный C translation unit:
   - в начале файла — `#include <stdint.h>` / `<stddef.h>` и typedef для
     128-битных q-регистров;
   - каждая функция — полноценное определение
     `uint64_t sub_XXXXXX(uint64_t x0, ..., uint64_t x7) { ... }`;
   - в начале тела — объявления всех используемых регистров и локалов
     (`uint64_t x0, x1, x8; uint32_t w0; int64_t local_16, tmp0; ...`);
   - доступ к памяти — явный каст с `uintptr_t`:
     `*(uint64_t*)((uintptr_t)x8 + 0x3b8)`;
   - адресные константы — `((uintptr_t)0x90f98c)` вместо `.data+0x0` /
     `.got+0x8`;
   - метки `goto` нормализуются в `LABEL_1`, `LABEL_2`, ... и уникальны в
     пределах функции; пропущенные цели `goto` получают метку в конце тела;
   - имена функций/переменных санитизируются до валидных C-идентификаторов,
     для внешних вызовов печатаются unprototyped `extern`-объявления.

[x] `--il2cpp-offsets` остаётся точкой подключения `MetadataProvider` для имён
   полей; `.il2cpp.h` больше не генерируется. `internal/arm64lift/cheader.go`
   и `rewrite.go` — legacy-хелперы удалённого режима, пайплайном не
   используются.

## Пример желаемого преобразования

Декомпилят:
```
if (x9.field_960 - x8.field_952 < 1) {
    local_16 = 10674176 + 4000;
}
```

После лифта (единый `--emit-pseudo`):
```
if (*(uint64_t*)((uintptr_t)0xa2a3c0) - *(uint64_t*)((uintptr_t)0xa2a3b8) < 1) {
    local_16 = ((uintptr_t)0xa2efa0);
}
// object-поля без метаданных:
if (*(uint64_t*)((uintptr_t)x9 + 0x3c0) - *(uint64_t*)((uintptr_t)x8 + 0x3b8) < 1) {
    local_16 = ((uintptr_t)0xa2efa0);
}
```

## Ссылки в репозитории

- `internal/arm64lift/lift.go` — само lifted IR
- `internal/arm64lift/render.go` — единый C-рендеринг (`RenderCFunction`, `WriteCFilePreamble`)
- `internal/arm64lift/offsetdb.go` — загрузчик offsets.json / offset.hpp (п. 1)
- `internal/arm64lift/liftopts.go` — LiftOptions: RegsAsVars, MetadataProvider (пп. 2, 7)
- `internal/arm64lift/rewrite.go` — legacy-хелпер удалённого `--emit-il2cpp-c` (не используется)
- `internal/arm64lift/cheader.go` — legacy-генератор `.il2cpp.h` (не используется)
- `internal/native/elf.go` — парсинг ELF, секции, адреса (+ `AnnotateAddr`, п. 5)
- `internal/il2cpp/` — парсеры IL2CPP metadata (точка подключения дампера, п. 7)
- `cmd/destruct/main.go` — CLI флаги

## Тестирование (quazar_arm64, arm64-v8a, stripped ET_DYN)

```
./destruct elf quazar_arm64 -o out --decompile --split-functions --il2cpp-offsets game_dump/
./destruct elf quazar_arm64 -o out --emit-pseudo --split-functions --regs-as-vars
```

Проход: 760 функций, 0 failed (761 граница из .eh_frame_hdr). Все 760
split-файлов проходят `clang -std=c11 -w -fsyntax-only` (и single-file
`quazar_arm64.decompiled.c` тоже).
- `local_8 = *(uint64_t*)((uintptr_t)var_4 + 0x28);`
- `tmp0 = arg1 - arg0;`
- `*(uint32_t*)((uintptr_t)arg0 + 4) = fvar_0;`
- `local_16 = ((uintptr_t)0xa2efa0);`
- сигнатура: `uint64_t sub_90f98c(uint64_t x0, ..., uint64_t x7) { ... }`
