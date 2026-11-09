package arm64lift

// offsetdb.go loads an IL2CPP field-offset dump so the lifter and its
// IL2CPP output modes can translate the synthetic "field_<disp>" names
// a lifted memory access produces into real field names and byte
// offsets. Two on-disk shapes are supported, both generated from a
// dump.cs by the operator's tooling:
//
//   - offsets.json - a flat JSON array of classes, each with its full
//     name, TypeDefIndex and a list of fields (name / type / hex byte
//     offset). This is the canonical shape (game_dump/offsets.json).
//   - offset.hpp - the C++ header generated from the same data
//     (namespace blocks of "inline constexpr" offset accessors with
//     the field declaration in a trailing comment). Parsed as a
//     fallback so a header copy works without the JSON.
//
// All offsets are byte offsets from the IL2CPP managed object's own
// address, i.e. they already include the 16-byte object header
// (klass* + monitor*) that precedes the first instance field - which
// is exactly the displacement an IL2CPP-compiled "ldr xN, [xM, #off]"
// carries, so a FieldOffset lookup keyed by (type, field) matches the
// displacement the lifter saw without any extra adjustment.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// FieldRef describes one field of an IL2CPP class as recovered from an
// offset dump. Owner is the field's full class name, Index its
// metadata field index within the owning TypeDef (-1 when the dump
// didn't carry indices, e.g. a plain offsets.json), and Offset its
// byte offset from the object base (header included).
type FieldRef struct {
	Owner  string
	Name   string
	Type   string
	Offset uint64
	Index  int
}

// ClassRef describes one IL2CPP class from an offset dump.
type ClassRef struct {
	Name         string
	Namespace    string
	TypeDefIndex int
	Fields       []FieldRef
}

type il2cppClass struct {
	Name         string
	Namespace    string
	TypeDefIndex int
	Fields       []FieldRef
}

// OffsetDB is an in-memory field-offset database loaded from
// offsets.json or offset.hpp. Lookups are by full class name (the
// dump's own dotted form, e.g. "Axlebolt.Bolt.Protobuf.PlayerAchievement");
// a bare class name is also accepted when it's unambiguous.
type OffsetDB struct {
	classes  []*il2cppClass
	byName   map[string]*il2cppClass
	byTD     map[int]*il2cppClass
	byShort  map[string][]*il2cppClass
	byOffset map[uint64][]FieldRef
}

// NewOffsetDB returns an empty database; useful for tests and for
// callers that add classes programmatically.
func NewOffsetDB() *OffsetDB {
	return &OffsetDB{
		byName:   make(map[string]*il2cppClass),
		byTD:     make(map[int]*il2cppClass),
		byShort:  make(map[string][]*il2cppClass),
		byOffset: make(map[uint64][]FieldRef),
	}
}

func (db *OffsetDB) addClass(c *il2cppClass) {
	db.classes = append(db.classes, c)
	db.byName[c.Name] = c
	for _, f := range c.Fields {
		db.byOffset[f.Offset] = append(db.byOffset[f.Offset], f)
	}
	if c.TypeDefIndex >= 0 {
		db.byTD[c.TypeDefIndex] = c
	}
	short := c.Name
	if idx := strings.LastIndex(short, "."); idx >= 0 {
		short = short[idx+1:]
	}
	db.byShort[short] = append(db.byShort[short], c)
}

// Count returns the number of classes loaded.
func (db *OffsetDB) Count() int { return len(db.classes) }

// Classes returns every class in load order. The returned slice is a
// copy; mutating it does not affect the database (the FieldRef slices
// themselves are shared and must be treated as read-only).
func (db *OffsetDB) Classes() []ClassRef {
	out := make([]ClassRef, 0, len(db.classes))
	for _, c := range db.classes {
		out = append(out, ClassRef{
			Name:         c.Name,
			Namespace:    c.Namespace,
			TypeDefIndex: c.TypeDefIndex,
			Fields:       c.Fields,
		})
	}
	return out
}

// lookupClass resolves a class by its full dump name, or - when the
// name is a bare short name - by its unique last path component.
func (db *OffsetDB) lookupClass(typeName string) *il2cppClass {
	if c, ok := db.byName[typeName]; ok {
		return c
	}
	if matches := db.byShort[typeName]; len(matches) == 1 {
		return matches[0]
	}
	return nil
}

// ClassByTypeDefIndex returns the class with the given metadata
// TypeDefIndex.
func (db *OffsetDB) ClassByTypeDefIndex(td int) (ClassRef, bool) {
	c, ok := db.byTD[td]
	if !ok {
		return ClassRef{}, false
	}
	return ClassRef{Name: c.Name, Namespace: c.Namespace, TypeDefIndex: c.TypeDefIndex, Fields: c.Fields}, true
}

// FieldOffset returns the byte offset of the field whose metadata field
// index within typeName's TypeDef is fieldIndex. Only databases that
// actually carry field indices (loaded from a maps/ TSV directory via
// LoadOffsetDBMaps, or a JSON dump that includes "index" keys) can
// answer this; a plain offsets.json has no indices and returns false.
func (db *OffsetDB) FieldOffset(typeName string, fieldIndex int) (uint64, bool) {
	c := db.lookupClass(typeName)
	if c == nil {
		return 0, false
	}
	for _, f := range c.Fields {
		if f.Index == fieldIndex && f.Index >= 0 {
			return f.Offset, true
		}
	}
	return 0, false
}

// FieldOffsetByName returns the byte offset of the named field of
// typeName.
func (db *OffsetDB) FieldOffsetByName(typeName, fieldName string) (uint64, bool) {
	c := db.lookupClass(typeName)
	if c == nil {
		return 0, false
	}
	for _, f := range c.Fields {
		if f.Name == fieldName {
			return f.Offset, true
		}
	}
	return 0, false
}

// FieldAtOffset returns the field of typeName whose byte offset is
// exactly offset - the reverse of FieldOffsetByName, used by the
// lifter to name a displacement-derived "field_<disp>" access.
func (db *OffsetDB) FieldAtOffset(typeName string, offset uint64) (FieldRef, bool) {
	c := db.lookupClass(typeName)
	if c == nil {
		return FieldRef{}, false
	}
	for _, f := range c.Fields {
		if f.Offset == offset {
			return f, true
		}
	}
	return FieldRef{}, false
}

// FieldsAtOffset returns every field in the database whose byte offset
// from the object base is exactly offset, in load order. Offset-only
// lookups are inherently ambiguous on a full IL2CPP dump (0x10 is used
// by thousands of classes), so this is the raw candidate set; use
// FieldAtOffsetAny for a deterministic best-effort choice.
func (db *OffsetDB) FieldsAtOffset(offset uint64) []FieldRef {
	return append([]FieldRef(nil), db.byOffset[offset]...)
}

// FieldCountAtOffset is the allocation-free candidate count used by the
// renderer when it only needs to know whether an offset lookup is
// ambiguous.
func (db *OffsetDB) FieldCountAtOffset(offset uint64) int {
	return len(db.byOffset[offset])
}

// FieldAtOffsetAny returns a deterministic best-effort field for an
// offset-only lookup. When type information is unavailable this is the
// only possible answer: candidates are ranked by access-width
// compatibility, then by not being the generic protobuf
// "_unknownFields" member, then by non-compiler-generated owner names,
// and finally by load order. Callers that know the class should use
// FieldAtOffset(typeName, offset) instead.
func (db *OffsetDB) FieldAtOffsetAny(offset uint64, width int) (FieldRef, bool) {
	cands := db.byOffset[offset]
	if len(cands) == 0 {
		return FieldRef{}, false
	}
	best := -1
	bestScore := 0
	for i, f := range cands {
		score := 0
		if width > 0 && fieldTypeWidth(f.Type) == width {
			score += 100
		}
		if f.Name != "_unknownFields" {
			score += 20
		}
		if !compilerGeneratedName(f.Owner) {
			score += 10
		}
		if strings.Contains(f.Name, "BackingField") {
			score += 5
		}
		if best == -1 || score > bestScore {
			best, bestScore = i, score
		}
	}
	return cands[best], true
}

// fieldTypeWidth maps a dump type name to its in-memory width. Unknown
// (reference) types are IL2CPP object pointers, i.e. 8 bytes.
func fieldTypeWidth(t string) int {
	switch t {
	case "bool", "byte", "sbyte":
		return 1
	case "char", "short", "ushort":
		return 2
	case "int", "uint", "float":
		return 4
	case "long", "ulong", "double", "string", "object":
		return 8
	default:
		return 8
	}
}

// compilerGeneratedName reports whether a class name looks like a
// compiler-generated closure/display class, which is usually a poor
// offset-comment candidate compared with a real data class.
func compilerGeneratedName(name string) bool {
	return strings.Contains(name, "<>c") ||
		strings.Contains(name, "DisplayClass") ||
		strings.HasPrefix(name, "__")
}

// TypeNames returns every loaded class's full name, in load order.
func (db *OffsetDB) TypeNames() []string {
	out := make([]string, 0, len(db.classes))
	for _, c := range db.classes {
		out = append(out, c.Name)
	}
	return out
}

// LoadOffsetDB loads an offset dump, choosing the parser by extension
// (.json / .hpp / .h) and falling back to content sniffing (a leading
// "{" means JSON, anything else is treated as the header form).
func LoadOffsetDB(path string) (*OffsetDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	switch strings.ToLower(fileExt(path)) {
	case ".json":
		return LoadOffsetDBFromJSON(f)
	case ".hpp", ".h", ".hxx":
		return LoadOffsetDBFromHPP(f)
	}

	// Content sniff: skip leading whitespace, "{" is JSON.
	br := bufio.NewReader(f)
	for {
		b, err := br.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("offset dump %s: empty file", path)
		}
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			continue
		}
		if b == '{' {
			return LoadOffsetDBFromJSON(io.MultiReader(strings.NewReader("{"), br))
		}
		return LoadOffsetDBFromHPP(io.MultiReader(strings.NewReader(string(b)), br))
	}
}

func fileExt(path string) string {
	idx := strings.LastIndex(path, ".")
	if idx < 0 {
		return ""
	}
	return path[idx:]
}

// offsetJSONDoc mirrors the offsets.json schema.
type offsetJSONDoc struct {
	Classes []offsetJSONClass `json:"classes"`
}

type offsetJSONClass struct {
	Name      string            `json:"name"`
	TypeDef   int               `json:"td"`
	Namespace string            `json:"namespace"`
	Fields    []offsetJSONField `json:"fields"`
}

type offsetJSONField struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Offset string `json:"offset"`
	Index  *int   `json:"index"`
}

// LoadOffsetDBFromJSON parses the offsets.json shape:
//
//	{"classes":[{"name":"A.B.C","td":9,"namespace":"C",
//	 "fields":[{"name":"id_","type":"string","offset":"0x18"}]}]}
func LoadOffsetDBFromJSON(r io.Reader) (*OffsetDB, error) {
	var doc offsetJSONDoc
	dec := json.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("offsets.json: %w", err)
	}
	db := NewOffsetDB()
	for i := range doc.Classes {
		jc := &doc.Classes[i]
		if jc.Name == "" {
			continue
		}
		cls := &il2cppClass{
			Name:         jc.Name,
			Namespace:    jc.Namespace,
			TypeDefIndex: jc.TypeDef,
		}
		for j := range jc.Fields {
			jf := &jc.Fields[j]
			off, ok := parseHexOffset(jf.Offset)
			if !ok {
				continue
			}
			idx := -1
			if jf.Index != nil {
				idx = *jf.Index
			}
			cls.Fields = append(cls.Fields, FieldRef{
				Owner:  jc.Name,
				Name:   jf.Name,
				Type:   jf.Type,
				Offset: off,
				Index:  idx,
			})
		}
		db.addClass(cls)
	}
	return db, nil
}

// parseHexOffset parses a dump offset string ("0x18" hex, "24"
// decimal). Negative offsets (static/const fields with no instance
// slot) are reported as not-ok so they never enter the layout.
func parseHexOffset(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "-") {
		return 0, false
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 64)
		return v, err == nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

// hppDeclRe matches the generated accessor lines of offset.hpp:
//
//	inline constexpr ::std::uintptr_t id_() { return 0x18; } // string id_
var hppDeclRe = regexp.MustCompile(`^\s*inline\s+constexpr\s+\S+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{\s*return\s+(0x[0-9A-Fa-f]+)\s*;\s*\}\s*(?://\s*(.*))?$`)

// hppClassRe matches the generated class banner comment:
//
//	// Axlebolt.Bolt.Protobuf.AchievementDefinition (TypeDefIndex: 9)
var hppClassRe = regexp.MustCompile(`^\s*//\s*([A-Za-z_][A-Za-z0-9_.<>]*)\s*\(TypeDefIndex:\s*(-?\d+)\)\s*$`)

// LoadOffsetDBFromHPP parses the offset.hpp C++ header shape. Only the
// generated structure is understood (class banner comments, namespace
// blocks, accessor lines); anything else is ignored so a hand-edited
// header with extra includes/comments still loads.
func LoadOffsetDBFromHPP(r io.Reader) (*OffsetDB, error) {
	db := NewOffsetDB()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var cls *il2cppClass
	namespace := ""
	for sc.Scan() {
		line := sc.Text()
		if m := hppClassRe.FindStringSubmatch(line); m != nil {
			td, _ := strconv.Atoi(m[2])
			if cls != nil {
				db.addClass(cls)
			}
			cls = &il2cppClass{Name: m[1], Namespace: namespace, TypeDefIndex: td}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "namespace ") && strings.HasSuffix(strings.TrimSpace(line), "{") {
			namespace = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line), "namespace "), "{")
			namespace = strings.TrimSpace(namespace)
			continue
		}
		m := hppDeclRe.FindStringSubmatch(line)
		if m == nil || cls == nil {
			continue
		}
		off, ok := parseHexOffset(m[2])
		if !ok {
			continue
		}
		name, typ := m[1], ""
		if m[3] != "" {
			// Trailing comment is "<type> <fieldname>"; the field name
			// is the last whitespace-separated token, the type is
			// everything before it (kept as the dump spelled it).
			if idx := strings.LastIndex(m[3], " "); idx >= 0 {
				typ = strings.TrimSpace(m[3][:idx])
				name = strings.TrimSpace(m[3][idx+1:])
			}
		}
		cls.Fields = append(cls.Fields, FieldRef{
			Owner:  cls.Name,
			Name:   name,
			Type:   typ,
			Offset: off,
			Index:  -1,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("offset.hpp: %w", err)
	}
	if cls != nil {
		db.addClass(cls)
	}
	return db, nil
}
