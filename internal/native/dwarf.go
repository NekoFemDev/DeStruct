package native

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// ErrNoDWARF is returned when an ELF file has no usable DWARF debug
// information.
var ErrNoDWARF = errors.New("no DWARF debug info")

// DWARFParam is one source-level parameter recovered from DWARF.
type DWARFParam struct {
	Name string
	Type string
}

// DWARFLocal is one frame-relative local recovered from a simple
// DW_OP_fbreg location expression.
type DWARFLocal struct {
	Name        string
	Type        string
	FrameOffset int64
}

// DWARFFunction is one DW_TAG_subprogram with its parameters, simple
// frame-relative locals and declaration site.
type DWARFFunction struct {
	Name        string
	LinkageName string
	LowPC       uint64
	HighPC      uint64
	DeclFile    string
	DeclLine    int
	ReturnType  string
	Params      []DWARFParam
	Locals      []DWARFLocal

	localsByOffset map[int64]DWARFLocal
}

// DWARFLine is one decoded line-table row.
type DWARFLine struct {
	Address uint64
	File    string
	Line    int
}

// DWARFInfo is the function/line/local summary parsed from an ELF's
// DWARF sections.
type DWARFInfo struct {
	Functions []DWARFFunction // sorted by LowPC
	Lines     []DWARFLine     // sorted by Address
}

// LoadDWARF parses DWARF from path. It returns ErrNoDWARF when the file
// has no .debug_info section.
func LoadDWARF(path string) (*DWARFInfo, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if f.Section(".debug_info") == nil {
		return nil, ErrNoDWARF
	}
	d, err := f.DWARF()
	if err != nil {
		return nil, fmt.Errorf("parse DWARF: %w", err)
	}

	info := &DWARFInfo{}
	r := d.Reader()
	var cur *DWARFFunction
	var files []*dwarf.LineFile

	for {
		entry, err := r.Next()
		if err != nil {
			return nil, fmt.Errorf("read DWARF entry: %w", err)
		}
		if entry == nil {
			break
		}
		if entry.Tag == 0 {
			cur = nil
			continue
		}

		switch entry.Tag {
		case dwarf.TagCompileUnit:
			cur = nil
			files = nil
			lr, lineErr := d.LineReader(entry)
			if lineErr == nil && lr != nil {
				files = lr.Files()
				var le dwarf.LineEntry
				for {
					if err := lr.Next(&le); err != nil {
						if err == io.EOF {
							break
						}
						return nil, fmt.Errorf("read DWARF line table: %w", err)
					}
					if le.EndSequence || le.Line <= 0 {
						continue
					}
					file := ""
					if le.File != nil {
						file = le.File.Name
					}
					info.Lines = append(info.Lines, DWARFLine{
						Address: le.Address,
						File:    file,
						Line:    le.Line,
					})
				}
			}

		case dwarf.TagSubprogram:
			low, high := dwarfPC(entry)
			name := dwarfString(entry, dwarf.AttrName)
			linkage := dwarfString(entry, dwarf.AttrLinkageName)
			if name == "" {
				name = linkage
			}
			cur = &DWARFFunction{
				Name:           name,
				LinkageName:    linkage,
				LowPC:          low,
				HighPC:         high,
				ReturnType:     dwarfTypeName(d, entry),
				localsByOffset: make(map[int64]DWARFLocal),
			}
			if fileIdx, ok := entry.Val(dwarf.AttrDeclFile).(int64); ok && int(fileIdx) < len(files) && files[fileIdx] != nil {
				cur.DeclFile = files[fileIdx].Name
			}
			if line, ok := entry.Val(dwarf.AttrDeclLine).(int64); ok {
				cur.DeclLine = int(line)
			}
			if cur.Name != "" && cur.HighPC > cur.LowPC {
				info.Functions = append(info.Functions, *cur)
				// Keep cur pointing at the copy's own local map by
				// writing through the slice element below.
				cur = &info.Functions[len(info.Functions)-1]
			}

		case dwarf.TagFormalParameter:
			if cur == nil || cur.HighPC <= cur.LowPC {
				continue
			}
			if artificial, _ := entry.Val(dwarf.AttrArtificial).(bool); artificial {
				continue
			}
			name := dwarfString(entry, dwarf.AttrName)
			if name == "" {
				continue
			}
			cur.Params = append(cur.Params, DWARFParam{
				Name: name,
				Type: dwarfTypeName(d, entry),
			})

		case dwarf.TagVariable:
			if cur == nil || cur.HighPC <= cur.LowPC {
				continue
			}
			name := dwarfString(entry, dwarf.AttrName)
			if name == "" {
				continue
			}
			loc, ok := entry.Val(dwarf.AttrLocation).([]byte)
			if !ok {
				continue
			}
			off, ok := dwarfFrameOffset(loc)
			if !ok {
				continue
			}
			local := DWARFLocal{
				Name:        name,
				Type:        dwarfTypeName(d, entry),
				FrameOffset: off,
			}
			cur.Locals = append(cur.Locals, local)
			if cur.localsByOffset == nil {
				cur.localsByOffset = make(map[int64]DWARFLocal)
			}
			cur.localsByOffset[off] = local
		}
	}

	sort.SliceStable(info.Functions, func(i, j int) bool {
		if info.Functions[i].LowPC != info.Functions[j].LowPC {
			return info.Functions[i].LowPC < info.Functions[j].LowPC
		}
		return info.Functions[i].HighPC > info.Functions[j].HighPC
	})
	info.Functions = dedupeDWARFFunctions(info.Functions)

	sort.Slice(info.Lines, func(i, j int) bool {
		if info.Lines[i].Address != info.Lines[j].Address {
			return info.Lines[i].Address < info.Lines[j].Address
		}
		return info.Lines[i].Line < info.Lines[j].Line
	})

	return info, nil
}

// FunctionCandidates returns DWARF subprograms as address ranges for the
// pipeline's function-candidate merge.
func (d *DWARFInfo) FunctionCandidates() []DiscoveredFunction {
	if d == nil {
		return nil
	}
	out := make([]DiscoveredFunction, 0, len(d.Functions))
	for _, fn := range d.Functions {
		if fn.HighPC > fn.LowPC {
			out = append(out, DiscoveredFunction{Addr: fn.LowPC, Size: fn.HighPC - fn.LowPC})
		}
	}
	return out
}

// FunctionAt returns the DWARF function whose range contains addr. When
// ranges overlap (inlined copies), the innermost/smallest containing
// range wins.
func (d *DWARFInfo) FunctionAt(addr uint64) (*DWARFFunction, bool) {
	if d == nil || len(d.Functions) == 0 {
		return nil, false
	}
	i := sort.Search(len(d.Functions), func(i int) bool { return d.Functions[i].LowPC > addr })
	best := -1
	bestSize := ^uint64(0)
	for j := i - 1; j >= 0; j-- {
		fn := &d.Functions[j]
		if fn.HighPC <= addr {
			if fn.HighPC < addr && j < i-1 {
				break
			}
			continue
		}
		size := fn.HighPC - fn.LowPC
		if size < bestSize {
			best, bestSize = j, size
		}
	}
	if best < 0 {
		return nil, false
	}
	return &d.Functions[best], true
}

// LineAt returns the last decoded line-table row at or before addr.
func (d *DWARFInfo) LineAt(addr uint64) (DWARFLine, bool) {
	if d == nil || len(d.Lines) == 0 {
		return DWARFLine{}, false
	}
	i := sort.Search(len(d.Lines), func(i int) bool { return d.Lines[i].Address > addr })
	if i == 0 {
		return DWARFLine{}, false
	}
	return d.Lines[i-1], true
}

// LocalAt returns a local variable declared at frame offset off. Only
// simple DW_OP_fbreg locations are decoded.
func (f *DWARFFunction) LocalAt(off int64) (name, ctype string, ok bool) {
	if f == nil {
		return "", "", false
	}
	local, ok := f.localsByOffset[off]
	if !ok {
		return "", "", false
	}
	return local.Name, local.Type, true
}

// Source returns "file:line" for a decoded row.
func (l DWARFLine) Source() string {
	if l.File == "" {
		return ""
	}
	if l.Line > 0 {
		return fmt.Sprintf("%s:%d", l.File, l.Line)
	}
	return l.File
}

func dedupeDWARFFunctions(in []DWARFFunction) []DWARFFunction {
	if len(in) < 2 {
		return in
	}
	out := in[:0]
	for _, fn := range in {
		if len(out) > 0 {
			prev := &out[len(out)-1]
			if prev.LowPC == fn.LowPC {
				if fn.HighPC > prev.HighPC || (prev.Name == "" && fn.Name != "") {
					*prev = fn
				}
				continue
			}
		}
		out = append(out, fn)
	}
	return out
}

func dwarfPC(e *dwarf.Entry) (low, high uint64) {
	if v, ok := e.Val(dwarf.AttrLowpc).(uint64); ok {
		low = v
	}
	switch v := e.Val(dwarf.AttrHighpc).(type) {
	case uint64:
		high = v
	case int64:
		high = low + uint64(v)
	}
	return low, high
}

func dwarfString(e *dwarf.Entry, attr dwarf.Attr) string {
	v, _ := e.Val(attr).(string)
	return v
}

func dwarfTypeName(d *dwarf.Data, e *dwarf.Entry) string {
	off, ok := e.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return ""
	}
	t, err := d.Type(off)
	if err != nil || t == nil {
		return ""
	}
	return cTypeFromDWARF(t)
}

func cTypeFromDWARF(t dwarf.Type) string {
	switch v := t.(type) {
	case *dwarf.TypedefType:
		if c := cTypeFromDWARF(v.Type); c != "" {
			return c
		}
	case *dwarf.QualType:
		return cTypeFromDWARF(v.Type)
	case *dwarf.IntType:
		switch v.ByteSize {
		case 1:
			return "int8_t"
		case 2:
			return "int16_t"
		case 4:
			return "int32_t"
		case 8:
			return "int64_t"
		}
	case *dwarf.UintType:
		switch v.ByteSize {
		case 1:
			return "uint8_t"
		case 2:
			return "uint16_t"
		case 4:
			return "uint32_t"
		case 8:
			return "uint64_t"
		}
	case *dwarf.BoolType:
		return "uint8_t"
	case *dwarf.FloatType:
		switch v.ByteSize {
		case 4:
			return "float"
		case 8:
			return "double"
		}
	case *dwarf.PtrType:
		return "uintptr_t"
	case *dwarf.ArrayType:
		if c := cTypeFromDWARF(v.Type); c != "" {
			return c + "*"
		}
		return "uintptr_t"
	case *dwarf.StructType, *dwarf.EnumType:
		return "uint64_t"
	}
	return ""
}

// dwarfFrameOffset decodes a simple DW_OP_fbreg location expression -
// the common DWARF representation for stack locals.
func dwarfFrameOffset(loc []byte) (int64, bool) {
	const opFbreg = 0x91
	if len(loc) < 2 || loc[0] != opFbreg {
		return 0, false
	}
	off, n, ok := decodeSLEB128(loc[1:])
	if !ok || n == 0 {
		return 0, false
	}
	return off, true
}

func decodeSLEB128(b []byte) (int64, int, bool) {
	var result int64
	var shift uint
	for i, c := range b {
		result |= int64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			if shift < 64 && c&0x40 != 0 {
				result |= -1 << shift
			}
			return result, i + 1, true
		}
		if shift >= 64 {
			return 0, 0, false
		}
	}
	return 0, 0, false
}

// DWARFSummary is a compact description for `elf info`.
type DWARFSummary struct {
	Functions int
	Lines     int
	Locals    int
	Params    int
}

// Summary returns basic counts for diagnostics.
func (d *DWARFInfo) Summary() DWARFSummary {
	if d == nil {
		return DWARFSummary{}
	}
	s := DWARFSummary{Functions: len(d.Functions), Lines: len(d.Lines)}
	for _, fn := range d.Functions {
		s.Params += len(fn.Params)
		s.Locals += len(fn.Locals)
	}
	return s
}

// SourceName returns a sanitized short file name for comments.
func SourceName(file string) string {
	file = strings.ReplaceAll(file, "\\", "/")
	if i := strings.LastIndex(file, "/"); i >= 0 {
		return file[i+1:]
	}
	return file
}
