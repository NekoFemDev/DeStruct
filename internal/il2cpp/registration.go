package il2cpp

import (
	"context"
	"fmt"
)

// Layouts for the registration structures that live in libil2cpp.so.

var layoutCodeRegistration = structLayout{fields: []structField{
	pv("methodPointersCount", 8, 0, 24.1), pv("methodPointers", 8, 0, 24.1),
	pv("delegateWrappersFromNativeToManagedCount", 8, 0, 21), pv("delegateWrappersFromNativeToManaged", 8, 0, 21),
	pv("reversePInvokeWrapperCount", 8, 22, 0), pv("reversePInvokeWrappers", 8, 22, 0),
	pv("delegateWrappersFromManagedToNativeCount", 8, 0, 22), pv("delegateWrappersFromManagedToNative", 8, 0, 22),
	pv("marshalingFunctionsCount", 8, 0, 22), pv("marshalingFunctions", 8, 0, 22),
	pv("ccwMarshalingFunctionsCount", 8, 21, 22), pv("ccwMarshalingFunctions", 8, 21, 22),
	p("genericMethodPointersCount", 8), p("genericMethodPointers", 8),
	pv("genericAdjustorThunks", 8, 24.5, 24.5), pv("genericAdjustorThunks", 8, 27.1, 0),
	p("invokerPointersCount", 8), p("invokerPointers", 8),
	pv("customAttributeCount", 8, 0, 24.5), pv("customAttributeGenerators", 8, 0, 24.5),
	pv("guidCount", 8, 21, 22), pv("guids", 8, 21, 22),
	pv("unresolvedVirtualCallCount", 8, 22, 0), pv("unresolvedVirtualCallPointers", 8, 22, 0),
	pv("unresolvedInstanceCallPointers", 8, 29.1, 0), pv("unresolvedStaticCallPointers", 8, 29.1, 0),
	pv("interopDataCount", 8, 23, 0), pv("interopData", 8, 23, 0),
	pv("windowsRuntimeFactoryCount", 8, 24.3, 0), pv("windowsRuntimeFactoryTable", 8, 24.3, 0),
	pv("codeGenModulesCount", 8, 24.2, 0), pv("codeGenModules", 8, 24.2, 0),
}}

var layoutCodeGenModule = structLayout{fields: []structField{
	p("moduleName", 8),
	p("methodPointerCount", 8), p("methodPointers", 8),
	pv("adjustorThunkCount", 8, 24.5, 24.5), pv("adjustorThunks", 8, 24.5, 24.5),
	pv("adjustorThunkCount", 8, 27.1, 0), pv("adjustorThunks", 8, 27.1, 0),
	p("invokerIndices", 8),
	p("reversePInvokeWrapperCount", 8), p("reversePInvokeWrapperIndices", 8),
	p("rgctxRangesCount", 8), p("rgctxRanges", 8),
	p("rgctxsCount", 8), p("rgctxs", 8),
	p("debuggerMetadata", 8),
	pv("customAttributeCacheGenerator", 8, 27, 27.2),
	pv("moduleInitializer", 8, 27, 0),
	pv("staticConstructorTypeIndices", 8, 27, 0),
	pv("metadataRegistration", 8, 27, 0),
	pv("codeRegistaration", 8, 27, 0),
}}

var layoutMetadataRegistration = structLayout{fields: []structField{
	p("genericClassesCount", 8), p("genericClasses", 8),
	p("genericInstsCount", 8), p("genericInsts", 8),
	p("genericMethodTableCount", 8), p("genericMethodTable", 8),
	p("typesCount", 8), p("types", 8),
	p("methodSpecsCount", 8), p("methodSpecs", 8),
	pv("methodReferencesCount", 8, 0, 16), pv("methodReferences", 8, 0, 16),
	p("fieldOffsetsCount", 8), p("fieldOffsets", 8),
	p("typeDefinitionsSizesCount", 8), p("typeDefinitionsSizes", 8),
	pv("metadataUsagesCount", 8, 19, 0), pv("metadataUsages", 8, 19, 0),
}}

var layoutIl2CppType = structLayout{fields: []structField{
	p("datapoint", 8), p("bits", 4),
}}

var layoutGenericClass = structLayout{fields: []structField{
	pv("typeDefinitionIndex", 8, 0, 24.5),
	pv("type", 8, 27, 0),
	s("context", &structLayout{fields: []structField{p("class_inst", 8), p("method_inst", 8)}}, 0, 0),
	p("cached_class", 8),
}}

var layoutGenericInst = structLayout{fields: []structField{
	p("type_argc", 8), p("type_argv", 8),
}}

var layoutMethodSpec = structLayout{fields: []structField{
	p("methodDefinitionIndex", 4), p("classIndexIndex", 4), p("methodIndexIndex", 4),
}}

var layoutGenericMethodFunctions = structLayout{fields: []structField{
	p("genericMethodIndex", 4),
	s("indices", &structLayout{fields: []structField{
		p("methodIndex", 4), p("invokerIndex", 4),
		pv("adjustorThunk", 4, 24.5, 24.5), pv("adjustorThunk", 4, 27.1, 0),
	}}, 0, 0),
}}

// Il2CppType mirrors the runtime type record (datapoint + packed bits).
type Il2CppType struct {
	DataPoint uint64
	Bits      uint32
	Version   float64

	Attrs     uint32
	TypeEnum  uint8
	NumMods   uint32
	ByRef     uint32
	Pinned    uint32
	ValueType uint32
}

func newIl2CppType(dataPoint uint64, bits uint32, version float64) *Il2CppType {
	t := &Il2CppType{DataPoint: dataPoint, Bits: bits, Version: version}
	t.Attrs = bits & 0xffff
	t.TypeEnum = uint8((bits >> 16) & 0xff)
	// Note: the reference dump was produced by a reader using the
	// pre-27.2 bit layout (byref at bit 30, pinned at bit 31), so ref/out
	// parameter modifiers are not emitted for v29+ metadata. Keep that
	// layout for byte-for-byte parity; bit 29 is "pinned" there too.
	t.NumMods = (bits >> 24) & 0x3f
	t.ByRef = (bits >> 30) & 1
	t.Pinned = bits >> 31
	return t
}

// Il2CppMethodSpec mirrors the runtime generic method spec record.
type Il2CppMethodSpec struct {
	MethodDefinitionIndex int32
	ClassIndexIndex       int32
	MethodIndexIndex      int32
}

type rgctxDefinition struct {
	typ   uint64
	index int64
}

// IL2CPP owns the parsed registrations and resolved metadata lookups.
type IL2CPP struct {
	ELF                 *elfFile
	Version             float64
	metadata            *Metadata
	PointerSize         uint64
	metadataUsagesCount int64
	pointerInExec       bool

	CodeRegistration     uint64
	MetadataRegistration uint64

	MethodPointers                []uint64
	GenericMethodPointers         []uint64
	InvokerPointers               []uint64
	CustomAttributeGenerators     []uint64
	ReversePInvokeWrappers        []uint64
	UnresolvedVirtualCallPointers []uint64
	FieldOffsets                  []uint64
	Types                         []*Il2CppType
	typeDic                       map[uint64]*Il2CppType
	MetadataUsages                []uint64

	genericMethodTable      []genericMethodEntry
	GenericInstPointers     []uint64
	GenericInsts            []*il2CppGenericInst
	MethodSpecs             []Il2CppMethodSpec
	MethodDefMethodSpecs    map[int][]int
	MethodSpecGenericPtrs   []uint64
	fieldOffsetsArePointers bool

	CodeGenModules              map[string]*codeGenModule
	CodeGenModuleMethodPointers map[string][]uint64
	RGCTXsDictionary            map[string]map[uint32][]rgctxDefinition

	// Fields read by the AutoPlusInit version heuristics.
	crGenericMethodPointersCount uint64
	crReversePInvokeWrapperCount uint64
	crInteropDataCount           uint64
}

type genericMethodEntry struct {
	genericMethodIndex int32
	methodIndex        int32
	invokerIndex       int32
}

type il2CppGenericInst struct {
	TypeArgc int64
	TypeArgv uint64
}

type codeGenModule struct {
	Name                          string
	Address                       uint64
	MethodPointerCount            int64
	MethodPointers                uint64
	InvokerIndices                uint64
	RGCTXs                        uint64
	RGCTXsCount                   int64
	RGCTXRanges                   uint64
	RGCTXRangesCount              int64
	CustomAttributeCacheGenerator uint64
}

func (ic *IL2CPP) mapVATR(addr uint64) (uint64, bool) { return ic.ELF.mapVATR(addr) }

func (ic *IL2CPP) readU64(addr uint64) uint64 { return ic.ELF.readU64(addr) }
func (ic *IL2CPP) readU32(addr uint64) uint32 { return ic.ELF.readU32(addr) }
func (ic *IL2CPP) readI32(addr uint64) int32  { return int32(ic.ELF.readU32(addr)) }

func (ic *IL2CPP) readU64s(addr uint64, count int64) []uint64 {
	return ic.readU64sContext(context.Background(), addr, count)
}

// readU64sContext is readU64s with cancellation: the word copy polls ctx
// every 4096 words and returns nil once cancelled. Callers that hold a ctx
// re-check ctx.Err() afterwards so cancellation is not mistaken for a
// truncated table.
func (ic *IL2CPP) readU64sContext(ctx context.Context, addr uint64, count int64) []uint64 {
	if count <= 0 || count > 1<<28 {
		return nil
	}
	off, ok := ic.mapVATR(addr)
	if !ok {
		return nil
	}
	start, _, ok := recordRange(ic.ELF.data, off, uint64(count), 8)
	if !ok {
		return nil
	}
	out := make([]uint64, count)
	for i := int64(0); i < count; i++ {
		if i&0xFFF == 0 && ctx.Err() != nil {
			return nil
		}
		out[i] = ic.ELF.u64(start + int(i)*8)
	}
	return out
}

// readU64sStrict reads a pointer array and reports false when any part
// of it falls outside the mapped file, matching the exception the C#
// reader raises for an unmappable array.
func (ic *IL2CPP) readU64sStrict(addr uint64, count int64) ([]uint64, bool) {
	return ic.readU64sStrictContext(context.Background(), addr, count)
}

// readU64sStrictContext is readU64sStrict with cancellation.
func (ic *IL2CPP) readU64sStrictContext(ctx context.Context, addr uint64, count int64) ([]uint64, bool) {
	if count < 0 || count > 1<<28 {
		return nil, false
	}
	off, ok := ic.mapVATR(addr)
	if !ok {
		return nil, false
	}
	start, _, ok := recordRange(ic.ELF.data, off, uint64(count), 8)
	if !ok {
		return nil, false
	}
	out := make([]uint64, count)
	for i := int64(0); i < count; i++ {
		if i&0xFFF == 0 && ctx.Err() != nil {
			return nil, false
		}
		out[i] = ic.ELF.u64(start + int(i)*8)
	}
	return out, true
}

func (ic *IL2CPP) readRecord(addr uint64, l *structLayout) ([]byte, bool) {
	off, ok := ic.mapVATR(addr)
	if !ok {
		return nil, false
	}
	n := l.size(ic.Version)
	start, end, ok := byteRange(ic.ELF.data, off, uint64(n))
	if !ok {
		return nil, false
	}
	return ic.ELF.data[start:end], true
}

// findCodeRegistration ports SectionHelper.FindCodeRegistration for ELF.
// Cancellation is reported as 0; the caller re-checks ctx.Err() to
// distinguish it from "not found".
func (ic *IL2CPP) findCodeRegistration(ctx context.Context, imageCount int) uint64 {
	if ic.Version >= 24.2 {
		cr := ic.findCodeRegistration2019(ctx, ic.ELF.execSections(), imageCount)
		if ctx.Err() != nil {
			return 0
		}
		if cr == 0 {
			cr = ic.findCodeRegistration2019(ctx, ic.ELF.dataSections(), imageCount)
		} else {
			ic.pointerInExec = true
		}
		return cr
	}
	return ic.findCodeRegistrationOld(ctx)
}

func (ic *IL2CPP) findCodeRegistrationOld(ctx context.Context) uint64 {
	methodCount := 0
	for i := range ic.metadata.methodDefs {
		if i&0xFFF == 0 && ctx.Err() != nil {
			return 0
		}
		if ic.metadata.methodDefs[i].has("methodIndex") {
			if ic.metadata.methodDefs[i].i32("methodIndex") >= 0 {
				methodCount++
			}
		} else {
			methodCount++
		}
	}
	for _, sec := range ic.ELF.dataSections() {
		if ctx.Err() != nil {
			return 0
		}
		pos := sec.offset
		scanned := uint64(0)
		for pos+8 <= sec.offsetEnd && pos+8 <= uint64(len(ic.ELF.data)) {
			scanned++
			if scanned%512 == 0 && ctx.Err() != nil { // every 4096 bytes
				return 0
			}
			if pos > uint64(len(ic.ELF.data))-16 {
				break
			}
			if int64(ic.ELF.u64(int(pos))) == int64(methodCount) {
				ptr := ic.ELF.u64(int(pos) + 8)
				if po, ok := ic.mapVATR(ptr); ok && ic.inDataRange(po) {
					pointers, ok := ic.readU64sStrictContext(ctx, ptr, int64(methodCount))
					if ok && ic.allInExecVA(ctx, pointers) {
						return pos - sec.offset + sec.address
					}
				}
			}
			pos += 8
		}
	}
	return 0
}

// featureBytes is the "mscorlib.dll\0" literal used by Il2CppDumper to
// locate the code registration through the generated module names.
var featureBytes = []byte("mscorlib.dll\x00")

func (ic *IL2CPP) findCodeRegistration2019(ctx context.Context, sections []searchSection, imageCount int) uint64 {
	// Level 1: find pointers to the mscorlib.dll string literal.
	level1Targets := make(map[uint64]struct{})
	type occurrence struct {
		va      uint64
		refs    []uint64
		section int
	}
	var occurrences []occurrence
	for si, sec := range sections {
		if ctx.Err() != nil {
			return 0
		}
		start, end, ok := byteRange(ic.ELF.data, sec.offset, sec.offsetEnd-sec.offset)
		if !ok {
			continue
		}
		buff := ic.ELF.data[start:end]
		for idx := 0; ; {
			j := indexBytesContext(ctx, buff[idx:], featureBytes)
			if j < 0 {
				break
			}
			idx += j
			va := uint64(idx) + sec.address
			level1Targets[va] = struct{}{}
			occurrences = append(occurrences, occurrence{va: va, section: si})
			idx++
		}
	}
	if ctx.Err() != nil {
		return 0
	}
	if len(occurrences) == 0 {
		return 0
	}
	refs1 := ic.ELF.findReferences(ctx, level1Targets)
	if ctx.Err() != nil {
		return 0
	}

	// Level 2: pointers to the moduleName slots found above.
	level2Targets := make(map[uint64]struct{})
	for _, o := range occurrences {
		if ctx.Err() != nil {
			return 0
		}
		for _, r := range refs1[o.va] {
			level2Targets[r] = struct{}{}
		}
	}
	if len(level2Targets) == 0 {
		return 0
	}
	refs2 := ic.ELF.findReferences(ctx, level2Targets)
	if ctx.Err() != nil {
		return 0
	}

	// Level 3: the codeGenModules array element holding the address of
	// (moduleNameSlot - i*ptr) for some module index i.
	level3Targets := make(map[uint64]struct{})
	for _, refs := range refs2 {
		if ctx.Err() != nil {
			return 0
		}
		for _, refva2 := range refs {
			for i := imageCount - 1; i >= 0; i-- {
				if uint64(i) > refva2/8 {
					continue
				}
				addr := refva2 - uint64(i)*8
				if addr != 0 {
					level3Targets[addr] = struct{}{}
				}
			}
		}
	}
	refs3 := ic.ELF.findReferences(ctx, level3Targets)
	if ctx.Err() != nil {
		return 0
	}

	for _, o := range occurrences {
		if ctx.Err() != nil {
			return 0
		}
		for _, refva := range refs1[o.va] {
			if ctx.Err() != nil {
				return 0
			}
			for _, refva2 := range refs2[refva] {
				if ctx.Err() != nil {
					return 0
				}
				for i := imageCount - 1; i >= 0; i-- {
					if uint64(i) > refva2/8 {
						continue
					}
					addr := refva2 - uint64(i)*8
					for _, refva3 := range refs3[addr] {
						if refva3 < 8 {
							continue
						}
						countOff, ok := ic.mapVATR(refva3 - 8)
						if !ok {
							continue
						}
						if int64(ic.ELF.u64(int(countOff))) == int64(imageCount) {
							if ic.Version >= 29 {
								if refva3 >= 8*14 {
									return refva3 - 8*14
								}
							}
							if refva3 >= 8*13 {
								return refva3 - 8*13
							}
						}
					}
				}
			}
		}
	}
	return 0
}

func (ic *IL2CPP) findMetadataRegistration(ctx context.Context, typeDefsCount int64, imageCount int) uint64 {
	if ic.Version < 19 {
		return 0
	}
	if ic.Version >= 27 {
		return ic.findMetadataRegistrationV21(ctx, typeDefsCount)
	}
	return ic.findMetadataRegistrationOld(ctx, typeDefsCount)
}

func (ic *IL2CPP) findMetadataRegistrationV21(ctx context.Context, typeDefsCount int64) uint64 {
	for _, sec := range ic.ELF.dataSections() {
		if ctx.Err() != nil {
			return 0
		}
		end := sec.offsetEnd
		if end > uint64(len(ic.ELF.data)) {
			end = uint64(len(ic.ELF.data))
		}
		if end < 8 {
			continue
		}
		scanned := uint64(0)
		for pos := sec.offset; pos+8 <= end; pos += 8 {
			scanned++
			if scanned%512 == 0 && ctx.Err() != nil { // every 4096 bytes
				return 0
			}
			if int64(ic.ELF.u64(int(pos))) != typeDefsCount {
				continue
			}
			if pos+32 > end {
				break
			}
			if int64(ic.ELF.u64(int(pos)+16)) != typeDefsCount {
				continue
			}
			ptr := ic.ELF.u64(int(pos) + 24)
			fileOff, ok := ic.mapVATR(ptr)
			if !ok || !ic.inDataRange(fileOff) {
				continue
			}
			pointers, ok := ic.readU64sStrictContext(ctx, ptr, typeDefsCount)
			if !ok {
				continue
			}
			check := func(p []uint64) bool { return ic.allInDataVA(ctx, p) }
			if ic.pointerInExec {
				check = func(p []uint64) bool { return ic.allInExecVA(ctx, p) }
			}
			if check(pointers) && pos-sec.offset+sec.address >= 8*10 {
				return pos - sec.offset + sec.address - 8*10
			}
		}
	}
	return 0
}

func (ic *IL2CPP) findMetadataRegistrationOld(ctx context.Context, typeDefsCount int64) uint64 {
	for _, sec := range ic.ELF.dataSections() {
		if ctx.Err() != nil {
			return 0
		}
		end := sec.offsetEnd
		if end > uint64(len(ic.ELF.data)) {
			end = uint64(len(ic.ELF.data))
		}
		if end < 8 {
			continue
		}
		scanned := uint64(0)
		for pos := sec.offset; pos+8 <= end; pos += 8 {
			scanned++
			if scanned%512 == 0 && ctx.Err() != nil { // every 4096 bytes
				return 0
			}
			if int64(ic.ELF.u64(int(pos))) != typeDefsCount {
				continue
			}
			if pos+32 > end {
				break
			}
			ptr := ic.ELF.u64(int(pos) + 24)
			fileOff, ok := ic.mapVATR(ptr)
			if !ok || !ic.inDataRange(fileOff) {
				continue
			}
			pointers, valid := ic.readU64sStrictContext(ctx, ptr, ic.metadataUsagesCount)
			if valid && ic.allInDataVA(ctx, pointers) && pos-sec.offset+sec.address >= 8*12 {
				return pos - sec.offset + sec.address - 8*12
			}
		}
	}
	return 0
}

func (ic *IL2CPP) inDataRange(fileOff uint64) bool {
	for _, sec := range ic.ELF.dataSections() {
		if fileOff >= sec.offset && fileOff <= sec.offsetEnd {
			return true
		}
	}
	return false
}

func (ic *IL2CPP) allInDataVA(ctx context.Context, pointers []uint64) bool {
	for i, p := range pointers {
		if i&0xFFF == 0 && ctx.Err() != nil {
			return false
		}
		found := false
		for _, sec := range ic.ELF.dataSections() {
			if p >= sec.address && p <= sec.addressEnd {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (ic *IL2CPP) allInExecVA(ctx context.Context, pointers []uint64) bool {
	for i, p := range pointers {
		if i&0xFFF == 0 && ctx.Err() != nil {
			return false
		}
		found := false
		for _, sec := range ic.ELF.execSections() {
			if p >= sec.address && p <= sec.addressEnd {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func indexBytes(haystack, needle []byte) int {
	return indexBytesContext(context.Background(), haystack, needle)
}

// indexBytesContext is indexBytes with cancellation: the byte scan polls ctx
// every 4096 offsets and reports "not found" once cancelled; callers hold a
// ctx and re-check ctx.Err() before continuing.
func indexBytesContext(ctx context.Context, haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if i&0xFFF == 0 && ctx.Err() != nil {
			return -1
		}
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// autoPlusInit ports Il2Cpp.AutoPlusInit: the version heuristics that
// distinguish adjacent metadata struct layouts sharing a version number.
func (ic *IL2CPP) autoPlusInit(codeRegistration uint64) (uint64, error) {
	const limit = 0x50000
	if codeRegistration == 0 {
		return 0, nil
	}
	if ic.Version >= 24.2 {
		if !ic.readCRFields(codeRegistration) {
			return codeRegistration, nil
		}
		if ic.Version == 31 {
			if ic.crGenericMethodPointersCount > limit {
				codeRegistration -= ic.PointerSize * 2
			} else {
				ic.Version = 29
			}
		}
		if ic.Version == 29 {
			if ic.crGenericMethodPointersCount > limit {
				ic.Version = 29.1
				codeRegistration -= ic.PointerSize * 2
			}
		}
		if ic.Version == 27 {
			if ic.crReversePInvokeWrapperCount > limit {
				ic.Version = 27.1
				codeRegistration -= ic.PointerSize
			}
		}
		if ic.Version == 24.4 {
			codeRegistration -= ic.PointerSize * 2
			if ic.crReversePInvokeWrapperCount > limit {
				ic.Version = 24.5
				codeRegistration -= ic.PointerSize
			}
		}
		if ic.Version == 24.2 {
			if ic.crInteropDataCount == 0 {
				ic.Version = 24.3
				codeRegistration -= ic.PointerSize * 2
			}
		}
	}
	return codeRegistration, nil
}

func (ic *IL2CPP) readCRFields(addr uint64) bool {
	b, ok := ic.readRecord(addr, &layoutCodeRegistration)
	if !ok {
		return false
	}
	r := record{b: b, l: &layoutCodeRegistration, ver: ic.Version}
	ic.crGenericMethodPointersCount = r.u64("genericMethodPointersCount")
	ic.crReversePInvokeWrapperCount = r.u64("reversePInvokeWrapperCount")
	ic.crInteropDataCount = r.u64("interopDataCount")
	return true
}

// init parses the code and metadata registrations. ctx is checked at each
// table boundary and inside the per-entry loops, so a cancelled dump stops
// between tables instead of finishing the registration walk.
func (ic *IL2CPP) init(ctx context.Context, codeRegistration, metadataRegistration uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	const limit = 0x50000
	b, ok := ic.readRecord(codeRegistration, &layoutCodeRegistration)
	if !ok {
		return fmt.Errorf("cannot map Il2CppCodeRegistration at 0x%X", codeRegistration)
	}
	cr := record{b: b, l: &layoutCodeRegistration, ver: ic.Version}

	if ic.Version == 27 && cr.u64("invokerPointersCount") > limit {
		ic.Version = 27.1
		b, ok = ic.readRecord(codeRegistration, &layoutCodeRegistration)
		if !ok {
			return fmt.Errorf("cannot re-map Il2CppCodeRegistration")
		}
		cr = record{b: b, l: &layoutCodeRegistration, ver: ic.Version}
	}
	if ic.Version == 27.1 && cr.has("codeGenModules") {
		mods := ic.readU64sContext(ctx, cr.u64("codeGenModules"), int64(cr.u64("codeGenModulesCount")))
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, modAddr := range mods {
			mb, ok := ic.readRecord(modAddr, &layoutCodeGenModule)
			if !ok {
				continue
			}
			mr := record{b: mb, l: &layoutCodeGenModule, ver: ic.Version}
			if mr.i64("rgctxsCount") > 0 {
				rgctxs := ic.readRGCTXDefs(mr.u64("rgctxs"), mr.i64("rgctxsCount"))
				allLarge := len(rgctxs) > 0
				for i, rg := range rgctxs {
					if i&0xFFF == 0 && ctx.Err() != nil {
						return ctx.Err()
					}
					if rg.index <= limit {
						allLarge = false
						break
					}
				}
				if allLarge {
					ic.Version = 27.2
				}
				break
			}
		}
	}
	if ic.Version == 24.4 && cr.u64("invokerPointersCount") > limit {
		ic.Version = 24.5
		b, ok = ic.readRecord(codeRegistration, &layoutCodeRegistration)
		if !ok {
			return fmt.Errorf("cannot re-map Il2CppCodeRegistration")
		}
		cr = record{b: b, l: &layoutCodeRegistration, ver: ic.Version}
	}
	if ic.Version == 24.2 && !cr.has("codeGenModules") {
		ic.Version = 24.3
		b, ok = ic.readRecord(codeRegistration, &layoutCodeRegistration)
		if !ok {
			return fmt.Errorf("cannot re-map Il2CppCodeRegistration")
		}
		cr = record{b: b, l: &layoutCodeRegistration, ver: ic.Version}
	}

	mb, ok := ic.readRecord(metadataRegistration, &layoutMetadataRegistration)
	if !ok {
		return fmt.Errorf("cannot map Il2CppMetadataRegistration at 0x%X", metadataRegistration)
	}
	mr := record{b: mb, l: &layoutMetadataRegistration, ver: ic.Version}

	ic.GenericMethodPointers = ic.readU64sContext(ctx, cr.u64("genericMethodPointers"), int64(cr.u64("genericMethodPointersCount")))
	ic.InvokerPointers = ic.readU64sContext(ctx, cr.u64("invokerPointers"), int64(cr.u64("invokerPointersCount")))
	if ic.Version < 27 && cr.has("customAttributeGenerators") {
		ic.CustomAttributeGenerators = ic.readU64sContext(ctx, cr.u64("customAttributeGenerators"), int64(cr.u64("customAttributeCount")))
	}
	if ic.Version > 16 && ic.Version < 27 {
		ic.MetadataUsages = ic.readU64sContext(ctx, mr.u64("metadataUsages"), ic.metadataUsagesCount)
	}
	if ic.Version >= 22 {
		if cr.u64("reversePInvokeWrapperCount") != 0 {
			ic.ReversePInvokeWrappers = ic.readU64sContext(ctx, cr.u64("reversePInvokeWrappers"), int64(cr.u64("reversePInvokeWrapperCount")))
		}
		if cr.u64("unresolvedVirtualCallCount") != 0 {
			ic.UnresolvedVirtualCallPointers = ic.readU64sContext(ctx, cr.u64("unresolvedVirtualCallPointers"), int64(cr.u64("unresolvedVirtualCallCount")))
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ic.GenericInstPointers = ic.readU64sContext(ctx, mr.u64("genericInsts"), mr.i64("genericInstsCount"))
	if err := ctx.Err(); err != nil {
		return err
	}
	ic.GenericInsts = make([]*il2CppGenericInst, len(ic.GenericInstPointers))
	for i, p := range ic.GenericInstPointers {
		if i&0xFFF == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		if b, ok := ic.readRecord(p, &layoutGenericInst); ok {
			r := record{b: b, l: &layoutGenericInst, ver: ic.Version}
			ic.GenericInsts[i] = &il2CppGenericInst{TypeArgc: r.i64("type_argc"), TypeArgv: r.u64("type_argv")}
		}
	}
	ic.fieldOffsetsArePointers = ic.Version > 21
	if ic.Version == 21 {
		fieldTest := ic.readU64sContext(ctx, mr.u64("fieldOffsets"), 6)
		if len(fieldTest) >= 6 {
			ic.fieldOffsetsArePointers = fieldTest[0] == 0 && fieldTest[1] == 0 && fieldTest[2] == 0 &&
				fieldTest[3] == 0 && fieldTest[4] == 0 && fieldTest[5] > 0
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if ic.fieldOffsetsArePointers {
		ic.FieldOffsets = ic.readU64sContext(ctx, mr.u64("fieldOffsets"), mr.i64("fieldOffsetsCount"))
	} else {
		raw := ic.readU32s(mr.u64("fieldOffsets"), mr.i64("fieldOffsetsCount"))
		ic.FieldOffsets = make([]uint64, len(raw))
		for i, v := range raw {
			if i&0xFFF == 0 && ctx.Err() != nil {
				return ctx.Err()
			}
			ic.FieldOffsets[i] = uint64(v)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	typesPtrs := ic.readU64sContext(ctx, mr.u64("types"), mr.i64("typesCount"))
	if err := ctx.Err(); err != nil {
		return err
	}
	ic.Types = make([]*Il2CppType, len(typesPtrs))
	ic.typeDic = make(map[uint64]*Il2CppType, len(typesPtrs))
	for i, p := range typesPtrs {
		if i&0xFFF == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		b, ok := ic.readRecord(p, &layoutIl2CppType)
		if !ok {
			continue
		}
		dp := leU64(b, 0)
		bits := leU32(b, 8)
		t := newIl2CppType(dp, bits, ic.Version)
		ic.Types[i] = t
		ic.typeDic[p] = t
	}

	if ic.Version >= 24.2 {
		modPtrs := ic.readU64sContext(ctx, cr.u64("codeGenModules"), int64(cr.u64("codeGenModulesCount")))
		if err := ctx.Err(); err != nil {
			return err
		}
		ic.CodeGenModules = make(map[string]*codeGenModule, len(modPtrs))
		ic.CodeGenModuleMethodPointers = make(map[string][]uint64, len(modPtrs))
		ic.RGCTXsDictionary = make(map[string]map[uint32][]rgctxDefinition, len(modPtrs))
		for i, modAddr := range modPtrs {
			if i&0xFFF == 0 && ctx.Err() != nil {
				return ctx.Err()
			}
			b, ok := ic.readRecord(modAddr, &layoutCodeGenModule)
			if !ok {
				continue
			}
			r := record{b: b, l: &layoutCodeGenModule, ver: ic.Version}
			name := ic.ELF.readCStringContext(ctx, r.u64("moduleName"))
			m := &codeGenModule{
				Name:                          name,
				Address:                       modAddr,
				MethodPointerCount:            r.i64("methodPointerCount"),
				MethodPointers:                r.u64("methodPointers"),
				InvokerIndices:                r.u64("invokerIndices"),
				RGCTXs:                        r.u64("rgctxs"),
				RGCTXsCount:                   r.i64("rgctxsCount"),
				RGCTXRanges:                   r.u64("rgctxRanges"),
				RGCTXRangesCount:              r.i64("rgctxRangesCount"),
				CustomAttributeCacheGenerator: r.u64("customAttributeCacheGenerator"),
			}
			ic.CodeGenModules[name] = m
			ic.CodeGenModuleMethodPointers[name] = ic.readU64sContext(ctx, m.MethodPointers, m.MethodPointerCount)

			rgctxDic := make(map[uint32][]rgctxDefinition)
			ic.RGCTXsDictionary[name] = rgctxDic
			if m.RGCTXsCount > 0 {
				rgctxs := ic.readRGCTXDefs(m.RGCTXs, m.RGCTXsCount)
				ranges := ic.readRGCTXRanges(m.RGCTXRanges, m.RGCTXRangesCount)
				for j, rg := range ranges {
					if j&0xFFF == 0 && ctx.Err() != nil {
						return ctx.Err()
					}
					start := rg.start
					length := rg.length
					if start < 0 || length <= 0 || int(start) > len(rgctxs) || int(length) > len(rgctxs)-int(start) {
						rgctxDic[rg.token] = nil
						continue
					}
					defs := make([]rgctxDefinition, length)
					copy(defs, rgctxs[start:start+length])
					rgctxDic[rg.token] = defs
				}
			}
		}
	} else {
		ic.MethodPointers = ic.readU64sContext(ctx, cr.u64("methodPointers"), int64(cr.u64("methodPointersCount")))
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	entries := ic.readGenericMethodEntries(mr.u64("genericMethodTable"), mr.i64("genericMethodTableCount"))
	specCount := mr.i64("methodSpecsCount")
	if specCount < 0 || specCount > 1<<28 {
		specCount = 0
	}
	specOff, mapped := ic.mapVATR(mr.u64("methodSpecs"))
	if _, _, ok := recordRange(ic.ELF.data, specOff, uint64(specCount), 12); !mapped || !ok {
		specCount = 0
	}
	ic.MethodSpecs = make([]Il2CppMethodSpec, specCount)
	for i := range ic.MethodSpecs {
		if i&0xFFF == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		b, ok := ic.readRecord(mr.u64("methodSpecs")+uint64(i)*12, &layoutMethodSpec)
		if !ok {
			continue
		}
		ic.MethodSpecs[i] = Il2CppMethodSpec{
			MethodDefinitionIndex: leI32(b, 0),
			ClassIndexIndex:       leI32(b, 4),
			MethodIndexIndex:      leI32(b, 8),
		}
	}
	ic.MethodDefMethodSpecs = make(map[int][]int)
	ic.MethodSpecGenericPtrs = make([]uint64, len(ic.MethodSpecs))
	for i, e := range entries {
		if i&0xFFF == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		if e.genericMethodIndex < 0 || int(e.genericMethodIndex) >= len(ic.MethodSpecs) {
			continue
		}
		spec := ic.MethodSpecs[e.genericMethodIndex]
		ic.MethodDefMethodSpecs[int(spec.MethodDefinitionIndex)] = append(ic.MethodDefMethodSpecs[int(spec.MethodDefinitionIndex)], int(e.genericMethodIndex))
		if e.methodIndex >= 0 && int(e.methodIndex) < len(ic.GenericMethodPointers) {
			ic.MethodSpecGenericPtrs[e.genericMethodIndex] = ic.GenericMethodPointers[e.methodIndex]
		}
	}
	return nil
}

func (ic *IL2CPP) readGenericMethodEntries(addr uint64, count int64) []genericMethodEntry {
	recs := recordsRaw(ic, addr, count, &layoutGenericMethodFunctions)
	out := make([]genericMethodEntry, 0, len(recs))
	for _, r := range recs {
		base := r.l.offset(r.ver, "indices")
		if base < 0 {
			continue
		}
		out = append(out, genericMethodEntry{
			genericMethodIndex: r.i32("genericMethodIndex"),
			methodIndex:        leI32(r.b, base),
			invokerIndex:       leI32(r.b, base+4),
		})
	}
	return out
}

func (ic *IL2CPP) readU32s(addr uint64, count int64) []uint32 {
	if count <= 0 {
		return nil
	}
	if count > 1<<30 {
		return nil
	}
	off, ok := ic.mapVATR(addr)
	if !ok {
		return nil
	}
	start, _, ok := recordRange(ic.ELF.data, off, uint64(count), 4)
	if !ok {
		return nil
	}
	out := make([]uint32, count)
	for i := int64(0); i < count; i++ {
		out[i] = ic.ELF.u32(start + int(i)*4)
	}
	return out
}

type rgctxRange struct {
	token  uint32
	start  int32
	length int32
}

func (ic *IL2CPP) readRGCTXDefs(addr uint64, count int64) []rgctxDefinition {
	recs := recordsRaw(ic, addr, count, &layoutRGCTXDefinition)
	out := make([]rgctxDefinition, 0, len(recs))
	for _, r := range recs {
		if r.has("type_post29") {
			out = append(out, rgctxDefinition{typ: r.u64("type_post29"), index: int64(r.u64("_data"))})
		} else {
			out = append(out, rgctxDefinition{
				typ:   uint64(r.i32("type_pre29")),
				index: int64(leI32(r.b, r.l.offset(r.ver, "data"))),
			})
		}
	}
	return out
}

func (ic *IL2CPP) readRGCTXRanges(addr uint64, count int64) []rgctxRange {
	l := &structLayout{fields: []structField{
		p("token", 4),
		s("range", &structLayout{fields: []structField{p("start", 4), p("length", 4)}}, 0, 0),
	}}
	recs := recordsRaw(ic, addr, count, l)
	out := make([]rgctxRange, 0, len(recs))
	for _, r := range recs {
		out = append(out, rgctxRange{
			token:  r.u32("token"),
			start:  r.i32("range"),
			length: leI32(r.b, r.l.offset(r.ver, "range")+4),
		})
	}
	return out
}

// recordsRaw reads an array of registration records from the ELF image.
func recordsRaw(ic *IL2CPP, addr uint64, count int64, l *structLayout) []record {
	if count <= 0 || addr == 0 {
		return nil
	}
	if count > 1<<28 {
		return nil
	}
	esz := l.size(ic.Version)
	if esz <= 0 {
		return nil
	}
	off, ok := ic.mapVATR(addr)
	if !ok {
		return nil
	}
	start, _, ok := recordRange(ic.ELF.data, off, uint64(count), uint64(esz))
	if !ok {
		return nil
	}
	out := make([]record, 0, count)
	for i := int64(0); i < count; i++ {
		pos := start + int(i)*esz
		out = append(out, record{b: ic.ELF.data[pos : pos+esz], l: l, ver: ic.Version})
	}
	return out
}

// GetIl2CppType resolves a type pointer through the type dictionary.
func (ic *IL2CPP) GetIl2CppType(pointer uint64) *Il2CppType {
	return ic.typeDic[pointer]
}

// GetMethodPointer resolves a method's native pointer.
func (ic *IL2CPP) GetMethodPointer(imageName string, methodDef record) uint64 {
	if ic.Version >= 24.2 {
		ptrs := ic.CodeGenModuleMethodPointers[imageName]
		idx := int(methodDef.u32("token")&0x00FFFFFF) - 1
		if idx < 0 || idx >= len(ptrs) {
			return 0
		}
		return ptrs[idx]
	}
	methodIndex := methodDef.i32("methodIndex")
	if methodIndex >= 0 && int(methodIndex) < len(ic.MethodPointers) {
		return ic.MethodPointers[methodIndex]
	}
	return 0
}

// GetRVA converts a native pointer to the value shown in dumps; for a
// file-based (non-memory) dump this is the pointer itself.
func (ic *IL2CPP) GetRVA(pointer uint64) uint64 {
	return pointer
}

// GetFieldOffsetFromIndex mirrors Il2CppDumper, including the -16
// adjustment for instance fields of value types.
func (ic *IL2CPP) GetFieldOffsetFromIndex(typeIndex int, fieldIndexInType int, fieldIndex int, isValueType, isStatic bool) int {
	offset := -1
	if ic.fieldOffsetsArePointers {
		if typeIndex >= 0 && typeIndex < len(ic.FieldOffsets) {
			ptr := ic.FieldOffsets[typeIndex]
			if ptr > 0 {
				if fieldIndexInType >= 0 && uint64(fieldIndexInType) <= (^uint64(0)-ptr)/4 {
					if off, ok := ic.mapVATR(ptr + uint64(fieldIndexInType)*4); ok {
						if start, _, valid := byteRange(ic.ELF.data, off, 4); valid {
							offset = int(int32(ic.ELF.u32(start)))
						}
					}
				}
			}
		}
	} else if fieldIndex >= 0 && fieldIndex < len(ic.FieldOffsets) {
		offset = int(int32(uint32(ic.FieldOffsets[fieldIndex])))
	}
	if offset > 0 && isValueType && !isStatic {
		if ic.PointerSize == 4 {
			offset -= 8
		} else {
			offset -= 16
		}
	}
	return offset
}

// codegen module rgctx accessors used by the type-name executor.

func (ic *IL2CPP) RGCTXForToken(imageName string, token uint32) []rgctxDefinition {
	if ic.RGCTXsDictionary == nil {
		return nil
	}
	return ic.RGCTXsDictionary[imageName][token]
}
