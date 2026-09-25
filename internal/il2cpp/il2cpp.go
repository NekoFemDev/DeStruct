package il2cpp

import (
	"fmt"
	"os"
)

// Options configures an IL2CPP dump.
type Options struct {
	LibPath      string
	MetadataPath string
	OutputDir    string
	Verbose      bool
	Dump         DumpOptions
}

// Result reports what the dumper found.
type Result struct {
	MetadataVersion      float64
	IL2CPPVersion        float64
	CodeRegistration     uint64
	MetadataRegistration uint64
	ImageCount           int
	TypeDefCount         int
	MethodCount          int
}

// Run parses global-metadata.dat and the IL2CPP binary, resolves the
// runtime registrations and writes dump.cs.
func Run(opts Options) (*Result, error) {
	if opts.Dump == (DumpOptions{}) {
		opts.Dump = DefaultDumpOptions()
	}
	if opts.Dump.OutputDir == "" {
		opts.Dump.OutputDir = opts.OutputDir
	}
	logf := func(format string, args ...any) {
		if opts.Verbose {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	metadataBytes, err := os.ReadFile(opts.MetadataPath)
	if err != nil {
		return nil, fmt.Errorf("reading metadata: %w", err)
	}
	metadata, err := NewMetadata(metadataBytes)
	if err != nil {
		return nil, err
	}
	logf("Metadata version: %.1f", metadata.Version)

	libBytes, err := os.ReadFile(opts.LibPath)
	if err != nil {
		return nil, fmt.Errorf("reading il2cpp binary: %w", err)
	}
	elf, err := newELF(libBytes)
	if err != nil {
		return nil, err
	}

	ic := &IL2CPP{
		ELF:                 elf,
		Version:             metadata.Version,
		metadata:            metadata,
		PointerSize:         8,
		metadataUsagesCount: metadata.MetadataUsagesCount,
	}
	if !elf.is64 {
		ic.PointerSize = 4
	}

	imageCount := metadata.ImageCount()
	typeDefsCount := int64(metadata.TypeDefCount())

	logf("Searching for registrations...")
	codeRegistration := ic.findCodeRegistration(imageCount)
	codeRegistration, err = ic.autoPlusInit(codeRegistration)
	if err != nil {
		return nil, err
	}
	metadataRegistration := ic.findMetadataRegistration(typeDefsCount, imageCount)

	if codeRegistration == 0 || metadataRegistration == 0 {
		logf("Auto search incomplete, trying symbols...")
		symCR, symMR := ic.symbolSearch()
		if symCR != 0 && symMR != 0 {
			codeRegistration = symCR
			metadataRegistration = symMR
		}
	}
	if codeRegistration == 0 || metadataRegistration == 0 {
		return nil, fmt.Errorf("could not locate Il2CppCodeRegistration (0x%X) / Il2CppMetadataRegistration (0x%X); the binary may be protected",
			codeRegistration, metadataRegistration)
	}
	logf("CodeRegistration: 0x%X", codeRegistration)
	logf("MetadataRegistration: 0x%X", metadataRegistration)
	logf("IL2CPP version: %.1f", ic.Version)

	if err := ic.init(codeRegistration, metadataRegistration); err != nil {
		return nil, err
	}
	ic.CodeRegistration = codeRegistration
	ic.MetadataRegistration = metadataRegistration

	executor := NewExecutor(metadata, ic)
	if err := executor.Err(); err != nil {
		return nil, fmt.Errorf("initializing executor: %w", err)
	}
	if err := executor.DumpCS(opts.Dump); err != nil {
		return nil, err
	}
	if err := executor.Err(); err != nil {
		return nil, fmt.Errorf("dumping metadata: %w", err)
	}

	methodCount := 0
	for i := 0; i < metadata.MethodDefCount(); i++ {
		m := metadata.MethodDef(i)
		if !m.has("methodIndex") || m.i32("methodIndex") >= 0 {
			methodCount++
		}
	}
	return &Result{
		MetadataVersion:      metadata.Version,
		IL2CPPVersion:        ic.Version,
		CodeRegistration:     codeRegistration,
		MetadataRegistration: metadataRegistration,
		ImageCount:           imageCount,
		TypeDefCount:         int(typeDefsCount),
		MethodCount:          methodCount,
	}, nil
}

// symbolSearch looks for the g_CodeRegistration / g_MetadataRegistration
// dynamic symbols, matching Il2CppDumper's Elf64.SymbolSearch.
func (ic *IL2CPP) symbolSearch() (uint64, uint64) {
	var codeRegistration, metadataRegistration uint64
	for _, sym := range ic.ELF.symbols {
		switch sym.name {
		case "g_CodeRegistration":
			codeRegistration = sym.value
		case "g_MetadataRegistration":
			metadataRegistration = sym.value
		}
	}
	return codeRegistration, metadataRegistration
}
