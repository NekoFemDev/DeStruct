// Package destruct is the public Go API for DeStruct.
//
// The CLI is the primary interface; this package exposes the same
// pipeline for callers that want to embed the decompiler in another
// tool. Formats are selected from the input extension, with an explicit
// Flutter switch for libapp.so/APK inputs (a generic .so is treated as a
// native ELF, not as Flutter).
package destruct

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/destruct/destruct/internal/csharp"
	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/jvm"
	"github.com/destruct/destruct/internal/pipeline"
)

// Options controls Decompile. The zero value is usable for JVM inputs.
type Options struct {
	Input   string
	Output  string
	Verbose bool
	Deobf   bool
	Project bool
	// Decompile selects pseudo-C for ELF inputs instead of disassembly.
	Decompile bool
	// Flutter treats .so/.apk inputs as a Flutter libapp.so bundle and
	// runs the Flutter/Dart AOT disassembler instead of the generic ELF
	// path.
	Flutter bool
}

// formatFor maps an input extension to a pipeline format. It returns
// ok=false for formats DeStruct does not process through the decompile
// pipeline (for example .exe/.dll after PE support was removed).
func formatFor(ext string, flutter bool) (pipeline.Format, bool) {
	ext = strings.ToLower(ext)
	if flutter && (ext == ".so" || ext == ".apk") {
		return pipeline.FormatFlutter, true
	}
	switch ext {
	case ".class", ".jar":
		return pipeline.FormatJVM, true
	case ".dex", ".apk":
		return pipeline.FormatDEX, true
	case ".so", ".elf":
		return pipeline.FormatELF, true
	default:
		return 0, false
	}
}

// Decompile runs the pipeline for the input selected by Options.Input.
func Decompile(opts Options) error {
	ext := strings.ToLower(filepath.Ext(opts.Input))
	format, ok := formatFor(ext, opts.Flutter)
	if !ok {
		if ext == ".exe" || ext == ".dll" {
			return fmt.Errorf("unsupported file format: %s (PE support was removed)", ext)
		}
		return fmt.Errorf("unsupported file format: %s", ext)
	}

	p := pipeline.New(pipeline.Options{
		Input:     opts.Input,
		Output:    opts.Output,
		Format:    format,
		Verbose:   opts.Verbose,
		Deobf:     opts.Deobf,
		Project:   opts.Project,
		Decompile: opts.Decompile,
	})

	return p.Run()
}

// DecompileJVM parses a .jar or .class file into the shared IR without
// writing output. It is useful for callers that want to post-process the
// program (for example with GenerateCSharp).
func DecompileJVM(filename string, outputDir string) (*ir.Program, error) {
	ext := strings.ToLower(filepath.Ext(filename))

	if ext == ".jar" {
		return jvm.DecompileJAR(filename)
	}

	return jvm.DecompileClassFile(filename)
}

// GenerateCSharp renders an IR program as C# source.
func GenerateCSharp(prog *ir.Program, outputDir string, project bool) error {
	gen := csharp.NewGenerator(csharp.Options{
		OutputDir: outputDir,
		Project:   project,
	})

	return gen.Generate(prog)
}
