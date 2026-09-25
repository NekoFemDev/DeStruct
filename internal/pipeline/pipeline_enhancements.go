package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
)

// ApplyARM64DecompilationEnhancements copies the decompiled output to the
// enhanced path. Address comments are emitted while lifting each function,
// when its ELF virtual address is still available.
func (p *Pipeline) ApplyARM64DecompilationEnhancements() error {
	if p.opts.SplitFunctions {
		return nil
	}

	outputPath := filepath.Join(p.opts.Output, filepath.Base(p.opts.Input)+".decompiled.c")
	content, err := os.ReadFile(outputPath)
	if err != nil {
		return fmt.Errorf("read decompiled output: %w", err)
	}

	enhancedPath := outputPath + ".enhanced"
	if err := os.WriteFile(enhancedPath, content, 0644); err != nil {
		return fmt.Errorf("write enhanced output: %w", err)
	}

	fmt.Printf("Enhanced decompiled ARM64 output: %s\n", enhancedPath)
	return nil
}
