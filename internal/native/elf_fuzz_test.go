package native

import (
	"encoding/binary"
	"os"
	"runtime"
	"testing"
	"time"
)

// Fuzzing bounds and per-input checks. Out-of-bounds access, nil
// dereferences and other malformed-input panics surface automatically as
// crashers; the bounds below additionally guard against runaway allocation
// and infinite loops, which the engine cannot classify on its own.
const (
	fuzzMaxInput = 1 << 20 // 1 MiB
	fuzzMaxAlloc = 64 << 20
	fuzzTimeout  = 10 * time.Second
)

// fuzzRun calls parse with a per-input watchdog and a coarse allocation
// ceiling. The ceiling is deliberately loose: parser structures may
// legitimately grow to a small multiple of the input, but never hundreds of
// megabytes for a megabyte-scale malformed file.
func fuzzRun(t *testing.T, input []byte, parse func()) {
	t.Helper()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	done := make(chan struct{})
	go func() {
		defer close(done)
		parse()
	}()

	timer := time.NewTimer(fuzzTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		t.Fatalf("parser did not return within %s for a %d-byte input", fuzzTimeout, len(input))
	}

	runtime.ReadMemStats(&after)
	if used := after.TotalAlloc - before.TotalAlloc; used > fuzzMaxAlloc {
		t.Fatalf("parser allocated %d bytes (limit %d) for a %d-byte input", used, fuzzMaxAlloc, len(input))
	}
}

// FuzzParseELF mirrors NewELFParser's own construction sequence on arbitrary
// bytes (same-package access to the unexported parse stages) and then
// exercises the post-parse accessors the pipeline uses.
func FuzzParseELF(f *testing.F) {
	if data, err := os.ReadFile("../../test/liblun.so"); err == nil {
		if len(data) > fuzzMaxInput {
			data = data[:fuzzMaxInput]
		}
		f.Add(data)
	}
	base := make([]byte, 64)
	copy(base, ELF_MAGIC)
	base[4], base[5] = ELFCLASS64, ELFDATA2LSB
	binary.LittleEndian.PutUint16(base[18:], EM_AARCH64)
	f.Add(base)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			t.Skip()
		}
		fuzzRun(t, data, func() {
			if len(data) < 16 || string(data[:4]) != ELF_MAGIC {
				return
			}
			p := &ELFParser{Data: data}
			if err := p.parseHeader(); err != nil {
				return
			}
			if err := p.parseSections(); err != nil {
				return
			}
			if len(p.Sections) == 0 {
				if err := p.parseProgramSections(); err != nil {
					return
				}
			}
			// NewELFParser only warns when symbol parsing fails, so the
			// post-parse accessors keep running either way.
			_ = p.parseSymbols()
			_ = p.GetCodeSections()
			_ = p.SymbolResolver()
			_ = p.DataReader()
			_, _ = p.ReadCString(0)
		})
	})
}
