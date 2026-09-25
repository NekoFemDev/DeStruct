package il2cpp

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

// FuzzParseMetadata feeds arbitrary bytes to the global-metadata.dat parser
// and exercises the accessors the dumper calls on parse results.
func FuzzParseMetadata(f *testing.F) {
	if data, err := os.ReadFile("../../global-metadata.dat"); err == nil {
		if len(data) > fuzzMaxInput {
			data = data[:fuzzMaxInput]
		}
		f.Add(data)
	}
	seed := make([]byte, 8)
	binary.LittleEndian.PutUint32(seed[0:], 0xFAB11BAF)
	binary.LittleEndian.PutUint32(seed[4:], 31)
	f.Add(seed)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			t.Skip()
		}
		fuzzRun(t, data, func() {
			m, err := NewMetadata(data)
			if err != nil {
				return
			}
			_ = m.ImageCount()
			_ = m.TypeDefCount()
			_ = m.MethodDefCount()
			_ = m.GetStringFromIndex(0)
			_ = m.GetStringLiteralFromIndex(0)
			_ = m.GetDefaultValueFromIndex(0)
			_ = m.DecodedMethodIndex(0)
		})
	})
}

// FuzzParseIL2CPPELF feeds arbitrary bytes to the ELF container parser used
// for libil2cpp.so.
func FuzzParseIL2CPPELF(f *testing.F) {
	if data, err := os.ReadFile("../../test/liblun.so"); err == nil {
		if len(data) > fuzzMaxInput {
			data = data[:fuzzMaxInput]
		}
		f.Add(data)
	}
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			t.Skip()
		}
		fuzzRun(t, data, func() {
			e, err := newELF(data)
			if err != nil {
				return
			}
			_ = e.execSections()
			_ = e.dataSections()
			_, _ = e.mapVATR(0)
			_ = e.readCString(0)
		})
	})
}
