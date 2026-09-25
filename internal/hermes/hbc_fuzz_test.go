package hermes

import (
	"bytes"
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

// FuzzParseHBC feeds arbitrary bytes to the Hermes bytecode parser.
func FuzzParseHBC(f *testing.F) {
	// Minimal header-shaped seed: correct magic in little-endian form.
	seed := make([]byte, 256)
	seed[0], seed[1], seed[2], seed[3] = 0xc6, 0x1f, 0xbc, 0x03
	seed[4], seed[5], seed[6], seed[7] = 0xc1, 0x03, 0x19, 0x1f
	f.Add(seed)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			t.Skip()
		}
		fuzzRun(t, data, func() {
			file, err := Parse(bytes.NewReader(data))
			if err != nil {
				return
			}
			_ = len(file.FunctionHeaders)
			_ = len(file.Strings)
		})
	})
}
