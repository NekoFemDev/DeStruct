package jvm

import (
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

// FuzzParseClassFile feeds arbitrary bytes to the class file parser and then
// to every attribute accessor the decompiler uses on parse results.
func FuzzParseClassFile(f *testing.F) {
	for _, fixture := range []string{"testdata/ManyTryCatch.class", "testdata/CtorArgsWidget.class"} {
		if data, err := os.ReadFile(fixture); err == nil {
			f.Add(data)
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0xca, 0xfe, 0xba, 0xbe})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			t.Skip()
		}
		fuzzRun(t, data, func() {
			cf, err := ParseClassFileFromBytes(data)
			if err != nil {
				return
			}
			for i := range cf.Methods {
				_, _ = cf.ParseCodeAttribute(i)
				_, _ = cf.ParseLineNumberTable(i)
				_, _ = cf.ParseLocalVariableTable(i)
			}
		})
	})
}
