package main

import "testing"

func TestParseFlagsUnknownOption(t *testing.T) {
	if _, _, err := parseFlags([]string{"--definitely-not-a-flag"}); err == nil {
		t.Fatal("unknown option was accepted")
	}
}

func TestParseFlagsMissingValue(t *testing.T) {
	for _, args := range [][]string{{"-o"}, {"--output"}, {"-i"}, {"--il2cpp-offsets"}, {"--il2cpp-metadata"}} {
		if _, _, err := parseFlags(args); err == nil {
			t.Errorf("parseFlags(%v) accepted a missing value", args)
		}
	}
}

func TestParseFlagsPositionals(t *testing.T) {
	opts, input, err := parseFlags([]string{"in.so", "-o", "out", "--decompile"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if input != "in.so" || opts.output != "out" || !opts.decompile {
		t.Fatalf("unexpected parse result: input=%q opts=%+v", input, opts)
	}

	if _, _, err := parseFlags([]string{"a.so", "b.so"}); err == nil {
		t.Fatal("second positional argument was accepted")
	}
}

func TestParseFlagsHelp(t *testing.T) {
	opts, _, err := parseFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if !opts.help {
		t.Fatal("-h did not set help")
	}
}
