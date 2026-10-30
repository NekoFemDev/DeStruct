package js

import "testing"

// TestDeobfuscateIIFE pins the headline behaviour of the v1 pipeline: the
// classic `!function(){...}()` wrapper is unwrapped into a block statement and
// the `!0` constant inside is folded.
func TestDeobfuscateIIFE(t *testing.T) {
	const in = `!function(){var t=!0;console.log(t)}();`
	const want = "{\n    var t = true;\n    console.log(t);\n}"

	got, err := Deobfuscate(in)
	if err != nil {
		t.Fatalf("Deobfuscate(%q): unexpected error: %v", in, err)
	}
	if got != want {
		t.Fatalf("Deobfuscate(%q):\n got: %q\nwant: %q", in, got, want)
	}
}

func TestDeobfuscateTransforms(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"not zero folds to true", `var a=!0;`, `var a = true;`},
		{"not one folds to false", `var a=!1;`, `var a = false;`},
		{"not empty array folds to false", `var a=![];`, `var a = false;`},
		{"double not empty array folds to true", `var a=!![];`, `var a = true;`},
		{"not negative number folds to false", `var a=!-1;`, `var a = false;`},
		{"integer addition folds", `var a=1+2;`, `var a = 3;`},
		{"nested arithmetic folds bottom-up", `var a=2*3+4;`, `var a = 10;`},
		{"negative arithmetic result", `var a=1-2;`, `var a = -1;`},
		{"division by zero is left alone", `var a=1/0;`, `var a = 1 / 0;`},
		{"void zero becomes undefined", `var a=void 0;`, `var a = undefined;`},
		{"debugger statements are removed", `debugger;var a=1;debugger;`, `var a = 1;`},
		{"debugger inside block", `if(x){debugger;a();}`, "if (x) {\n    a();\n}"},
		{"debugger as sole if body", `if(x)debugger;`, `if (x);`},
		{"empty input", ``, ``},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Deobfuscate(tt.in)
			if err != nil {
				t.Fatalf("Deobfuscate(%q): unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("Deobfuscate(%q):\n got: %q\nwant: %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestDeobfuscateLeavesUnsafeIIFE verifies that unwrapping is declined when the
// rewrite would change semantics — here the body returns from the wrapper, and
// a `return` outside a function is a syntax error.
func TestDeobfuscateLeavesUnsafeIIFE(t *testing.T) {
	const in = `!function(){return !0;}();`
	const want = "!function() {\n    return true;\n}();"

	got, err := Deobfuscate(in)
	if err != nil {
		t.Fatalf("Deobfuscate(%q): unexpected error: %v", in, err)
	}
	if got != want {
		t.Fatalf("Deobfuscate(%q):\n got: %q\nwant: %q", in, got, want)
	}
}

func TestDeobfuscateRejectsBrokenInput(t *testing.T) {
	if _, err := Deobfuscate(`!function(){`); err == nil {
		t.Fatal("expected a parse error for truncated input")
	}
}

// FuzzDeobfuscate enforces the panic-safety contract: any byte string either
// deobfuscates or returns an error — it never takes the process down.
//
// Note: the go tool disables active fuzzing on android/arm64, so on Termux
// this runs its seed corpus as regular unit tests; on desktop platforms
// `go test -fuzz=FuzzDeobfuscate` exercises random inputs.
func FuzzDeobfuscate(f *testing.F) {
	f.Add(`!function(){var t=!0;console.log(t)}();`)
	f.Add(`debugger;var a=1+2;`)
	f.Add(`var a=void 0;`)
	f.Add(`!(function(){})();`)

	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 4096 {
			t.Skip()
		}
		_, _ = Deobfuscate(src)
	})
}
