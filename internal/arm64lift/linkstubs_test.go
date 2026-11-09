package arm64lift

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateLinkStubsDir(t *testing.T) {
	dir := t.TempDir()
	generated := `#include <stdint.h>
uint64_t sub_existing(uint64_t x0, uint64_t x1)
{
    extern uint64_t ext_memmove();
    extern uint64_t ext_strlen();
    extern uint64_t func_9799cc();
    extern uint64_t ext___errno();
    extern uint64_t ext_some_global;
    ext_memmove(1, 2, 3);
    ext_strlen(4);
    func_9799cc(1, 2);
    *(uint32_t*)(uintptr_t)ext___errno();
    ext_some_global = 7;
    return 0;
}
`
	if err := os.WriteFile(filepath.Join(dir, "generated.c"), []byte(generated), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "stubs.c")
	res, err := GenerateLinkStubsDir(dir, out)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{
		"uint64_t ext_memmove(",
		"memmove((void*)(uintptr_t)a0",
		"uint64_t ext_strlen(",
		"strlen((const char*)(uintptr_t)a0)",
		"uint64_t func_9799cc(",
		"return 0;",
		"uint64_t ext_some_global;",
		"static uint32_t eni_errno_storage;",
		"return (uint64_t)(uintptr_t)&eni_errno_storage;",
		"int main(void)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stubs.c missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "uint64_t sub_existing(") {
		t.Errorf("defined function was stubbed:\n%s", got)
	}
	if !res.AddedMain {
		t.Error("expected main to be added")
	}
	if len(res.Variables) != 1 || res.Variables[0] != "ext_some_global" {
		t.Errorf("variables = %v, want [ext_some_global]", res.Variables)
	}
}

func TestGenerateLinkStubs_DoesNotAddMainWhenDefined(t *testing.T) {
	dir := t.TempDir()
	generated := `#include <stdint.h>
int main(void) { return 0; }
`
	if err := os.WriteFile(filepath.Join(dir, "main.c"), []byte(generated), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "stubs.c")
	res, err := GenerateLinkStubsDir(dir, out)
	if err != nil {
		t.Fatal(err)
	}
	if res.AddedMain {
		t.Fatal("main was already defined but a stub main was added")
	}
}
