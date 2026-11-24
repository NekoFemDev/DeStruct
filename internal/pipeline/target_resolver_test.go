package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteTargetResolver(t *testing.T) {
	dir := t.TempDir()
	candidates := []funcCandidate{
		{addr: 0x1000, name: "sub_1000"},
		{addr: 0x2000, name: "sub_2000"},
		{addr: 0x3000, name: "sub_3000"},
	}
	if err := writeTargetResolver(dir, candidates, 0, 0x100000); err != nil {
		t.Fatalf("writeTargetResolver: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "ds_targets.c"))
	if err != nil {
		t.Fatalf("read resolver: %v", err)
	}
	src := string(data)
	for _, want := range []string{
		"extern uint64_t sub_1000();",
		"extern uint64_t sub_2000();",
		"extern uint64_t sub_3000();",
		"{ 0x1000ULL, (void *)sub_1000 }",
		"{ 0x2000ULL, (void *)sub_2000 }",
		"{ 0x3000ULL, (void *)sub_3000 }",
		"DS_TARGET",
		"DS_RESOLVE_IMAGE_SIZE",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("resolver missing %q:\n%s", want, src)
		}
	}
}
