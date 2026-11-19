package destruct

import (
	"testing"

	"github.com/destruct/destruct/internal/pipeline"
)

func TestFormatFor(t *testing.T) {
	for _, tc := range []struct {
		ext     string
		flutter bool
		want    pipeline.Format
		ok      bool
	}{
		{".class", false, pipeline.FormatJVM, true},
		{".JAR", false, pipeline.FormatJVM, true},
		{".dex", false, pipeline.FormatDEX, true},
		{".apk", false, pipeline.FormatDEX, true},
		{".so", false, pipeline.FormatELF, true},
		{".ELF", false, pipeline.FormatELF, true},
		{".so", true, pipeline.FormatFlutter, true},
		{".apk", true, pipeline.FormatFlutter, true},
		{".dex", true, pipeline.FormatDEX, true},
		{".exe", false, 0, false},
		{".dll", false, 0, false},
		{".hbc", false, 0, false},
	} {
		got, ok := formatFor(tc.ext, tc.flutter)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("formatFor(%q, %v) = (%v, %v), want (%v, %v)",
				tc.ext, tc.flutter, got, ok, tc.want, tc.ok)
		}
	}
}
