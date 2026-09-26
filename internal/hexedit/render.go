package hexedit

import (
	"fmt"
	"io"
	"strings"
)

const hexDumpRowBytes = 16

// sectionAnnotation returns a "; .name f:0x..." header for the section
// containing start, appending the virtual address only when it differs
// from the file offset - on many ELFs the two are equal, and printing
// both unconditionally would be noise.
func sectionAnnotation(img *Image, start int64) string {
	sec, ok := img.SectionAtFile(uint64(start))
	if !ok {
		return ""
	}
	name := sec.Name
	if name == "" {
		name = "<unnamed>"
	}
	ann := fmt.Sprintf("; %s f:0x%08x", name, start)
	if va, ok := img.FileToVA(uint64(start)); ok && va != uint64(start) {
		ann += fmt.Sprintf(" (v:0x%08x)", va)
	}
	return ann
}

// renderHexDump writes 16-byte rows of data, which must start at file
// offset start in img. Short rows at EOF are padded so the ASCII column
// stays aligned.
func renderHexDump(w io.Writer, img *Image, start int64, data []byte) {
	if ann := sectionAnnotation(img, start); ann != "" {
		fmt.Fprintln(w, ann)
	}
	for row := 0; row < len(data); row += hexDumpRowBytes {
		end := row + hexDumpRowBytes
		if end > len(data) {
			end = len(data)
		}
		chunk := data[row:end]

		var hexPart strings.Builder
		for i, b := range chunk {
			if i > 0 {
				hexPart.WriteByte(' ')
			}
			fmt.Fprintf(&hexPart, "%02x", b)
		}

		var ascii strings.Builder
		for _, b := range chunk {
			if b >= 0x20 && b <= 0x7e {
				ascii.WriteByte(b)
			} else {
				ascii.WriteByte('.')
			}
		}

		fmt.Fprintf(w, "f:0x%08x  %-*s  |%s|\n",
			start+int64(row), hexDumpRowBytes*3-1, hexPart.String(), ascii.String())
	}
}
