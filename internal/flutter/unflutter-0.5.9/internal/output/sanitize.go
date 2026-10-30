package output

import (
	"fmt"
	"hash/fnv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxFileNameLen bounds a single output path component, in bytes. Most
// filesystems cap a name at 255 bytes; 200 leaves headroom for the ".txt" /
// ".bin" suffixes and keeps the full output path comfortably short.
const MaxFileNameLen = 200

// illegalChars maps characters that are unsafe or reserved in filenames to
// "_". "/" and "\" are also path separators on POSIX and Windows, so
// replacing them guarantees a sanitized name can never open an unintended
// subdirectory.
var illegalChars = strings.NewReplacer(
	"/", "_",
	"\\", "_",
	":", "_",
	"*", "_",
	"?", "_",
	"\"", "_",
	"<", "_",
	">", "_",
	"|", "_",
	" ", "_",
)

// SanitizeFileName makes a single name safe to use as one path component:
//
//   - non-printable runes and the Windows-reserved set ([/\:*?"<>| ]) are
//     replaced with "_", so a Dart symbol such as "Duration/dyn_-_1435fa4"
//     cannot turn into a nested directory path;
//   - names longer than MaxFileNameLen bytes are truncated on a rune
//     boundary and suffixed with a short FNV-1a hash of the full name, so
//     oversized symbols neither overflow filesystem limits nor collide
//     into the same output file.
//
// The function is idempotent (SanitizeFileName(SanitizeFileName(s)) ==
// SanitizeFileName(s)), which lets readers reconstruct exactly the same
// relative path the writer used.
func SanitizeFileName(name string) string {
	var clean strings.Builder
	clean.Grow(len(name))
	for _, r := range name {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			clean.WriteByte('_')
		} else {
			clean.WriteRune(r)
		}
	}
	s := illegalChars.Replace(clean.String())
	if s == "" || s == "." || s == ".." {
		return "_"
	}
	if len(s) <= MaxFileNameLen {
		return s
	}
	return truncateWithHash(s)
}

// truncateWithHash cuts s down to MaxFileNameLen bytes without splitting a
// UTF-8 rune and appends "-<fnv64a>" derived from the full name. The hash is
// deterministic, so writer and readers agree on the truncated name.
func truncateWithHash(s string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	suffix := fmt.Sprintf("-%016x", h.Sum64())
	cut := MaxFileNameLen - len(suffix)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}
