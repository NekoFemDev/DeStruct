package hexedit

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
)

const (
	// searchBlockBytes is the streaming window; matches straddling a
	// block boundary are recovered by scanning a
	// (len(pattern)-1)-byte carry into the next block.
	searchBlockBytes = 1 << 20
	// searchLimit caps how many hit addresses are printed; the total
	// count is still exact because counting never stops early.
	searchLimit = 64
)

// searchPattern is a parsed search expression: literal bytes plus a
// wildcard mask ('??' bytes match anything).
type searchPattern struct {
	data []byte
	wild []bool
	mode string // "hex" or "ascii", for the result header
}

func (p searchPattern) hasWildcards() bool {
	for _, w := range p.wild {
		if w {
			return true
		}
	}
	return false
}

func (p searchPattern) matchesAt(hay []byte) bool {
	for i := range p.data {
		if !p.wild[i] && hay[i] != p.data[i] {
			return false
		}
	}
	return true
}

// parseSearchPattern parses the frozen search syntax:
//
//	"ASCII text"          quoted: literal ASCII bytes
//	48 65 6c              space-separated hex byte pairs
//	48656c                contiguous hex pairs (even length)
//	48 ?? 6c              hex with '??' whole-byte wildcards
//	hello                 bare non-hex token: ASCII
//
// Anything ambiguous (multiple words, neither all hex nor quoted) is
// rejected rather than guessed; "abcd" is hex, "\"abcd\"" is ASCII.
func parseSearchPattern(raw string) (searchPattern, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return searchPattern{}, fmt.Errorf("empty search pattern")
	}

	if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
		ascii := text[1 : len(text)-1]
		if ascii == "" {
			return searchPattern{}, fmt.Errorf("empty ASCII search pattern")
		}
		return searchPattern{data: []byte(ascii), wild: make([]bool, len(ascii)), mode: "ascii"}, nil
	}

	fields := strings.Fields(text)
	if len(fields) == 0 {
		return searchPattern{}, fmt.Errorf("empty search pattern")
	}

	if len(fields) == 1 {
		if pat, ok := parseHexPairs(fields[0]); ok {
			return pat, nil
		}
		if strings.Contains(fields[0], "?") {
			return searchPattern{}, fmt.Errorf("wildcards must be space-separated ?? bytes, e.g. 48 ?? 6c")
		}
		return searchPattern{data: []byte(fields[0]), wild: make([]bool, len(fields[0])), mode: "ascii"}, nil
	}

	for _, f := range fields {
		if f == "??" || isHexPair(f) {
			continue
		}
		return searchPattern{}, fmt.Errorf("ambiguous search pattern: use \"ASCII text\" for text, or space-separated hex bytes (?? = wildcard)")
	}
	data := make([]byte, 0, len(fields))
	wild := make([]bool, 0, len(fields))
	for _, f := range fields {
		if f == "??" {
			data = append(data, 0)
			wild = append(wild, true)
			continue
		}
		b, _ := strconv.ParseUint(f, 16, 8)
		data = append(data, byte(b))
		wild = append(wild, false)
	}
	return searchPattern{data: data, wild: wild, mode: "hex"}, nil
}

// parseHexPairs parses a contiguous even-length hex token ("48656c")
// into byte pairs, treating each "??" pair as a wildcard. It reports
// false for anything else so the caller can fall back to ASCII.
func parseHexPairs(tok string) (searchPattern, bool) {
	if len(tok) == 0 || len(tok)%2 != 0 {
		return searchPattern{}, false
	}
	data := make([]byte, 0, len(tok)/2)
	wild := make([]bool, 0, len(tok)/2)
	for i := 0; i < len(tok); i += 2 {
		pair := tok[i : i+2]
		if pair == "??" {
			data = append(data, 0)
			wild = append(wild, true)
			continue
		}
		if !isHexPair(pair) {
			return searchPattern{}, false
		}
		b, _ := strconv.ParseUint(pair, 16, 8)
		data = append(data, byte(b))
		wild = append(wild, false)
	}
	return searchPattern{data: data, wild: wild, mode: "hex"}, true
}

func isHexPair(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i < 2; i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// search scans the whole file (mapped source; staged patches are
// merged in once staging exists) and returns up to limit hit offsets in
// ascending order plus the exact total count. ctx is checked once per
// block so a cancelled search stops promptly.
func (s *Session) search(ctx context.Context, pat searchPattern, limit int) ([]int64, int, error) {
	data := s.img.Bytes()
	if len(pat.data) == 0 {
		return nil, 0, fmt.Errorf("empty search pattern")
	}
	var hits []int64
	total := 0
	carry := len(pat.data) - 1

	for start := 0; start < len(data); {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		end := start + searchBlockBytes
		if end > len(data) {
			end = len(data)
		}
		scanEnd := end + carry
		if scanEnd > len(data) {
			scanEnd = len(data)
		}
		block := data[start:scanEnd]

		if !pat.hasWildcards() {
			// Fast path: bytes.Index per literal.
			idx := 0
			for {
				k := bytes.Index(block[idx:], pat.data)
				if k < 0 {
					break
				}
				pos := start + idx + k
				if pos >= end {
					break // starts in the next block; it will be found there
				}
				total++
				if len(hits) < limit {
					hits = append(hits, int64(pos))
				}
				idx += k + 1
			}
		} else {
			for i := 0; i+len(pat.data) <= len(block); i++ {
				if start+i >= end {
					break
				}
				if pat.matchesAt(block[i:]) {
					total++
					if len(hits) < limit {
						hits = append(hits, int64(start+i))
					}
				}
			}
		}
		if end == len(data) {
			break
		}
		start = end
	}
	return hits, total, nil
}

// cmdSearch runs a search and prints the hits, capped at searchLimit,
// with both address spaces when they differ.
func (s *Session) cmdSearch(ctx context.Context, rest string) error {
	if strings.TrimSpace(rest) == "" {
		return fmt.Errorf("usage: search <hex bytes | \"ascii\"> (?? = wildcard)")
	}
	pat, err := parseSearchPattern(rest)
	if err != nil {
		return err
	}
	hits, total, err := s.search(ctx, pat, searchLimit)
	if err != nil {
		return err
	}

	desc := fmt.Sprintf("%s, %d byte(s)", pat.mode, len(pat.data))
	if pat.hasWildcards() {
		desc = fmt.Sprintf("%s with wildcards, %d byte(s)", pat.mode, len(pat.data))
	}
	s.printfln("; search: %s", desc)
	if total == 0 {
		s.printfln("no matches")
		return nil
	}
	for _, off := range hits {
		line := fmt.Sprintf("f:0x%08x", off)
		if va, ok := s.img.FileToVA(uint64(off)); ok && va != uint64(off) {
			line += fmt.Sprintf(" (v:0x%08x)", va)
		}
		s.printfln("%s", line)
	}
	if total > len(hits) {
		s.printfln("... %d more matches (showing first %d of %d)", total-len(hits), len(hits), total)
	}
	return nil
}
