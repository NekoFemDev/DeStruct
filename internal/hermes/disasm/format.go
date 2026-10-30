package disasm

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
)

// This file ports the Python-facing rendering primitives that make the
// exact output byte-identical to the reference hermes-dec disassembler:
// float formatting as CPython's str(), string quoting as CPython's
// repr(), and the "0"/"1" rendering of bool bitfields.

// formatPyFloat renders a float64 exactly as Python's str()/repr() does:
// the shortest decimal digit string that round-trips back to the same
// float64, in fixed-point notation when the base-10 exponent e satisfies
// -4 <= e < 16, exponential otherwise. This threshold is CPython's own
// (PyOS_double_to_string format code 'r'); Go's strconv 'g' verb picks
// the same shortest digits but switches to exponential much earlier.
func formatPyFloat(f float64) string {
	if math.IsInf(f, 1) {
		return "inf"
	}
	if math.IsInf(f, -1) {
		return "-inf"
	}
	if math.IsNaN(f) {
		return "nan"
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}

	sci := strconv.FormatFloat(f, 'e', -1, 64)

	neg := false
	if sci[0] == '-' {
		neg = true
		sci = sci[1:]
	}

	eIdx := strings.IndexByte(sci, 'e')
	mantissa := sci[:eIdx]
	expPart := sci[eIdx+1:]
	exp, _ := strconv.Atoi(expPart)

	digits := strings.Replace(mantissa, ".", "", 1)

	var out string
	if exp >= -4 && exp < 16 {
		out = formatPyFixed(digits, exp)
	} else {
		out = formatPyExponential(digits, exp)
	}

	if neg {
		out = "-" + out
	}
	return out
}

// formatPyFixed renders significant-digit string `digits` (no decimal
// point, first digit is the ones place of 10^exp) in fixed-point form.
func formatPyFixed(digits string, exp int) string {
	if exp >= 0 {
		intLen := exp + 1
		if len(digits) <= intLen {
			return digits + strings.Repeat("0", intLen-len(digits)) + ".0"
		}
		return digits[:intLen] + "." + digits[intLen:]
	}
	return "0." + strings.Repeat("0", -exp-1) + digits
}

// formatPyExponential renders significant-digit string `digits` in
// Python's exponential form: "d.ddde+XX" / "d.ddde-XX", always a sign and
// at least two exponent digits, no decimal point for a single digit.
func formatPyExponential(digits string, exp int) string {
	var mantissa string
	if len(digits) == 1 {
		mantissa = digits
	} else {
		mantissa = digits[:1] + "." + digits[1:]
	}
	sign := "+"
	e := exp
	if e < 0 {
		sign = "-"
		e = -e
	}
	expStr := strconv.Itoa(e)
	if len(expStr) < 2 {
		expStr = "0" + expStr
	}
	return mantissa + "e" + sign + expStr
}

// pyRepr renders a Go string the way Python's repr() renders a str:
// double quotes when the string contains a single quote but no double
// quote, single quotes otherwise; backslash and common control characters
// use their short escapes, everything non-printable is escaped as \xXX /
// \uXXXX / \UXXXXXXXX.
func pyRepr(s string) string {
	hasSingle := strings.ContainsRune(s, '\'')
	hasDouble := strings.ContainsRune(s, '"')
	quote := byte('\'')
	if hasSingle && !hasDouble {
		quote = '"'
	}

	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case byte(r) == quote && r < 0x80:
			b.WriteByte('\\')
			b.WriteByte(quote)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		default:
			if unicode.IsPrint(r) {
				b.WriteRune(r)
			} else {
				switch {
				case r <= 0xFF:
					fmt.Fprintf(&b, `\x%02x`, r)
				case r <= 0xFFFF:
					fmt.Fprintf(&b, `\u%04x`, r)
				default:
					fmt.Fprintf(&b, `\U%08x`, r)
				}
			}
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// pyBit renders a bool as Python's repr() of the underlying c_uint8:1
// bitfield: "0" or "1", not "True"/"False".
func pyBit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
