package asm

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// This file parses the hermes-dec exact text format back into structured
// instructions. Comments (everything from the first "  # " onward, and the
// exception-handler/debug annotations on function header lines) are not
// authoritative and are only skipped.
//
// "    case N: XXXXXXXX" lines are a DeStruct extension emitted by the
// disassembler in editable mode; they carry a switch jump table's targets.

// hasmFunction is one parsed "=> [Function #N ...]" section.
type hasmFunction struct {
	Index        int
	Instructions []hasmInstruction
}

// hasmInstruction is one parsed "==> ..." line.
type hasmInstruction struct {
	LineNo   int
	Name     string
	Operands []hasmOperand
	// Offset is the instruction's byte position inside the CURRENT
	// (pre-edit) function; filled when the instruction list is built by
	// decoding the file, left zero for instructions parsed from text.
	Offset uint32
	// SwitchCases holds "    case N: XXXXXXXX" entries following the
	// instruction, if any.
	SwitchCases []switchCase
}

type hasmOperand struct {
	TypeLabel string
	Value     string
	LineNo    int
}

type switchCase struct {
	LineNo    int
	Index     int
	TargetHex string
}

var (
	funcHeaderRe     = regexp.MustCompile(`^=> \[.+ #(\d+) "`)
	instLineRe       = regexp.MustCompile(`^==> [0-9a-fA-F]{8}: <([A-Za-z0-9_]+)>: <(.*?)>`)
	switchCaseLineRe = regexp.MustCompile(`^\s{4}case (\d+): ([0-9a-fA-F]{8})\s*$`)
)

// parseHASM parses the hermes-dec exact text format into per-function
// instruction lists.
func parseHASM(text string) ([]hasmFunction, error) {
	var funcs []hasmFunction
	var cur *hasmFunction

	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024*1024) // long comment lines

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		if m := funcHeaderRe.FindStringSubmatch(line); m != nil {
			idx, err := strconv.Atoi(m[1])
			if err != nil {
				return nil, fmt.Errorf("line %d: malformed function header: %w", lineNo, err)
			}
			funcs = append(funcs, hasmFunction{Index: idx})
			cur = &funcs[len(funcs)-1]
			continue
		}

		if m := switchCaseLineRe.FindStringSubmatch(line); m != nil {
			if cur == nil || len(cur.Instructions) == 0 {
				return nil, fmt.Errorf("line %d: switch case line before any instruction", lineNo)
			}
			last := &cur.Instructions[len(cur.Instructions)-1]
			switch last.Name {
			case "SwitchImm", "UIntSwitchImm":
			default:
				return nil, fmt.Errorf("line %d: switch case line follows a %s, not a switch instruction", lineNo, last.Name)
			}
			caseIdx, _ := strconv.Atoi(m[1])
			last.SwitchCases = append(last.SwitchCases, switchCase{
				LineNo:    lineNo,
				Index:     caseIdx,
				TargetHex: m[2],
			})
			continue
		}

		if !strings.HasPrefix(line, "==> ") {
			continue
		}
		if cur == nil {
			return nil, fmt.Errorf("line %d: instruction line before any function header", lineNo)
		}

		m := instLineRe.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("line %d: malformed instruction line: %s", lineNo, line)
		}
		operands, err := parseOperandList(m[2], lineNo)
		if err != nil {
			return nil, err
		}
		cur.Instructions = append(cur.Instructions, hasmInstruction{
			LineNo:   lineNo,
			Name:     m[1],
			Operands: operands,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading HASM: %w", err)
	}
	return funcs, nil
}

// parseOperandList parses the comma-separated "Type: value" list inside
// the <...> following an instruction name.
func parseOperandList(s string, lineNo int) ([]hasmOperand, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ", ")
	operands := make([]hasmOperand, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		idx := strings.Index(p, ":")
		if idx < 0 {
			return nil, fmt.Errorf("line %d: malformed operand %q (expected \"Type: value\")", lineNo, p)
		}
		operands = append(operands, hasmOperand{
			TypeLabel: strings.TrimSpace(p[:idx]),
			Value:     strings.TrimSpace(p[idx+1:]),
			LineNo:    lineNo,
		})
	}
	return operands, nil
}
