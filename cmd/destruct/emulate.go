package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/destruct/destruct/internal/emulate"
	"github.com/destruct/destruct/internal/native"
)

// handleELFEmulate implements:
//
//	destruct elf emulate <file> <function|address> [--args ...] [--json]
func handleELFEmulate(ctx context.Context, args []string) error {
	var (
		input     string
		function  string
		argText   string
		maxInsns  uint64 = 10_000_000
		timeoutMS uint64 = 5000
		asJSON    bool
	)

	i := 0
	for i < len(args) {
		arg := args[i]
		switch arg {
		case "-h", "--help":
			printCommandHelp("elf emulate")
			return nil
		case "--args":
			i++
			if i >= len(args) {
				return commandUsageError("elf emulate", errors.New("--args requires a value"))
			}
			argText = args[i]
		case "--max-insns":
			i++
			if i >= len(args) {
				return commandUsageError("elf emulate", errors.New("--max-insns requires a value"))
			}
			v, err := strconv.ParseUint(args[i], 0, 64)
			if err != nil {
				return commandUsageError("elf emulate", fmt.Errorf("invalid --max-insns: %w", err))
			}
			maxInsns = v
		case "--timeout":
			i++
			if i >= len(args) {
				return commandUsageError("elf emulate", errors.New("--timeout requires a value"))
			}
			v, err := strconv.ParseUint(args[i], 0, 64)
			if err != nil {
				return commandUsageError("elf emulate", fmt.Errorf("invalid --timeout: %w", err))
			}
			timeoutMS = v
		case "--json":
			asJSON = true
		default:
			if strings.HasPrefix(arg, "-") {
				return commandUsageError("elf emulate", fmt.Errorf("unknown option: %s", arg))
			}
			switch {
			case input == "":
				input = arg
			case function == "":
				function = arg
			default:
				return commandUsageError("elf emulate", errors.New("expected <file> <function|address>"))
			}
		}
		i++
	}
	if input == "" || function == "" {
		return commandUsageError("elf emulate", errors.New("input file and function/address required"))
	}

	vals, err := parseEmulatedArgs(argText)
	if err != nil {
		return commandUsageError("elf emulate", err)
	}

	elf, err := native.NewELFParserContext(ctx, input)
	if err != nil {
		return fmt.Errorf("parsing ELF: %w", err)
	}
	if elf.Header.Machine != native.EM_AARCH64 {
		return fmt.Errorf("emulation currently supports AArch64 only (machine 0x%x)", elf.Header.Machine)
	}
	addr, name, err := resolveEmulationTarget(elf, function)
	if err != nil {
		return err
	}

	cfg := emulate.DefaultConfig()
	cfg.MaxInsns = maxInsns
	cfg.Timeout = time.Duration(timeoutMS) * time.Millisecond
	m, err := emulate.NewMachine(emulate.ArchARM64, cfg)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.LoadELF(elf); err != nil {
		return err
	}

	res, runErr := m.Call(addr, vals)
	if asJSON {
		payload := map[string]any{
			"input":    input,
			"function": name,
			"address":  fmt.Sprintf("0x%x", addr),
			"result":   res,
		}
		if runErr != nil {
			payload["error"] = runErr.Error()
		}
		data, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Function: %s (0x%x)\n", name, addr)
		if res != nil {
			fmt.Printf("return:   0x%x (%d)\n", res.Return, res.Return)
			for i := 0; i < 8; i++ {
				fmt.Printf("x%-2d      0x%x\n", i, res.X[i])
			}
			fmt.Printf("sp:       0x%x\n", res.SP)
			fmt.Printf("pc:       0x%x\n", res.PC)
			fmt.Printf("nzcv:     0x%x\n", res.NZCV)
			fmt.Printf("stopped:  %v\n", res.Stopped)
		}
	}
	if runErr != nil {
		return runErr
	}
	return nil
}

func parseEmulatedArgs(text string) ([]uint64, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	out := make([]uint64, 0, len(fields))
	for _, f := range fields {
		v, err := strconv.ParseUint(f, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid argument %q (use decimal or 0x...)", f)
		}
		out = append(out, v)
	}
	return out, nil
}

func resolveEmulationTarget(elf *native.ELFParser, spec string) (uint64, string, error) {
	if v, err := strconv.ParseUint(spec, 0, 64); err == nil {
		return v, fmt.Sprintf("0x%x", v), nil
	}
	// Decompiler-style sub_<hex> name.
	if strings.HasPrefix(spec, "sub_") {
		if v, err := strconv.ParseUint(spec[4:], 16, 64); err == nil {
			return v, spec, nil
		}
	}
	for _, sym := range elf.Symbols {
		if sym.Value == 0 || sym.Shndx == 0 {
			continue
		}
		name := elf.GetSymbolName(sym)
		if name == spec {
			return sym.Value, name, nil
		}
	}
	return 0, "", fmt.Errorf("function %q not found in the symbol table (pass an address like 0x... for stripped binaries)", spec)
}
