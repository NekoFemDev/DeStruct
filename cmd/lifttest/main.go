package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/destruct/destruct/internal/arm64lift"
	"github.com/destruct/destruct/internal/native"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: lifttest <elf> <symbol> [params...]")
	}
	elfPath := args[0]
	symName := args[1]
	params := args[2:]

	p, err := native.NewELFParser(elfPath)
	if err != nil {
		panic(err)
	}

	var target *native.SymbolEntry
	for i := range p.Symbols {
		if p.GetSymbolName(p.Symbols[i]) == symName {
			target = &p.Symbols[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("symbol not found: %s", symName)
	}

	var sec *native.SectionHeader
	for i := range p.Sections {
		s := &p.Sections[i]
		if target.Value >= s.Addr && target.Value < s.Addr+s.Size {
			sec = s
			break
		}
	}
	if sec == nil {
		return fmt.Errorf("no section contains address 0x%x", target.Value)
	}
	fileOff := sec.Offset + (target.Value - sec.Addr)
	code := p.Data[fileOff : fileOff+target.Size]

	d, err := native.NewARM64Disassembler()
	if err != nil {
		panic(err)
	}
	defer d.Close()

	insns, err := d.DisassembleDetailed(code, target.Value)
	if err != nil {
		panic(err)
	}

	resolver := p.SymbolResolver()
	strResolver := func(addr uint64) (string, bool) {
		return p.ReadCString(addr)
	}

	stmts := arm64lift.LiftFunctionWithData(insns, params, resolver, strResolver, p.DataReader(), true)
	fmt.Printf("// %s\n", symName)
	arm64lift.RenderStmts(os.Stdout, stmts, 1)
	return nil
}
