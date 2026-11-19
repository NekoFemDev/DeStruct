package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/destruct/destruct/internal/native"
)

// handleELFInfo implements `destruct elf info <file>`: a compact
// readelf-style triage summary of one ELF file.
func handleELFInfo(ctx context.Context, args []string) error {
	var input string
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; arg {
		case "-h", "--help":
			printCommandHelp("elf info")
			return nil
		default:
			if strings.HasPrefix(arg, "-") {
				return commandUsageError("elf info", fmt.Errorf("unknown option: %s", arg))
			}
			if input != "" {
				return commandUsageError("elf info", fmt.Errorf("unexpected extra argument: %s", arg))
			}
			input = arg
		}
	}
	if input == "" {
		return commandUsageError("elf info", errors.New("input file required"))
	}

	p, err := native.NewELFParserContext(ctx, input)
	if err != nil {
		return fmt.Errorf("parse ELF: %w", err)
	}
	info, err := p.Info(ctx)
	if err != nil {
		return fmt.Errorf("ELF info: %w", err)
	}
	info.Path = input
	if st, statErr := os.Stat(input); statErr == nil {
		info.Size = st.Size()
	}
	if di, derr := native.LoadDWARF(input); derr == nil {
		s := di.Summary()
		info.DWARF = &s
	} else if !errors.Is(derr, native.ErrNoDWARF) {
		fmt.Fprintf(os.Stderr, "warning: DWARF: %v\n", derr)
	}

	printELFInfo(os.Stdout, info)
	return nil
}

func printELFInfo(w io.Writer, info *native.ELFInfo) {
	fmt.Fprintf(w, "ELF info: %s (%s)\n\n", info.Path, humanSize(info.Size))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  Class:\t%s\n", info.Class)
	fmt.Fprintf(tw, "  Data:\t%s\n", info.Data)
	fmt.Fprintf(tw, "  OS/ABI:\t%s\n", info.OSABI)
	fmt.Fprintf(tw, "  Type:\t%s\n", info.Type)
	fmt.Fprintf(tw, "  Machine:\t%s\n", info.Machine)
	fmt.Fprintf(tw, "  Entry:\t0x%x\n", info.Entry)
	fmt.Fprintf(tw, "  Sections:\t%d\n", info.SectionCount)
	fmt.Fprintf(tw, "  Program headers:\t%d\n", info.ProgramHeaders)
	fmt.Fprintf(tw, "  Symbols:\t%d (defined %d, undefined %d)\n",
		info.SymbolCount, info.DefinedSymbols, info.UndefinedSymbols)
	fmt.Fprintf(tw, "  Functions:\t%d (exported %d, .eh_frame %d)\n",
		info.FunctionCount, len(info.Exports), info.DiscoveredFuncs)
	fmt.Fprintf(tw, "  Stripped:\t%s\n", yesNo(info.Stripped))
	if info.Interp != "" {
		fmt.Fprintf(tw, "  Interpreter:\t%s\n", info.Interp)
	}
	if info.SONAME != "" {
		fmt.Fprintf(tw, "  SONAME:\t%s\n", info.SONAME)
	}
	if len(info.Needed) > 0 {
		fmt.Fprintf(tw, "  NEEDED:\t%s\n", strings.Join(info.Needed, ", "))
	}
	if len(info.RPATH) > 0 {
		fmt.Fprintf(tw, "  RPATH:\t%s\n", strings.Join(info.RPATH, ", "))
	}
	if len(info.RUNPATH) > 0 {
		fmt.Fprintf(tw, "  RUNPATH:\t%s\n", strings.Join(info.RUNPATH, ", "))
	}
	fmt.Fprintf(tw, "  PIE:\t%s\n", yesNo(info.PIE))
	fmt.Fprintf(tw, "  NX:\t%s\n", nxLabel(info))
	fmt.Fprintf(tw, "  RELRO:\t%s\n", relroLabel(info))
	fmt.Fprintf(tw, "  Stack canary:\t%s\n", yesNo(info.Canary))
	if info.FORTIFYFuncs > 0 {
		fmt.Fprintf(tw, "  FORTIFY symbols:\t%d\n", info.FORTIFYFuncs)
	}
	if info.DWARF != nil {
		fmt.Fprintf(tw, "  DWARF:\t%d functions, %d lines, %d params, %d locals\n",
			info.DWARF.Functions, info.DWARF.Lines, info.DWARF.Params, info.DWARF.Locals)
	}
	_ = tw.Flush()

	if len(info.Sections) > 0 {
		fmt.Fprintln(w, "\nSections:")
		sw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(sw, "  [Nr]\tName\tType\tFlags\tAddr\tOffset\tSize")
		for _, s := range info.Sections {
			fmt.Fprintf(sw, "  [%d]\t%s\t%s\t%s\t0x%x\t0x%x\t0x%x\n",
				s.Index, s.Name, s.Type, s.Flags, s.Addr, s.Offset, s.Size)
		}
		_ = sw.Flush()
	}

	printSymbolList(w, "Exports", info.Exports, 20)
	printSymbolList(w, "Imports", info.Imports, 20)
}

func printSymbolList(w io.Writer, label string, names []string, limit int) {
	if len(names) == 0 {
		return
	}
	shown := len(names)
	if limit > 0 && shown > limit {
		shown = limit
	}
	if shown == len(names) {
		fmt.Fprintf(w, "\n%s (%d):\n", label, len(names))
	} else {
		fmt.Fprintf(w, "\n%s (first %d of %d):\n", label, shown, len(names))
	}
	for _, name := range names[:shown] {
		fmt.Fprintf(w, "  %s\n", name)
	}
}

func nxLabel(info *native.ELFInfo) string {
	if !info.GNUStack {
		return "unknown (no PT_GNU_STACK)"
	}
	return yesNo(info.NX)
}

func relroLabel(info *native.ELFInfo) string {
	if !info.RELRO {
		return "no"
	}
	if info.BindNow {
		return "yes (full)"
	}
	return "yes (partial)"
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func humanSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	f := float64(n)
	i := -1
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}
