package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/destruct/destruct/internal/arm64lift"
	"github.com/destruct/destruct/internal/emulate"
	"github.com/destruct/destruct/internal/native"
)

type verifyFunction struct {
	Address string `json:"address"`
	Name    string `json:"name"`
	Size    uint64 `json:"size"`
	Success bool   `json:"success"`
}

type verifyMismatch struct {
	Function string   `json:"function"`
	Address  string   `json:"address"`
	Args     []uint64 `json:"args"`
	Original string   `json:"original,omitempty"`
	Host     string   `json:"host,omitempty"`
	Reason   string   `json:"reason"`
}

// handleELFVerify implements:
//
//	destruct elf verify <original> <decompiled_dir> [--function ...]
func handleELFVerify(ctx context.Context, args []string) error {
	var (
		original  string
		decDir    string
		onlyFunc  string
		argsText  string
		limit     int
		rebuild   bool
		asJSON    bool
		maxInsns  uint64 = 2_000_000
		timeoutMS uint64 = 2000
	)
	i := 0
	for i < len(args) {
		arg := args[i]
		switch arg {
		case "-h", "--help":
			printCommandHelp("elf verify")
			return nil
		case "--function":
			i++
			if i >= len(args) {
				return commandUsageError("elf verify", errors.New("--function requires a value"))
			}
			onlyFunc = args[i]
		case "--args":
			i++
			if i >= len(args) {
				return commandUsageError("elf verify", errors.New("--args requires a value"))
			}
			argsText = args[i]
		case "--limit":
			i++
			if i >= len(args) {
				return commandUsageError("elf verify", errors.New("--limit requires a value"))
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 0 {
				return commandUsageError("elf verify", fmt.Errorf("invalid --limit: %q", args[i]))
			}
			limit = v
		case "--max-insns":
			i++
			if i >= len(args) {
				return commandUsageError("elf verify", errors.New("--max-insns requires a value"))
			}
			v, err := strconv.ParseUint(args[i], 0, 64)
			if err != nil {
				return commandUsageError("elf verify", fmt.Errorf("invalid --max-insns: %w", err))
			}
			maxInsns = v
		case "--timeout":
			i++
			if i >= len(args) {
				return commandUsageError("elf verify", errors.New("--timeout requires a value"))
			}
			v, err := strconv.ParseUint(args[i], 0, 64)
			if err != nil {
				return commandUsageError("elf verify", fmt.Errorf("invalid --timeout: %w", err))
			}
			timeoutMS = v
		case "--rebuild":
			rebuild = true
		case "--json":
			asJSON = true
		default:
			if strings.HasPrefix(arg, "-") {
				return commandUsageError("elf verify", fmt.Errorf("unknown option: %s", arg))
			}
			switch {
			case original == "":
				original = arg
			case decDir == "":
				decDir = arg
			default:
				return commandUsageError("elf verify", errors.New("expected <original> <decompiled_dir>"))
			}
		}
		i++
	}
	if original == "" || decDir == "" {
		return commandUsageError("elf verify", errors.New("original ELF and decompiled directory required"))
	}
	sampleArgs, err := parseEmulatedArgs(argsText)
	if err != nil {
		return commandUsageError("elf verify", err)
	}

	elf, err := native.NewELFParserContext(ctx, original)
	if err != nil {
		return fmt.Errorf("parsing original ELF: %w", err)
	}
	if elf.Header.Machine != native.EM_AARCH64 {
		return fmt.Errorf("verification currently supports AArch64 only (machine 0x%x)", elf.Header.Machine)
	}
	functions, err := loadVerifyFunctions(decDir, onlyFunc)
	if err != nil {
		return err
	}
	driver, err := ensureVerifyDriver(ctx, decDir, functions, rebuild)
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

	type outcome struct {
		tested, matched, mismatch, faults, pointers int
		details                                     []verifyMismatch
	}
	out := outcome{}
	imageBase, image, _ := elf.LoadImage()
	imageSize := uint64(len(image))
	addressLike := func(v uint64) bool {
		if v >= 0x100000000000 {
			return true
		}
		return v >= imageBase && v < imageBase+imageSize
	}
	for idx, fn := range functions {
		if limit > 0 && out.tested >= limit {
			break
		}
		addr, err := strconv.ParseUint(strings.TrimPrefix(fn.Address, "0x"), 16, 64)
		if err != nil {
			continue
		}
		if idx%100 == 0 && idx > 0 {
			fmt.Fprintf(os.Stderr, "  ... %d/%d verified\n", idx, len(functions))
		}
		out.tested++
		origRes, origErr := m.Call(addr, sampleArgs)
		hostVal, hostErr := runVerifyDriver(ctx, driver, addr, sampleArgs, time.Duration(timeoutMS)*time.Millisecond)

		switch {
		case origErr == nil && hostErr == nil:
			if origRes.Return == hostVal {
				out.matched++
			} else if addressLike(origRes.Return) || addressLike(hostVal) {
				out.pointers++
			} else {
				out.mismatch++
				out.details = append(out.details, verifyMismatch{
					Function: fn.Name, Address: fn.Address, Args: sampleArgs,
					Original: fmt.Sprintf("0x%x", origRes.Return),
					Host:     fmt.Sprintf("0x%x", hostVal),
					Reason:   "return mismatch",
				})
			}
		case origErr != nil && hostErr != nil:
			out.faults++
		default:
			out.mismatch++
			reason := "original faulted"
			orig := ""
			host := ""
			if origErr != nil {
				orig = origErr.Error()
			} else {
				orig = fmt.Sprintf("0x%x", origRes.Return)
			}
			if hostErr != nil {
				host = hostErr.Error()
			} else {
				host = fmt.Sprintf("0x%x", hostVal)
			}
			if origErr == nil {
				reason = "host faulted"
			}
			out.details = append(out.details, verifyMismatch{
				Function: fn.Name, Address: fn.Address, Args: sampleArgs,
				Original: orig, Host: host, Reason: reason,
			})
		}
	}

	if asJSON {
		data, _ := json.MarshalIndent(map[string]any{
			"tested":   out.tested,
			"matched":  out.matched,
			"mismatch": out.mismatch,
			"faults":   out.faults,
			"pointers": out.pointers,
			"details":  out.details,
		}, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("verified %d functions: %d matched, %d mismatched, %d pointer-only, %d both-faulted\n",
			out.tested, out.matched, out.mismatch, out.pointers, out.faults)
		for _, d := range out.details {
			fmt.Printf("  mismatch %s (%s) args=%v original=%s host=%s (%s)\n",
				d.Function, d.Address, d.Args, d.Original, d.Host, d.Reason)
		}
	}
	return nil
}

func loadVerifyFunctions(decDir, only string) ([]verifyFunction, error) {
	path := filepath.Join(decDir, "functions.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var all []verifyFunction
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if only == "" {
		out := all[:0]
		for _, f := range all {
			if f.Success {
				out = append(out, f)
			}
		}
		return out, nil
	}
	for _, f := range all {
		if f.Address == only || f.Name == only {
			return []verifyFunction{f}, nil
		}
	}
	// Numeric address not present in functions.json.
	if v, err := strconv.ParseUint(only, 0, 64); err == nil {
		return []verifyFunction{{Address: fmt.Sprintf("0x%x", v), Name: fmt.Sprintf("sub_%x", v), Success: true}}, nil
	}
	return nil, fmt.Errorf("function %q not found in %s", only, path)
}

func ensureVerifyDriver(ctx context.Context, decDir string, functions []verifyFunction, rebuild bool) (string, error) {
	driverC := filepath.Join(decDir, "verify_driver.c")
	driverBin := filepath.Join(decDir, "verify_driver")
	sigPath := driverBin + ".sig"
	sig := verifyFunctionsSig(functions)
	if !rebuild {
		if ok, _ := verifyDriverFresh(driverBin, decDir); ok {
			if old, err := os.ReadFile(sigPath); err == nil && string(old) == sig {
				return driverBin, nil
			}
		}
	}
	if err := writeVerifyDriver(driverC, functions); err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "building host verification driver...\n")
	files, err := collectCFiles(decDir, driverBin)
	if err != nil {
		return "", err
	}
	var compile []string
	for _, f := range files {
		base := filepath.Base(f)
		switch base {
		case "stubs.c", "verify_driver.c", "verify_stubs.c":
			continue
		}
		compile = append(compile, f)
	}
	stubsPath := filepath.Join(decDir, "verify_stubs.c")
	if _, err := arm64lift.GenerateLinkStubsDirForVerify(decDir, stubsPath); err != nil {
		return "", fmt.Errorf("generate verify stubs: %w", err)
	}
	compile = append(compile, driverC, stubsPath)
	clang, err := exec.LookPath("clang")
	if err != nil {
		return "", fmt.Errorf("clang not found in PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, clang, append([]string{"-std=c11", "-w", "-o", driverBin}, compile...)...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("compile verify driver: %w", err)
	}
	if err := os.WriteFile(sigPath, []byte(sig), 0o644); err != nil {
		return "", err
	}
	return driverBin, nil
}

func verifyFunctionsSig(functions []verifyFunction) string {
	h := fnv.New64a()
	for _, f := range functions {
		fmt.Fprintf(h, "%s;%s;%t\n", f.Address, f.Name, f.Success)
	}
	return fmt.Sprintf("%x", h.Sum64())
}

func verifyDriverFresh(driverBin, decDir string) (bool, error) {
	info, err := os.Stat(driverBin)
	if err != nil {
		return false, err
	}
	binTime := info.ModTime()
	fresh := true
	err = filepath.WalkDir(decDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".c") {
			return nil
		}
		base := filepath.Base(path)
		if base == "verify_driver.c" || base == "verify_stubs.c" || base == "stubs.c" {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.ModTime().After(binTime) {
			fresh = false
			return filepath.SkipAll
		}
		return nil
	})
	return fresh, err
}

func writeVerifyDriver(path string, functions []verifyFunction) error {
	var b strings.Builder
	b.WriteString("/* Auto-generated by DeStruct: host-side differential driver. */\n")
	b.WriteString("#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n\n")
	b.WriteString("typedef uint64_t (*fn8)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);\n")
	b.WriteString("struct entry { uint64_t addr; fn8 fn; };\n")
	for _, fn := range functions {
		name := arm64lift.FunctionCName(fn.Name)
		if name == "" {
			continue
		}
		fmt.Fprintf(&b, "extern uint64_t %s();\n", name)
	}
	b.WriteString("\nstatic struct entry entries[] = {\n")
	for _, fn := range functions {
		name := arm64lift.FunctionCName(fn.Name)
		addr, err := strconv.ParseUint(strings.TrimPrefix(fn.Address, "0x"), 16, 64)
		if err != nil || name == "" {
			continue
		}
		fmt.Fprintf(&b, "    { 0x%xULL, (fn8)%s },\n", addr, name)
	}
	b.WriteString("};\n\n")
	b.WriteString(`int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <address> [a0..a7]\n", argv[0]);
        return 2;
    }
    uint64_t target = strtoull(argv[1], 0, 0);
    uint64_t a[8] = {0};
    for (int i = 0; i < 8 && i + 2 < argc; i++) {
        a[i] = strtoull(argv[i + 2], 0, 0);
    }
    for (unsigned i = 0; i < sizeof(entries)/sizeof(entries[0]); i++) {
        if (entries[i].addr == target) {
            uint64_t r = entries[i].fn(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
            printf("%llu\n", (unsigned long long)r);
            return 0;
        }
    }
    fprintf(stderr, "function 0x%llx not found\n", (unsigned long long)target);
    return 2;
}
`)
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func runVerifyDriver(ctx context.Context, driver string, addr uint64, args []uint64, timeout time.Duration) (uint64, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmdArgs := []string{fmt.Sprintf("0x%x", addr)}
	for _, a := range args {
		cmdArgs = append(cmdArgs, fmt.Sprintf("0x%x", a))
	}
	cmd := exec.CommandContext(cctx, driver, cmdArgs...)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if cctx.Err() != nil {
		return 0, fmt.Errorf("host timeout")
	}
	if err != nil {
		return 0, fmt.Errorf("host fault: %v: %s", err, strings.TrimSpace(out.String()))
	}
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	last := ""
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			last = strings.TrimSpace(sc.Text())
		}
	}
	v, err := strconv.ParseUint(last, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("host output %q", last)
	}
	return v, nil
}
