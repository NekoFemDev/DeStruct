package main

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	apktoolHint   = "install apktool and put it on PATH (https://apktool.org)"
	zipalignHint  = "install the Android SDK build-tools and put zipalign on PATH (usually $ANDROID_HOME/build-tools/<version>)"
	apksignerHint = "install the Android SDK build-tools and put apksigner on PATH (usually $ANDROID_HOME/build-tools/<version>)"
)

func apkUsage() string {
	return `Usage:
  destruct apk build <dir> -o <out.apk> [--arch <abi>]
  destruct apk sign <in.apk> -k <keystore> -p <password> -o <out.apk>

Subcommands:
  build   Repack an apktool project and optionally strip native libraries
          for every ABI except the requested one
  sign    zipalign + apksigner an APK with the given keystore

build options:
  -o, --output <apk>   Output APK path (required)
  --arch <abi>         Keep only lib/<abi>/ (e.g. arm64-v8a, armeabi-v7a)
  -h, --help           Show this help

sign options:
  -o, --output <apk>   Signed output APK path (required)
  -k, --keystore <ks>  Keystore path (JKS/PKCS12) (required)
  -p, --password <pw>  Keystore password (required; may be empty)
  -h, --help           Show this help

External tools (must be on PATH):
  apktool    required by 'apk build'
  zipalign   required by 'apk sign' (Android SDK build-tools)
  apksigner  required by 'apk sign' (Android SDK build-tools)

Examples:
  destruct apk build decoded/ -o app-unsigned.apk --arch arm64-v8a
  destruct apk sign app-unsigned.apk -k release.jks -p "$KS_PASS" -o app.apk`
}

// handleAPK dispatches `destruct apk <subcommand>`.
func handleAPK(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Println(apkUsage())
		return errUsage
	}

	switch sub := args[0]; sub {
	case "build":
		return handleAPKBuild(ctx, args[1:])
	case "sign":
		return handleAPKSign(ctx, args[1:])
	case "help", "-h", "--help":
		fmt.Println(apkUsage())
		return nil
	default:
		fmt.Println(apkUsage())
		return fmt.Errorf("unknown apk subcommand: %s", sub)
	}
}

// ---------------------------------------------------------------------------
// apk build
// ---------------------------------------------------------------------------

type apkBuildOpts struct {
	dir    string
	output string
	arch   string
	help   bool
}

func parseAPKBuildFlags(args []string) (apkBuildOpts, error) {
	var opts apkBuildOpts

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			opts.help = true
		case arg == "-o" || arg == "--output":
			v, err := nextFlagValue(args, &i, arg)
			if err != nil {
				return opts, err
			}
			opts.output = v
		case strings.HasPrefix(arg, "--output="):
			opts.output = strings.TrimPrefix(arg, "--output=")
		case arg == "--arch":
			v, err := nextFlagValue(args, &i, arg)
			if err != nil {
				return opts, err
			}
			opts.arch = v
		case strings.HasPrefix(arg, "--arch="):
			opts.arch = strings.TrimPrefix(arg, "--arch=")
		case strings.HasPrefix(arg, "-"):
			return opts, fmt.Errorf("unknown option %s", arg)
		default:
			if opts.dir != "" {
				return opts, fmt.Errorf("unexpected extra argument %s", arg)
			}
			opts.dir = arg
		}
	}

	return opts, nil
}

func handleAPKBuild(ctx context.Context, args []string) error {
	opts, err := parseAPKBuildFlags(args)
	if err != nil {
		return err
	}
	if opts.help {
		fmt.Println(apkUsage())
		return nil
	}
	if opts.dir == "" {
		return fmt.Errorf("apktool project directory required\nUsage: destruct apk build <dir> -o <out.apk> [--arch <abi>]")
	}
	if opts.output == "" {
		return fmt.Errorf("output APK required (-o/--output)\nUsage: destruct apk build <dir> -o <out.apk> [--arch <abi>]")
	}
	info, err := os.Stat(opts.dir)
	if err != nil {
		return fmt.Errorf("reading project directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", opts.dir)
	}

	opts.arch = strings.Trim(strings.TrimSpace(opts.arch), "/")
	if strings.Contains(opts.arch, "/") {
		return fmt.Errorf("invalid --arch %q: expected a single ABI directory name such as arm64-v8a", opts.arch)
	}

	// Resolve the tool before running it so a missing apktool is reported
	// cleanly instead of as a generic exec error.
	apktool, err := lookTool("apktool", apktoolHint)
	if err != nil {
		return err
	}

	fmt.Printf("Building %s -> %s\n", opts.dir, opts.output)
	if err := runTool(ctx, apktool, "b", opts.dir, "-o", opts.output); err != nil {
		return err
	}
	if _, err := os.Stat(opts.output); err != nil {
		return fmt.Errorf("apktool reported success but %s is missing: %w", opts.output, err)
	}

	if opts.arch == "" {
		fmt.Printf("Wrote %s (all native ABIs kept)\n", opts.output)
		return nil
	}

	removed, err := filterAPKArch(opts.output, opts.arch)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s (kept lib/%s/, removed %d entr%s from other ABIs)\n",
		opts.output, opts.arch, removed, pluralY(removed))
	return nil
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// ---------------------------------------------------------------------------
// apk sign
// ---------------------------------------------------------------------------

type apkSignOpts struct {
	input       string
	keystore    string
	password    string
	passwordSet bool
	output      string
	help        bool
}

func parseAPKSignFlags(args []string) (apkSignOpts, error) {
	var opts apkSignOpts

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			opts.help = true
		case arg == "-o" || arg == "--output":
			v, err := nextFlagValue(args, &i, arg)
			if err != nil {
				return opts, err
			}
			opts.output = v
		case strings.HasPrefix(arg, "--output="):
			opts.output = strings.TrimPrefix(arg, "--output=")
		case arg == "-k" || arg == "--keystore" || arg == "--ks":
			v, err := nextFlagValue(args, &i, arg)
			if err != nil {
				return opts, err
			}
			opts.keystore = v
		case strings.HasPrefix(arg, "--keystore="):
			opts.keystore = strings.TrimPrefix(arg, "--keystore=")
		case strings.HasPrefix(arg, "--ks="):
			opts.keystore = strings.TrimPrefix(arg, "--ks=")
		case arg == "-p" || arg == "--password":
			v, err := nextFlagValue(args, &i, arg)
			if err != nil {
				return opts, err
			}
			opts.password = v
			opts.passwordSet = true
		case strings.HasPrefix(arg, "--password="):
			opts.password = strings.TrimPrefix(arg, "--password=")
			opts.passwordSet = true
		case strings.HasPrefix(arg, "-"):
			return opts, fmt.Errorf("unknown option %s", arg)
		default:
			if opts.input != "" {
				return opts, fmt.Errorf("unexpected extra argument %s", arg)
			}
			opts.input = arg
		}
	}

	return opts, nil
}

func handleAPKSign(ctx context.Context, args []string) error {
	opts, err := parseAPKSignFlags(args)
	if err != nil {
		return err
	}
	if opts.help {
		fmt.Println(apkUsage())
		return nil
	}

	const usage = "Usage: destruct apk sign <in.apk> -k <keystore> -p <password> -o <out.apk>"
	if opts.input == "" {
		return fmt.Errorf("input APK required\n%s", usage)
	}
	if opts.keystore == "" {
		return fmt.Errorf("keystore required (-k/--keystore)\n%s", usage)
	}
	if !opts.passwordSet {
		return fmt.Errorf("keystore password required (-p/--password; pass an empty value if the key has none)\n%s", usage)
	}
	if opts.output == "" {
		return fmt.Errorf("output APK required (-o/--output)\n%s", usage)
	}

	inputInfo, err := os.Stat(opts.input)
	if err != nil {
		return fmt.Errorf("reading input APK: %w", err)
	}
	if inputInfo.IsDir() {
		return fmt.Errorf("%s is a directory, not an APK", opts.input)
	}
	if _, err := os.Stat(opts.keystore); err != nil {
		return fmt.Errorf("reading keystore: %w", err)
	}

	// Signing in place would clobber the input if it is also the output.
	if same, err := sameFile(opts.input, opts.output); err == nil && same {
		return fmt.Errorf("output %s is the input APK; choose a different -o path", opts.output)
	}

	// Resolve both tools before doing any work so a missing build-tools
	// binary fails fast rather than after a successful zipalign run.
	zipalign, err := lookTool("zipalign", zipalignHint)
	if err != nil {
		return err
	}
	apksigner, err := lookTool("apksigner", apksignerHint)
	if err != nil {
		return err
	}

	if dir := filepath.Dir(opts.output); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}

	// Temporary aligned APK lives in a private temp dir; RemoveAll runs
	// on every exit path (success, tool failure, cancellation).
	tmpDir, err := os.MkdirTemp("", "destruct-apk-sign-*")
	if err != nil {
		return fmt.Errorf("creating temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	aligned := filepath.Join(tmpDir, "aligned.apk")

	fmt.Printf("Aligning %s\n", opts.input)
	if err := runTool(ctx, zipalign, "-p", "-f", "4", opts.input, aligned); err != nil {
		return err
	}

	fmt.Printf("Signing %s -> %s\n", opts.input, opts.output)
	if err := runTool(ctx, apksigner, "sign",
		"--ks", opts.keystore,
		"--ks-pass", "pass:"+opts.password,
		"--out", opts.output,
		aligned,
	); err != nil {
		return err
	}
	if _, err := os.Stat(opts.output); err != nil {
		return fmt.Errorf("apksigner reported success but %s is missing: %w", opts.output, err)
	}

	fmt.Printf("Wrote %s\n", opts.output)
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// nextFlagValue consumes the value following a space-separated flag.
func nextFlagValue(args []string, i *int, flag string) (string, error) {
	if *i+1 >= len(args) {
		return "", fmt.Errorf("%s requires a value", flag)
	}
	*i = *i + 1
	return args[*i], nil
}

// lookTool resolves an external tool on PATH with an actionable error that
// names the tool and where to get it.
func lookTool(name, hint string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found on PATH: %s", name, hint)
	}
	return path, nil
}

// runTool streams an external command's stdout/stderr to the terminal and
// wraps failures with the tool name. Context cancellation is returned as-is
// so callers can distinguish Ctrl-C from a tool error.
func runTool(ctx context.Context, path string, args ...string) error {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%s failed: %w", filepath.Base(path), err)
	}
	return nil
}

// sameFile reports whether a and b resolve to the same existing path.
func sameFile(a, b string) (bool, error) {
	ai, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(ai, bi), nil
}

// filterAPKArch rewrites the APK at apkPath in place, keeping only
// lib/<arch>/ entries. It returns the number of removed entries.
//
// The rewrite goes through a sibling temp file and os.Rename so a crash or
// error cannot leave a half-written APK. Entry order, names, comments,
// timestamps, compression methods and directory entries are preserved.
func filterAPKArch(apkPath, arch string) (int, error) {
	arch = strings.Trim(strings.TrimSpace(arch), "/")
	if arch == "" {
		return 0, fmt.Errorf("empty ABI")
	}
	if strings.Contains(arch, "/") {
		return 0, fmt.Errorf("invalid ABI %q: expected a single directory name", arch)
	}

	r, err := zip.OpenReader(apkPath)
	if err != nil {
		return 0, fmt.Errorf("opening %s as APK/ZIP: %w", apkPath, err)
	}

	// Validate the requested ABI before rewriting anything: silently
	// stripping every native library because of a typo would produce an
	// APK that installs but crashes at the first JNI call.
	availableSet := make(map[string]bool)
	matched := false
	for _, f := range r.File {
		abi := apkEntryABI(f.Name)
		if abi == "" {
			continue
		}
		availableSet[abi] = true
		if abi == arch {
			matched = true
		}
	}
	if len(availableSet) == 0 {
		r.Close()
		return 0, fmt.Errorf("%s has no lib/<abi>/ entries to filter", apkPath)
	}
	if !matched {
		available := make([]string, 0, len(availableSet))
		for abi := range availableSet {
			available = append(available, abi)
		}
		sort.Strings(available)
		r.Close()
		return 0, fmt.Errorf("no native libraries for ABI %q in %s (available: %s)",
			arch, apkPath, strings.Join(available, ", "))
	}

	tmp, err := os.CreateTemp(filepath.Dir(apkPath), ".destruct-apk-*.zip")
	if err != nil {
		r.Close()
		return 0, fmt.Errorf("creating temp APK next to %s: %w", apkPath, err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			os.Remove(tmpPath)
		}
	}()

	zw := zip.NewWriter(tmp)
	if r.Comment != "" {
		if err := zw.SetComment(r.Comment); err != nil {
			zw.Close()
			tmp.Close()
			r.Close()
			return 0, fmt.Errorf("copying APK archive comment: %w", err)
		}
	}
	removed := 0
	for _, f := range r.File {
		if abi := apkEntryABI(f.Name); abi != "" && abi != arch {
			removed++
			continue
		}
		if err := copyZipEntry(zw, f); err != nil {
			zw.Close()
			tmp.Close()
			r.Close()
			return 0, fmt.Errorf("repacking %s: %w", f.Name, err)
		}
	}

	if err := zw.Close(); err != nil {
		tmp.Close()
		r.Close()
		return 0, fmt.Errorf("finishing repacked APK: %w", err)
	}
	if err := tmp.Close(); err != nil {
		r.Close()
		return 0, fmt.Errorf("closing temp APK: %w", err)
	}
	// Close the source before replacing it: Windows refuses to rename
	// over a file that still has an open handle.
	if err := r.Close(); err != nil {
		return 0, fmt.Errorf("closing %s: %w", apkPath, err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return 0, fmt.Errorf("setting temp APK permissions: %w", err)
	}
	if err := os.Rename(tmpPath, apkPath); err != nil {
		return 0, fmt.Errorf("replacing %s: %w", apkPath, err)
	}
	committed = true

	return removed, nil
}

// apkEntryABI returns the ABI directory for a "lib/<abi>/..." entry, or ""
// when the entry is not under lib/.
func apkEntryABI(name string) string {
	const prefix = "lib/"
	if !strings.HasPrefix(name, prefix) {
		return ""
	}
	rest := name[len(prefix):]
	if rest == "" {
		return ""
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// copyZipEntry clones one archive entry into w, preserving its header.
func copyZipEntry(w *zip.Writer, f *zip.File) error {
	hdr := f.FileHeader
	dst, err := w.CreateHeader(&hdr)
	if err != nil {
		return err
	}
	if f.FileInfo().IsDir() {
		return nil
	}

	src, err := f.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	_, err = io.Copy(dst, src)
	return err
}
