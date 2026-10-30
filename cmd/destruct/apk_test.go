package main

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestAPK(t *testing.T, path string, entries map[string]string) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	// Sort-free is fine here: map iteration order does not matter to the
	// code under test (it preserves the order it reads).
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func readTestAPK(t *testing.T, path string) (map[string]string, []string) {
	t.Helper()

	r, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	entries := make(map[string]string)
	var order []string
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		entries[f.Name] = string(data)
		order = append(order, f.Name)
	}
	return entries, order
}

func TestParseAPKBuildFlags(t *testing.T) {
	opts, err := parseAPKBuildFlags([]string{"decoded/", "-o", "out.apk", "--arch", "arm64-v8a"})
	if err != nil {
		t.Fatalf("parseAPKBuildFlags: %v", err)
	}
	if opts.dir != "decoded/" || opts.output != "out.apk" || opts.arch != "arm64-v8a" {
		t.Fatalf("opts = %+v", opts)
	}

	opts, err = parseAPKBuildFlags([]string{"decoded/", "--output=out.apk", "--arch=x86_64"})
	if err != nil {
		t.Fatalf("parseAPKBuildFlags long form: %v", err)
	}
	if opts.output != "out.apk" || opts.arch != "x86_64" {
		t.Fatalf("opts = %+v", opts)
	}

	if opts, err := parseAPKBuildFlags([]string{"-h"}); err != nil || !opts.help {
		t.Fatalf("help: opts=%+v err=%v", opts, err)
	}

	for _, args := range [][]string{
		{"decoded/", "-o"},      // missing value
		{"decoded/", "--bogus"}, // unknown option
		{"one/", "two/"},        // two project dirs
	} {
		if _, err := parseAPKBuildFlags(args); err == nil {
			t.Errorf("parseAPKBuildFlags(%v): expected error", args)
		}
	}
}

func TestParseAPKSignFlags(t *testing.T) {
	opts, err := parseAPKSignFlags([]string{"in.apk", "-k", "ks.jks", "-p", "secret", "-o", "out.apk"})
	if err != nil {
		t.Fatalf("parseAPKSignFlags: %v", err)
	}
	if opts.input != "in.apk" || opts.keystore != "ks.jks" || opts.password != "secret" || opts.output != "out.apk" || !opts.passwordSet {
		t.Fatalf("opts = %+v", opts)
	}

	opts, err = parseAPKSignFlags([]string{"in.apk", "--keystore=ks.jks", "--password=", "--output=out.apk"})
	if err != nil {
		t.Fatalf("parseAPKSignFlags long form: %v", err)
	}
	if !opts.passwordSet || opts.password != "" {
		t.Fatalf("empty password should still count as explicitly set: %+v", opts)
	}

	if opts, err := parseAPKSignFlags([]string{"--help"}); err != nil || !opts.help {
		t.Fatalf("help: opts=%+v err=%v", opts, err)
	}

	for _, args := range [][]string{
		{"in.apk", "-k"},       // missing value
		{"in.apk", "--bogus"},  // unknown option
		{"one.apk", "two.apk"}, // two inputs
	} {
		if _, err := parseAPKSignFlags(args); err == nil {
			t.Errorf("parseAPKSignFlags(%v): expected error", args)
		}
	}
}

func TestAPKEntryABI(t *testing.T) {
	cases := map[string]string{
		"lib/arm64-v8a/libfoo.so":      "arm64-v8a",
		"lib/armeabi-v7a/libfoo.so":    "armeabi-v7a",
		"lib/x86/libfoo.so":            "x86",
		"lib/arm64-v8a":                "arm64-v8a",
		"lib/":                         "",
		"lib":                          "",
		"classes.dex":                  "",
		"assets/lib/arm64-v8a/fake.so": "",
	}
	for name, want := range cases {
		if got := apkEntryABI(name); got != want {
			t.Errorf("apkEntryABI(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestFilterAPKArch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.apk")
	writeTestAPK(t, path, map[string]string{
		"AndroidManifest.xml":             "manifest",
		"classes.dex":                     "dex",
		"lib/arm64-v8a/libfoo.so":         "arm64",
		"lib/armeabi-v7a/libfoo.so":       "armv7",
		"lib/x86/libfoo.so":               "x86",
		"lib/x86_64/libfoo.so":            "x86_64",
		"assets/lib/arm64-v8a/not-native": "asset",
	})

	removed, err := filterAPKArch(path, "arm64-v8a")
	if err != nil {
		t.Fatalf("filterAPKArch: %v", err)
	}
	if removed != 3 {
		t.Fatalf("removed = %d, want 3", removed)
	}

	entries, _ := readTestAPK(t, path)
	for _, keep := range []string{"AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libfoo.so", "assets/lib/arm64-v8a/not-native"} {
		if _, ok := entries[keep]; !ok {
			t.Errorf("expected %q to survive filtering", keep)
		}
	}
	for _, drop := range []string{"lib/armeabi-v7a/libfoo.so", "lib/x86/libfoo.so", "lib/x86_64/libfoo.so"} {
		if _, ok := entries[drop]; ok {
			t.Errorf("expected %q to be removed", drop)
		}
	}
	if entries["lib/arm64-v8a/libfoo.so"] != "arm64" {
		t.Errorf("payload was not preserved: %q", entries["lib/arm64-v8a/libfoo.so"])
	}
}

func TestFilterAPKArchUnknownABI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.apk")
	writeTestAPK(t, path, map[string]string{
		"classes.dex":             "dex",
		"lib/arm64-v8a/libfoo.so": "arm64",
	})

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = filterAPKArch(path, "mips")
	if err == nil {
		t.Fatal("expected an error for a missing ABI")
	}
	if !strings.Contains(err.Error(), "arm64-v8a") {
		t.Errorf("error should list available ABIs, got: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("APK was modified even though filtering failed")
	}
}

func TestHandleAPKUnknownSubcommand(t *testing.T) {
	if err := handleAPK(context.Background(), []string{"bogus"}); err == nil {
		t.Fatal("expected an error for an unknown apk subcommand")
	}
}

// Both handlers must fail with an actionable message when their external
// tools are absent, before touching the input/output files.
func TestHandleAPKBuildMissingApktool(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	dir := t.TempDir()
	out := filepath.Join(t.TempDir(), "out.apk")
	err := handleAPKBuild(context.Background(), []string{dir, "-o", out})
	if err == nil {
		t.Fatal("expected an error when apktool is missing")
	}
	if !strings.Contains(err.Error(), "apktool not found on PATH") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleAPKSignMissingTools(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	dir := t.TempDir()
	input := filepath.Join(dir, "in.apk")
	keystore := filepath.Join(dir, "ks.jks")
	out := filepath.Join(dir, "out.apk")
	for _, p := range []string{input, keystore} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	err := handleAPKSign(context.Background(), []string{input, "-k", keystore, "-p", "pw", "-o", out})
	if err == nil {
		t.Fatal("expected an error when zipalign/apksigner are missing")
	}
	if !strings.Contains(err.Error(), "not found on PATH") {
		t.Fatalf("unexpected error: %v", err)
	}
}
