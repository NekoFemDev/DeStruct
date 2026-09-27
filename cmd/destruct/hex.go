package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/destruct/destruct/internal/hexedit"
)

// hexOptions is the parsed `destruct hex` command line.
type hexOptions struct {
	path     string
	commands []string
	yes      bool
	readOnly bool
	help     bool
}

func hexUsageLine() string {
	return "Usage: destruct hex <file> [-c <command>]... [-y|--yes] [--read-only]"
}

func printHexHelp() {
	fmt.Println(hexUsageLine())
	fmt.Println(`
Opens an interactive hex-editing session over <file>. The file is mapped
read-only; staged patches are only written by 'apply' (original file,
after a confirmation) or 'save <path>' (different path).

Options:
  -c, --command <cmd>  run one command and exit; repeatable, fail-fast
                       (exit codes: 0 ok, 1 command error, 2 usage)
  -y, --yes            skip apply/save confirmation prompts (for scripts)
      --read-only      refuse patch/apply/save commands
  -h, --help           show this help

Commands inside a session: read, disasm, decompile, search, goto,
patch, diff, drop, clear, apply, save, info, help, exit. Type 'help'
in an interactive session for the full reference.

Examples:
  destruct hex libil2cpp.so
  destruct hex lib.so -c "info" -c "disasm 0x1000 32"
  destruct hex lib.so -c "search \"UnityPlayer\"" -c "read 0x2000"
  destruct hex lib.so --read-only -c "info"`)
}

// parseHexFlags parses `destruct hex` arguments.
func parseHexFlags(args []string) (hexOptions, error) {
	var opts hexOptions
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; arg {
		case "-y", "--yes":
			opts.yes = true
		case "--read-only":
			opts.readOnly = true
		case "-h", "--help":
			opts.help = true
		case "-c", "--command":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("%s requires a command argument", arg)
			}
			i++
			opts.commands = append(opts.commands, args[i])
		default:
			if strings.HasPrefix(arg, "-") {
				return opts, fmt.Errorf("unknown option %s", arg)
			}
			if opts.path != "" {
				return opts, fmt.Errorf("unexpected extra argument %s", arg)
			}
			opts.path = arg
		}
	}
	return opts, nil
}

// handleHex implements `destruct hex`.
func handleHex(ctx context.Context, args []string) error {
	opts, err := parseHexFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "destruct hex: %v\n", err)
		fmt.Fprintln(os.Stderr, hexUsageLine())
		return errUsage
	}
	if opts.help {
		printHexHelp()
		return nil
	}
	if opts.path == "" {
		fmt.Fprintln(os.Stderr, "destruct hex: input file required")
		fmt.Fprintln(os.Stderr, hexUsageLine())
		return errUsage
	}
	return runHex(ctx, opts, os.Stdin, os.Stdout)
}

// runHex opens the session and either runs the -c batch (fail-fast) or
// the interactive loop.
func runHex(ctx context.Context, opts hexOptions, in io.Reader, out io.Writer) error {
	sess, err := hexedit.Open(opts.path, hexedit.Options{
		ReadOnly: opts.readOnly,
		Yes:      opts.yes,
		Out:      out,
		In:       in,
	})
	if err != nil {
		return err
	}
	defer sess.Close()

	if len(opts.commands) > 0 {
		for _, line := range opts.commands {
			quit, err := sess.Exec(ctx, line)
			if err != nil {
				return fmt.Errorf("%s: %w", strings.TrimSpace(line), err)
			}
			if quit {
				break
			}
		}
		return nil
	}
	return repl(sess, in, out)
}

// repl runs the interactive command loop. Input is read by a single
// scanner goroutine feeding a channel; confirmation prompts consume
// from that same channel (via SetConfirm), so apply/save answers never
// race a second buffered reader for the same terminal.
//
// Ctrl-C semantics: while a command runs, SIGINT cancels that command's
// context and returns to the prompt; at the prompt it exits the
// session. Commands that cannot be interrupted mid-call (the lifter)
// finish under their own budget before the prompt returns.
func repl(sess *hexedit.Session, in io.Reader, out io.Writer) error {
	// Register the signal handler before the first output so a test
	// (or a user) waiting on the banner can rely on it being active.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	fmt.Fprintf(out, "DeStruct hex: %s (%d bytes). 'help' for commands, 'exit' to leave.\n",
		sess.Path(), sess.Size())

	lines := make(chan string)
	scanErrCh := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			lines <- sc.Text()
		}
		scanErrCh <- sc.Err()
		close(lines)
	}()

	sess.SetConfirm(func(prompt string) bool {
		fmt.Fprintf(out, "%s [y/N] ", prompt)
		select {
		case line, ok := <-lines:
			if !ok {
				return false
			}
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "y", "yes":
				return true
			default:
				return false
			}
		case <-sigCh:
			fmt.Fprintln(out)
			return false
		}
	})

	for {
		fmt.Fprintf(out, "%s> ", sess.Cursor())
		select {
		case line, ok := <-lines:
			if !ok {
				fmt.Fprintln(out)
				if sess.Dirty() {
					fmt.Fprintln(out, "staged patches discarded (not applied)")
				}
				return <-scanErrCh
			}
			quit, err := execInterruptible(sess, line, sigCh, out)
			if err != nil {
				fmt.Fprintf(out, "error: %v\n", err)
			}
			if quit {
				return nil
			}
		case <-sigCh:
			fmt.Fprintln(out)
			if sess.Dirty() {
				fmt.Fprintln(out, "staged patches discarded (not applied)")
			}
			return nil
		}
	}
}

// execResult is one command's outcome: quit reports that the session
// should end (exit/quit/q, or q! discarding staging), err carries a
// command error. Both fields must survive the interruptible wrapper -
// dropping quit here is what made `exit` ignore the prompt.
type execResult struct {
	quit bool
	err  error
}

// execInterruptible runs one command in its own goroutine so Ctrl-C can
// cancel it without ending the session. If a command ignores
// cancellation, the prompt waits for it to finish.
func execInterruptible(sess *hexedit.Session, line string, sigCh <-chan os.Signal, out io.Writer) (bool, error) {
	cmdCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan execResult, 1)
	go func() {
		quit, err := sess.Exec(cmdCtx, line)
		done <- execResult{quit: quit, err: err}
	}()

	select {
	case r := <-done:
		return r.quit, r.err
	case <-sigCh:
		cancel()
		r := <-done
		fmt.Fprintln(out, "interrupted")
		if r.err != nil && !errors.Is(r.err, context.Canceled) {
			return r.quit, r.err
		}
		return r.quit, nil
	}
}
