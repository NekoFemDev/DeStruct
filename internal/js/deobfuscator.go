// Package js implements DeStruct's JavaScript deobfuscation pipeline: a
// beautifier plus a small, conservative set of AST rewrites that strip the
// most common minifier and obfuscator idioms from a script.
//
// The pipeline is:
//
//	Parse      raw text -> AST   (github.com/tdewolff/parse/v2/js)
//	Transform  AST      -> AST   (visitor.go)
//	Print      AST      -> text  (printer.go)
//
// Scope of v1:
//
//   - constant folding: !0 -> true, !1 -> false, ![] -> false, !![] -> true,
//     arithmetic between numeric literals, void 0 -> undefined;
//   - IIFE unwrapping: !function(){...}() -> { ... };
//   - debugger statement removal.
//
// The governing rule for every pass: never rewrite an expression when the
// rewrite could change program semantics. A missed fold is acceptable; a
// wrong fold is not.
package js

import (
	"fmt"

	"github.com/tdewolff/parse/v2"
	tjs "github.com/tdewolff/parse/v2/js"
)

// Deobfuscate parses rawJS, applies the v1 transform passes, and returns
// beautified JavaScript.
//
// rawJS is expected to be a complete script (a statement list), which is what
// minified bundles and obfuscated payloads are. On malformed input an error is
// returned.
//
// The parser is treated as adversarial: parser panics on malformed input or
// parser bugs are recovered and reported as errors instead of crashing the
// process.
func Deobfuscate(rawJS string) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = ""
			if e, ok := r.(error); ok {
				err = fmt.Errorf("js: parse panic: %w", e)
			} else {
				err = fmt.Errorf("js: parse panic: %v", r)
			}
		}
	}()

	ast, parseErr := tjs.Parse(parse.NewInputString(rawJS), tjs.Options{})
	if parseErr != nil {
		return "", fmt.Errorf("js: parsing input: %w", parseErr)
	}

	transform(ast)

	return Print(ast), nil
}
