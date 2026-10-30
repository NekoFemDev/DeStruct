package js

import (
	"strings"

	tjs "github.com/tdewolff/parse/v2/js"
)

// Print renders ast back to JavaScript text.
//
// tdewolff's AST carries its own serializer: every node implements
// INode.JS(io.Writer), block statements indent their children by four spaces
// through parse.Indenter, and program-level statements are separated by
// newlines. That output is exactly the beautified shape DeStruct v1 wants, so
// Print deliberately delegates to it instead of maintaining a parallel
// printer by hand.
//
// It stays a separate step so a bespoke pretty-printer (multi-line call
// arguments, consistent string quoting, source comments) can replace it
// here without touching the transform passes.
//
// The result is not guaranteed to end with a newline.
func Print(ast *tjs.AST) string {
	var sb strings.Builder
	ast.JS(&sb)
	return sb.String()
}
