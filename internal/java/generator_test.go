package java

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/ir"
)

// TestDollarToDot mirrors internal/jvm's own test for the identical
// logic (duplicated here rather than shared - see dollarToDot's own
// doc comment for why): an ordinary nested class reads with dots, but
// a synthetic anonymous/local class - digit right after the '$' - must
// keep it, since "Outer.3" isn't valid Java syntax.
func TestDollarToDot(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ordinary nested class", "Outer$Inner", "Outer.Inner"},
		{"anonymous class", "Outer$3", "Outer$3"},
		{"local class", "Outer$1LocalClass", "Outer$1LocalClass"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dollarToDot(c.in); got != c.want {
				t.Errorf("dollarToDot(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestGenerateClass_NativeMethodHasNoBody exercises the actual
// template end to end: a real bug had a native (and, the same bug, an
// abstract) method rendered with a "{ // TODO }" body - illegal Java,
// since a native/abstract method declaration must end in a bare ";"
// with no body at all.
func TestGenerateClass_NativeMethodHasNoBody(t *testing.T) {
	class := &ir.Class{
		Name:   "Sample",
		Access: ir.AccPublic,
		Methods: []*ir.Method{
			{
				Name:       "doNative",
				Access:     ir.AccPublic | ir.AccNative,
				ReturnType: &ir.PrimitiveType{Name: "void"},
				// Body intentionally nil: a native method has no Code
				// attribute in the real class file, which is exactly
				// what triggers the old "// TODO" body fallback.
			},
			{
				Name:       "doAbstract",
				Access:     ir.AccPublic | ir.AccAbstract,
				ReturnType: &ir.PrimitiveType{Name: "void"},
			},
		},
	}

	dir := t.TempDir()
	g := NewGenerator(Options{OutputDir: dir})
	if err := g.GenerateClass(class); err != nil {
		t.Fatalf("GenerateClass: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "Sample.java"))
	if err != nil {
		t.Fatalf("reading generated file: %v", err)
	}
	src := string(data)

	if !strings.Contains(src, "native void doNative();") {
		t.Errorf("expected \"native void doNative();\" (no body) in output, got:\n%s", src)
	}
	if strings.Contains(src, "doNative() {") {
		t.Errorf("native method must not have a \"{\" body, got:\n%s", src)
	}
	if !strings.Contains(src, "abstract void doAbstract();") {
		t.Errorf("expected \"abstract void doAbstract();\" (no body) in output, got:\n%s", src)
	}
	if strings.Contains(src, "doAbstract() {") {
		t.Errorf("abstract method must not have a \"{\" body, got:\n%s", src)
	}
	if strings.Contains(src, "// TODO") {
		t.Errorf("native/abstract methods should never fall back to the \"// TODO\" body placeholder, got:\n%s", src)
	}
}

// TestGenerateClass_OrdinaryMethodStillGetsBody guards against an
// overcorrection: only native/abstract methods should lose their body -
// an ordinary method with no decompiled body yet (Body == nil for some
// OTHER reason - a genuine decompilation gap, not because it's
// native/abstract) must still fall back to "{ // TODO }", since it DOES
// have a real implementation in the class file that was just not
// recovered, unlike a native/abstract method which never had one.
func TestGenerateClass_OrdinaryMethodStillGetsBody(t *testing.T) {
	class := &ir.Class{
		Name:   "Sample",
		Access: ir.AccPublic,
		Methods: []*ir.Method{
			{
				Name:       "notYetDecompiled",
				Access:     ir.AccPublic,
				ReturnType: &ir.PrimitiveType{Name: "void"},
			},
		},
	}

	dir := t.TempDir()
	g := NewGenerator(Options{OutputDir: dir})
	if err := g.GenerateClass(class); err != nil {
		t.Fatalf("GenerateClass: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "Sample.java"))
	if err != nil {
		t.Fatalf("reading generated file: %v", err)
	}
	src := string(data)

	if !strings.Contains(src, "notYetDecompiled() {") {
		t.Errorf("expected an ordinary method to still get a \"{\" body, got:\n%s", src)
	}
	if !strings.Contains(src, "// TODO") {
		t.Errorf("expected the \"// TODO\" placeholder for a genuinely undecompiled ordinary method, got:\n%s", src)
	}
}

// TestGenerateClass_SuperCallWithArgs exercises the actual bug: a
// constructor whose superclass constructor call carries real arguments
// (e.g. a View subclass forwarding its own Context/AttributeSet
// parameters to android.widget.EditText's constructor) must render
// those arguments, not a bare "super();" that silently drops them.
func TestGenerateClass_SuperCallWithArgs(t *testing.T) {
	class := &ir.Class{
		Name:       "Sample",
		Access:     ir.AccPublic,
		SuperClass: "android/widget/EditText",
		Methods: []*ir.Method{
			{
				Name:   "<init>",
				Access: ir.AccPublic,
				Params: []*ir.Param{
					{Name: "context", Type: &ir.ClassType{Name: "android.content.Context"}},
				},
				Body: &ir.Block{
					Statements: []ir.Stmt{
						&ir.SuperCallStmt{Args: []ir.Expr{&ir.LocalVar{Name: "context"}}},
						&ir.ReturnStmt{},
					},
				},
			},
		},
	}

	dir := t.TempDir()
	g := NewGenerator(Options{OutputDir: dir})
	if err := g.GenerateClass(class); err != nil {
		t.Fatalf("GenerateClass: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "Sample.java"))
	if err != nil {
		t.Fatalf("reading generated file: %v", err)
	}
	src := string(data)

	if !strings.Contains(src, "super(context);") {
		t.Errorf("expected \"super(context);\" (the real forwarded argument, not dropped), got:\n%s", src)
	}
	if strings.Contains(src, "super();") {
		t.Errorf("must not ALSO render a bare \"super();\" - the leading SuperCallStmt should be consumed exactly once, got:\n%s", src)
	}
}

// TestGenerateClass_ThisCallWithArgs covers the sibling case: one
// constructor overload delegating to another in the SAME class
// ("this(...)"), which compiles to the identical invokespecial <init>
// shape as a super() call and is only told apart by its target class
// (see decompileInvoke's own doc comment in internal/jvm/decoder.go).
func TestGenerateClass_ThisCallWithArgs(t *testing.T) {
	class := &ir.Class{
		Name:   "Sample",
		Access: ir.AccPublic,
		Methods: []*ir.Method{
			{
				Name:   "<init>",
				Access: ir.AccPublic,
				Body: &ir.Block{
					Statements: []ir.Stmt{
						&ir.ThisCallStmt{Args: []ir.Expr{&ir.IntLit{Value: 0}}},
						&ir.ReturnStmt{},
					},
				},
			},
		},
	}

	dir := t.TempDir()
	g := NewGenerator(Options{OutputDir: dir})
	if err := g.GenerateClass(class); err != nil {
		t.Fatalf("GenerateClass: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "Sample.java"))
	if err != nil {
		t.Fatalf("reading generated file: %v", err)
	}
	src := string(data)

	if !strings.Contains(src, "this(0);") {
		t.Errorf("expected \"this(0);\", got:\n%s", src)
	}
}

// TestGenerateClass_ImplicitSuperCall covers a constructor whose body
// doesn't start with a SuperCallStmt/ThisCallStmt at all (defensive
// fallback - shouldn't happen for a real decompiled constructor, since
// decompileInvoke always produces one, but the template must still
// degrade to a harmless bare "super();" rather than panicking or
// emitting nothing).
func TestGenerateClass_ImplicitSuperCall(t *testing.T) {
	class := &ir.Class{
		Name:   "Sample",
		Access: ir.AccPublic,
		Methods: []*ir.Method{
			{Name: "<init>", Access: ir.AccPublic},
		},
	}

	dir := t.TempDir()
	g := NewGenerator(Options{OutputDir: dir})
	if err := g.GenerateClass(class); err != nil {
		t.Fatalf("GenerateClass: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "Sample.java"))
	if err != nil {
		t.Fatalf("reading generated file: %v", err)
	}
	src := string(data)

	if !strings.Contains(src, "super();") {
		t.Errorf("expected the defensive bare \"super();\" fallback, got:\n%s", src)
	}
}

// TestRenderStmt_ForStmt covers the ForStmt renderer: init/cond/post are
// emitted in the Java for-header rather than falling through to the
// abbreviated ir.ForStmt.String form, and the body is rendered in full.
func TestRenderStmt_ForStmt(t *testing.T) {
	stmt := &ir.ForStmt{
		Init: &ir.VarDeclStmt{
			Name: "i",
			Type: &ir.PrimitiveType{Name: "int"},
			Init: &ir.IntLit{Value: 0},
		},
		Cond: &ir.BinaryExpr{
			Op:    "<",
			Left:  &ir.LocalVar{Name: "i"},
			Right: &ir.IntLit{Value: 3},
		},
		Post: &ir.ExprStmt{
			Expr: &ir.UnaryExpr{Op: "++", Expr: &ir.LocalVar{Name: "i"}},
		},
		Body: &ir.Block{Statements: []ir.Stmt{
			&ir.ExprStmt{Expr: &ir.StaticMethodCall{Class: "System", Method: "nanoTime"}},
		}},
	}

	got := renderStmt(stmt, 2)
	want := "\t\tfor (int i = 0; i < 3; ++i) {\n" +
		"\t\t\tSystem.nanoTime();\n" +
		"\t\t}"
	if got != want {
		t.Fatalf("renderStmt(ForStmt) =\n%q\nwant:\n%q", got, want)
	}
}

// TestGenerateClass_ConstructorRendersFullBody is the regression test for
// the constructor template path: a nested control-flow statement must be
// rendered as a real body, not the "if (...) { ... }" placeholder produced
// by ir.Stmt.String.
func TestGenerateClass_ConstructorRendersFullBody(t *testing.T) {
	class := &ir.Class{
		Name:   "Sample",
		Access: ir.AccPublic,
		Methods: []*ir.Method{
			{
				Name:   "<init>",
				Access: ir.AccPublic,
				Params: []*ir.Param{
					{Name: "x", Type: &ir.PrimitiveType{Name: "int"}},
				},
				Body: &ir.Block{Statements: []ir.Stmt{
					&ir.SuperCallStmt{},
					&ir.IfStmt{
						Cond: &ir.BinaryExpr{
							Op:    ">",
							Left:  &ir.LocalVar{Name: "x"},
							Right: &ir.IntLit{Value: 0},
						},
						Then: &ir.Block{Statements: []ir.Stmt{
							&ir.ExprStmt{Expr: &ir.StaticMethodCall{Class: "System", Method: "nanoTime"}},
						}},
					},
					&ir.ReturnStmt{},
				}},
			},
		},
	}

	dir := t.TempDir()
	g := NewGenerator(Options{OutputDir: dir})
	if err := g.GenerateClass(class); err != nil {
		t.Fatalf("GenerateClass: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "Sample.java"))
	if err != nil {
		t.Fatalf("reading generated file: %v", err)
	}
	src := string(data)

	if !strings.Contains(src, "if (x > 0) {") {
		t.Errorf("constructor body was not rendered in full, got:\n%s", src)
	}
	if strings.Contains(src, "if (x > 0) { ... }") {
		t.Errorf("constructor body fell back to the abbreviated String() form, got:\n%s", src)
	}
	if !strings.Contains(src, "System.nanoTime();") {
		t.Errorf("nested constructor statement missing, got:\n%s", src)
	}
}

// TestGenerateClass_ClinitRendersFullBody covers the static-initializer
// template path, which had the same {{.}} placeholder rendering bug.
func TestGenerateClass_ClinitRendersFullBody(t *testing.T) {
	class := &ir.Class{
		Name:   "Sample",
		Access: ir.AccPublic,
		Methods: []*ir.Method{
			{
				Name:   "<clinit>",
				Access: ir.AccStatic,
				Body: &ir.Block{Statements: []ir.Stmt{
					&ir.ForStmt{
						Init: &ir.VarDeclStmt{
							Name: "i",
							Type: &ir.PrimitiveType{Name: "int"},
							Init: &ir.IntLit{Value: 0},
						},
						Cond: &ir.BinaryExpr{
							Op:    "<",
							Left:  &ir.LocalVar{Name: "i"},
							Right: &ir.IntLit{Value: 2},
						},
						Post: &ir.ExprStmt{
							Expr: &ir.UnaryExpr{Op: "++", Expr: &ir.LocalVar{Name: "i"}},
						},
						Body: &ir.Block{Statements: []ir.Stmt{
							&ir.ExprStmt{Expr: &ir.StaticMethodCall{Class: "System", Method: "nanoTime"}},
						}},
					},
					&ir.ReturnStmt{},
				}},
			},
		},
	}

	dir := t.TempDir()
	g := NewGenerator(Options{OutputDir: dir})
	if err := g.GenerateClass(class); err != nil {
		t.Fatalf("GenerateClass: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "Sample.java"))
	if err != nil {
		t.Fatalf("reading generated file: %v", err)
	}
	src := string(data)

	if !strings.Contains(src, "for (int i = 0; i < 2; ++i) {") {
		t.Errorf("static initializer for-loop was not rendered in full, got:\n%s", src)
	}
	if strings.Contains(src, "for (...;") {
		t.Errorf("static initializer fell back to the abbreviated ForStmt.String form, got:\n%s", src)
	}
	if !strings.Contains(src, "System.nanoTime();") {
		t.Errorf("nested static-initializer statement missing, got:\n%s", src)
	}
}
