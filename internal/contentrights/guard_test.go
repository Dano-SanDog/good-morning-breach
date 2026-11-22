package contentrights

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fields that carry source content beyond the headline and link. Only this
// package may declare them (SC-023); output structs embed Content instead.
var contentFieldNames = map[string]bool{
	"Excerpt": true, "Summary": true, "Body": true, "FullText": true,
	"Description": true, "Snippet": true, "Abstract": true,
}

func parseTree(t *testing.T) map[string]*ast.File {
	t.Helper()
	files := map[string]*ast.File{}
	fset := token.NewFileSet()
	err := filepath.WalkDir("..", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(path)] = f
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// A new output type that adds its own content field would bypass the gate.
func TestNoContentFieldsOutsideGate(t *testing.T) {
	for path, f := range parseTree(t) {
		if strings.HasPrefix(path, "../contentrights/") || strings.HasPrefix(path, "../ingest/") {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			field, ok := n.(*ast.Field)
			if !ok {
				return true
			}
			for _, name := range field.Names {
				if contentFieldNames[name.Name] {
					t.Errorf("%s declares content field %s outside the content-rights gate", path, name.Name)
				}
			}
			return true
		})
	}
}

// Output story types must embed contentrights.Content.
func TestOutputStoriesEmbedGatedContent(t *testing.T) {
	files := parseTree(t)
	for _, path := range []string{"../identity/types.go", "../alerting/alerting.go"} {
		f := files[path]
		found := false
		ast.Inspect(f, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok || spec.Name.Name != "Story" {
				return true
			}
			st := spec.Type.(*ast.StructType)
			for _, field := range st.Fields.List {
				if sel, ok := field.Type.(*ast.SelectorExpr); ok && len(field.Names) == 0 && sel.Sel.Name == "Content" {
					found = true
				}
			}
			return true
		})
		if !found {
			t.Errorf("%s: Story must embed contentrights.Content", path)
		}
	}
}

// Stores must scan stored text into contentrights.Raw, not straight into an
// output story, so that every read passes through Gate.
func TestStoresDoNotScanStoryContentDirectly(t *testing.T) {
	for path, f := range parseTree(t) {
		if !strings.HasPrefix(path, "../store/postgres/") {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			u, ok := n.(*ast.UnaryExpr)
			if !ok || u.Op != token.AND {
				return true
			}
			sel, ok := u.X.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "story" && (sel.Sel.Name == "Title" || sel.Sel.Name == "URL") {
				t.Errorf("%s scans story.%s directly; scan into contentrights.Raw and call Gate", path, sel.Sel.Name)
			}
			return true
		})
	}
}
