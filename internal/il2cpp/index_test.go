package il2cpp

import "testing"

func TestMetadataIndexLookups(t *testing.T) {
	idx := &MetadataIndex{
		Methods: map[uint64]MethodInfo{
			0x1000: {
				RVA:      0x1000,
				TypeName: "Game.Player",
				Name:     "Update",
				Params:   []string{"this", "dt"},
				IsStatic: false,
			},
		},
		Fields: map[string]map[uint64]FieldInfo{
			"Game.Player": {
				0x10: {Owner: "Game.Player", Name: "health", FieldType: "System.Int32", Offset: 0x10},
			},
			"Game.Entity": {
				0x20: {Owner: "Game.Entity", Name: "id", FieldType: "System.Int32", Offset: 0x20},
			},
		},
		Parents: map[string]string{"Game.Player": "Game.Entity"},
	}

	typeName, params, isStatic, ok := idx.MethodAtRVA(0x1000)
	if !ok || typeName != "Game.Player" || isStatic || len(params) != 2 || params[1] != "dt" {
		t.Fatalf("MethodAtRVA = (%q,%v,%v,%v)", typeName, params, isStatic, ok)
	}
	if _, _, _, ok := idx.MethodAtRVA(0x2000); ok {
		t.Fatal("unknown RVA resolved")
	}

	name, typ, ok := idx.FieldAtOffset("Game.Player", 0x10)
	if !ok || name != "health" || typ != "System.Int32" {
		t.Fatalf("FieldAtOffset = (%q,%q,%v)", name, typ, ok)
	}
	if _, _, ok := idx.FieldAtOffset("Game.Player", 0x18); ok {
		t.Fatal("unknown field offset resolved")
	}
	if name, typ, ok := idx.FieldAtOffset("Game.Player", 0x20); !ok || name != "id" || typ != "System.Int32" {
		t.Fatalf("inherited FieldAtOffset = (%q,%q,%v), want id/System.Int32", name, typ, ok)
	}
}
