package dex

import (
	"os"
	"testing"
)

func TestTryItemsAndDebugInfo(t *testing.T) {
	dex, err := ParseDexFile(testDexPath)
	if err != nil {
		t.Fatalf("ParseDexFile: %v", err)
	}

	triesFound := false
	debugFound := false
	for _, classDef := range dex.Classes {
		cd := dex.GetClassData(classDef)
		if cd == nil {
			continue
		}
		methods := append(append([]Method{}, cd.DirectMethods...), cd.VirtualMethods...)
		for _, m := range methods {
			if m.CodeOff == 0 {
				continue
			}
			ci := dex.GetCodeItem(m.CodeOff)
			if ci == nil {
				continue
			}
			if ci.TriesSize > 0 {
				items := dex.GetTryItems(ci)
				if len(items) == 0 {
					t.Fatalf("code item 0x%x has %d tries but no parsed try_items", m.CodeOff, ci.TriesSize)
				}
				handlers := dex.GetCatchHandlers(ci, items[0].HandlerOff)
				if len(handlers) == 0 {
					t.Fatalf("code item 0x%x try has no catch handlers", m.CodeOff)
				}
				triesFound = true
			}
			if di := dex.GetDebugInfo(ci); di != nil {
				for _, n := range di.ParamNames {
					if n != "" {
						debugFound = true
					}
				}
				if len(di.Locals) > 0 {
					debugFound = true
				}
			}
		}
	}
	if !triesFound {
		t.Skip("fixture has no try/catch entries")
	}
	if !debugFound {
		t.Log("fixture has no named debug locals/params")
	}
}

func TestTryItemsZenin(t *testing.T) {
	const path = "../../test/zenin/classes.dex"
	if _, err := os.Stat(path); err != nil {
		t.Skip("zenin fixture not present")
	}
	dex, err := ParseDexFile(path)
	if err != nil {
		t.Fatalf("ParseDexFile: %v", err)
	}
	checked := 0
	for _, classDef := range dex.Classes {
		cd := dex.GetClassData(classDef)
		if cd == nil {
			continue
		}
		methods := append(append([]Method{}, cd.DirectMethods...), cd.VirtualMethods...)
		for _, m := range methods {
			if m.CodeOff == 0 {
				continue
			}
			ci := dex.GetCodeItem(m.CodeOff)
			if ci == nil || ci.TriesSize == 0 {
				continue
			}
			items := dex.GetTryItems(ci)
			if len(items) == 0 {
				t.Fatalf("code item 0x%x has %d tries but no parsed items", m.CodeOff, ci.TriesSize)
			}
			handlers := dex.GetCatchHandlers(ci, items[0].HandlerOff)
			if len(handlers) == 0 {
				t.Fatalf("code item 0x%x try has no handlers", m.CodeOff)
			}
			checked++
			if checked >= 20 {
				return
			}
		}
	}
	if checked == 0 {
		t.Skip("fixture has no try entries")
	}
}
