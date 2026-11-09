package arm64lift

import (
	"os"
	"strings"
	"testing"
)

const testOffsetsJSON = `{
  "classes": [
    {
      "name": "Axlebolt.Bolt.Protobuf.AchievementDefinition",
      "td": 9,
      "namespace": "AchievementDefinition",
      "fields": [
        {"name": "_unknownFields", "type": "UnknownFieldSet", "offset": "0x10"},
        {"name": "id_", "type": "string", "offset": "0x18"},
        {"name": "title_", "type": "LocalizedTitle", "offset": "0x28"}
      ]
    },
    {
      "name": "Axlebolt.Bolt.Protobuf.PlayerAchievement",
      "td": 11,
      "namespace": "PlayerAchievement",
      "fields": [
        {"name": "_unknownFields", "type": "UnknownFieldSet", "offset": "0x10"},
        {"name": "progressCurrent_", "type": "int", "offset": "0x40"},
        {"name": "progressTarget_", "type": "int", "offset": "0x44"}
      ]
    }
  ]
}`

const testOffsetsHPP = `#pragma once
#include <cstdint>

namespace offsets {
    // Axlebolt.Bolt.Protobuf.AchievementDefinition (TypeDefIndex: 9)
    namespace AchievementDefinition {
        inline constexpr ::std::uintptr_t _unknownFields() { return 0x10; } // UnknownFieldSet _unknownFields
        inline constexpr ::std::uintptr_t id_() { return 0x18; } // string id_
    }

    // Axlebolt.Bolt.Protobuf.PlayerAchievement (TypeDefIndex: 11)
    namespace PlayerAchievement {
        inline constexpr ::std::uintptr_t progressCurrent_() { return 0x40; } // int progressCurrent_
    }
}`

func TestLoadOffsetDBFromJSON(t *testing.T) {
	db, err := LoadOffsetDBFromJSON(strings.NewReader(testOffsetsJSON))
	if err != nil {
		t.Fatalf("LoadOffsetDBFromJSON: %v", err)
	}
	if db.Count() != 2 {
		t.Fatalf("class count = %d, want 2", db.Count())
	}
	if off, ok := db.FieldOffsetByName("Axlebolt.Bolt.Protobuf.PlayerAchievement", "progressTarget_"); !ok || off != 0x44 {
		t.Errorf("progressTarget_ offset = %#x, %v; want 0x44, true", off, ok)
	}
	// Short-name lookup when unambiguous.
	if off, ok := db.FieldOffsetByName("PlayerAchievement", "progressCurrent_"); !ok || off != 0x40 {
		t.Errorf("short-name progressCurrent_ offset = %#x, %v; want 0x40, true", off, ok)
	}
	// Reverse lookup, the naming path the lifter uses.
	f, ok := db.FieldAtOffset("AchievementDefinition", 0x18)
	if !ok || f.Name != "id_" || f.Owner != "Axlebolt.Bolt.Protobuf.AchievementDefinition" {
		t.Errorf("FieldAtOffset(0x18) = %#v, %v; want id_ of AchievementDefinition", f, ok)
	}
	if _, ok := db.FieldAtOffset("AchievementDefinition", 0x20); ok {
		t.Errorf("FieldAtOffset(0x20) unexpectedly resolved")
	}
	// No indices in a plain JSON dump: the index API reports not-found
	// rather than guessing.
	if _, ok := db.FieldOffset("AchievementDefinition", 1); ok {
		t.Errorf("FieldOffset(index) unexpectedly resolved from index-less JSON")
	}
	if td, ok := db.ClassByTypeDefIndex(11); !ok || td.Name != "Axlebolt.Bolt.Protobuf.PlayerAchievement" {
		t.Errorf("ClassByTypeDefIndex(11) = %#v, %v", td, ok)
	}
}

func TestLoadOffsetDBFromHPP(t *testing.T) {
	db, err := LoadOffsetDBFromHPP(strings.NewReader(testOffsetsHPP))
	if err != nil {
		t.Fatalf("LoadOffsetDBFromHPP: %v", err)
	}
	if db.Count() != 2 {
		t.Fatalf("class count = %d, want 2", db.Count())
	}
	if off, ok := db.FieldOffsetByName("Axlebolt.Bolt.Protobuf.AchievementDefinition", "id_"); !ok || off != 0x18 {
		t.Errorf("id_ offset = %#x, %v; want 0x18, true", off, ok)
	}
	f, ok := db.FieldAtOffset("Axlebolt.Bolt.Protobuf.AchievementDefinition", 0x10)
	if !ok || f.Name != "_unknownFields" || f.Type != "UnknownFieldSet" {
		t.Errorf("FieldAtOffset(0x10) = %#v, %v", f, ok)
	}
	if td, ok := db.ClassByTypeDefIndex(11); !ok || td.Name != "Axlebolt.Bolt.Protobuf.PlayerAchievement" {
		t.Errorf("ClassByTypeDefIndex(11) = %#v, %v", td, ok)
	}
}

func TestLoadOffsetDB_FileSniffing(t *testing.T) {
	dir := t.TempDir()
	jsonPath := dir + "/offsets.json"
	if err := writeFile(jsonPath, testOffsetsJSON); err != nil {
		t.Fatal(err)
	}
	db, err := LoadOffsetDB(jsonPath)
	if err != nil {
		t.Fatalf("LoadOffsetDB(json): %v", err)
	}
	if db.Count() != 2 {
		t.Fatalf("json class count = %d, want 2", db.Count())
	}

	hppPath := dir + "/offset.hpp"
	if err := writeFile(hppPath, testOffsetsHPP); err != nil {
		t.Fatal(err)
	}
	db, err = LoadOffsetDB(hppPath)
	if err != nil {
		t.Fatalf("LoadOffsetDB(hpp): %v", err)
	}
	if db.Count() != 2 {
		t.Fatalf("hpp class count = %d, want 2", db.Count())
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
