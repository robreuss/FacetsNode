package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperationalRecordsAreBoundedAndHaveNoFreeFormMessages(t *testing.T) {
	root := t.TempDir()
	if recordOperation(root, "release", "password=secret", "failed") == nil {
		t.Fatal("accepted free-form operation")
	}
	if err := recordOperation(root, "release", "boot", "started"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "operations/events.jsonl")
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(path, []byte(strings.Repeat("x", 256*1024)), 0600); err != nil {
			t.Fatal(err)
		}
		if err := recordOperation(root, "release", "buildServices", "failed"); err != nil {
			t.Fatal(err)
		}
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("unbounded logs: %d", len(files))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"operation":"buildServices"`) || strings.Contains(string(b), "secret") {
		t.Fatal("unexpected record")
	}
}
