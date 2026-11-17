package secrets

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestReadDataKeyRequiresPrivateRegularFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "data-key")
	want := make([]byte, dataKeySize)
	encoded := []byte(hex.EncodeToString(want))
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readDataKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != dataKeySize {
		t.Fatalf("key size = %d; want %d", len(got), dataKeySize)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readDataKey(path); err == nil {
		t.Fatal("group-readable data key was accepted")
	}
}
