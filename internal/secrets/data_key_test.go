package secrets

import (
	"bytes"
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

func TestBoxBindsAccountAndPurpose(t *testing.T) {
	box, err := NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal("slack_webhook", 7, []byte("https://hooks.slack.com/services/T/B/x"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("hooks.slack.com")) {
		t.Fatal("ciphertext contains plaintext")
	}
	if got, err := box.Open("slack_webhook", 7, sealed); err != nil || string(got) != "https://hooks.slack.com/services/T/B/x" {
		t.Fatalf("round trip: %q %v", got, err)
	}
	if _, err := box.Open("slack_webhook", 8, sealed); err == nil {
		t.Fatal("decrypted for another account")
	}
	if _, err := box.Open("other", 7, sealed); err == nil {
		t.Fatal("decrypted for another purpose")
	}
	again, _ := box.Seal("slack_webhook", 7, []byte("x"))
	other, _ := box.Seal("slack_webhook", 7, []byte("x"))
	if bytes.Equal(again, other) {
		t.Fatal("nonce reused")
	}
}
