package identity

import (
	"bytes"
	"testing"
)

func TestTOTPSecretEncryptionBindsAccountID(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	secret := []byte("a base32 authenticator secret")
	ciphertext, nonce, err := encryptTOTPSecret(key, 17, secret)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := decryptTOTPSecret(key, 17, ciphertext, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, secret) {
		t.Fatal("decrypted secret does not match")
	}
	if _, err := decryptTOTPSecret(key, 18, ciphertext, nonce); err == nil {
		t.Fatal("ciphertext was accepted for a different account")
	}
}
