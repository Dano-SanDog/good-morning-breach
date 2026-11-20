package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strconv"
)

// Box encrypts small secrets for storage with AES-256-GCM (SC-071). Each value
// gets a random 96-bit nonce, and the account ID is bound as associated data so
// a ciphertext copied to another account's row fails to decrypt.
type Box struct {
	aead cipher.AEAD
	key  []byte
}

func NewBox(key []byte) (*Box, error) {
	if len(key) != dataKeySize {
		return nil, errors.New("data encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("create data cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("create data cipher")
	}
	return &Box{aead: aead, key: append([]byte(nil), key...)}, nil
}

func aad(purpose string, accountID int64) []byte {
	return []byte(purpose + ":" + strconv.FormatInt(accountID, 10))
}

// Seal returns nonce||ciphertext.
func (b *Box) Seal(purpose string, accountID int64, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("generate nonce")
	}
	return b.aead.Seal(nonce, nonce, plaintext, aad(purpose, accountID)), nil
}

func (b *Box) Open(purpose string, accountID int64, sealed []byte) ([]byte, error) {
	size := b.aead.NonceSize()
	if len(sealed) < size+b.aead.Overhead() {
		return nil, errors.New("sealed value is too short")
	}
	plaintext, err := b.aead.Open(nil, sealed[:size], sealed[size:], aad(purpose, accountID))
	if err != nil {
		return nil, errors.New("sealed value could not be decrypted")
	}
	return plaintext, nil
}

// Digest returns a keyed hash for short secrets such as verification codes, so a
// copy of the database cannot be used to guess them offline.
func (b *Box) Digest(purpose string, accountID int64, value string) []byte {
	mac := hmac.New(sha256.New, b.key)
	mac.Write(aad(purpose, accountID))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	return mac.Sum(nil)
}
