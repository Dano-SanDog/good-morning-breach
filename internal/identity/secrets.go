package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"strconv"
)

func encryptTOTPSecret(key []byte, accountID int64, secret []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, errors.New("invalid data encryption key")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, errors.New("configure data encryption")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, errors.New("generate data encryption nonce")
	}
	ciphertext := aead.Seal(nil, nonce, secret, []byte(strconv.FormatInt(accountID, 10)))
	return ciphertext, nonce, nil
}

func decryptTOTPSecret(key []byte, accountID int64, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("invalid data encryption key")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("configure data encryption")
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid encrypted time-based code")
	}
	secret, err := aead.Open(nil, nonce, ciphertext, []byte(strconv.FormatInt(accountID, 10)))
	if err != nil {
		return nil, errors.New("decrypt time-based code")
	}
	return secret, nil
}
