package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory  = 19456
	argonTime    = 2
	argonThreads = 1
	argonSaltLen = 16
	argonKeyLen  = 32
)

var (
	ErrPasswordLength           = errors.New("password must be between 12 and 256 characters")
	ErrPasswordBreached         = errors.New("password appears in the known-breached password list")
	ErrPasswordCheckUnavailable = errors.New("password breach check unavailable")
)

var dummyPasswordHash = encodePasswordHash(
	argon2.IDKey([]byte("gmb-unknown-account"), []byte("gmb-dummy-salt!1"), argonTime, argonMemory, argonThreads, argonKeyLen),
	[]byte("gmb-dummy-salt!1"),
)

func HashPassword(password string) (string, error) {
	if !validPasswordLength(password) {
		return "", ErrPasswordLength
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.New("generate password salt")
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return encodePasswordHash(hash, salt), nil
}

func VerifyPassword(encoded, password string) bool {
	salt, expected, ok := decodePasswordHash(encoded)
	if !ok {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func validPasswordLength(password string) bool {
	return utf8.ValidString(password) && utf8.RuneCountInString(password) >= 12 && utf8.RuneCountInString(password) <= 256
}

func encodePasswordHash(hash, salt []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

func decodePasswordHash(encoded string) ([]byte, []byte, bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" ||
		parts[3] != "m=19456,t=2,p=1" {
		return nil, nil, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != argonSaltLen {
		return nil, nil, false
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) != argonKeyLen {
		return nil, nil, false
	}
	return salt, hash, true
}

func ValidateNewPassword(ctx context.Context, client *http.Client, password string) error {
	if !validPasswordLength(password) {
		return ErrPasswordLength
	}
	return checkHIBP(ctx, client, password)
}

func checkHIBP(ctx context.Context, client *http.Client, password string) error {
	return checkHIBPAt(ctx, client, password, "https://api.pwnedpasswords.com/range/")
}

func checkHIBPAt(ctx context.Context, client *http.Client, password, endpoint string) error {
	digest := sha1.Sum([]byte(password))
	encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
	prefix, suffix := encoded[:5], []byte(encoded[5:])
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		endpoint+prefix,
		nil,
	)
	if err != nil {
		return errors.New("prepare password breach check")
	}
	request.Header.Set("Add-Padding", "true")
	response, err := client.Do(request)
	if err != nil {
		return ErrPasswordCheckUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrPasswordCheckUnavailable
	}

	const maxResponseBytes = 4 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(body) > maxResponseBytes {
		return ErrPasswordCheckUnavailable
	}
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		entry := strings.SplitN(string(line), ":", 2)
		if len(entry) != 2 || len(entry[0]) != 35 {
			return ErrPasswordCheckUnavailable
		}
		entrySuffix := []byte(strings.ToUpper(entry[0]))
		for _, character := range entrySuffix {
			if (character < '0' || character > '9') && (character < 'A' || character > 'F') {
				return ErrPasswordCheckUnavailable
			}
		}
		count, err := strconv.ParseUint(entry[1], 10, 64)
		if err != nil {
			return ErrPasswordCheckUnavailable
		}
		if count > 0 && subtle.ConstantTimeCompare(entrySuffix, suffix) == 1 {
			return ErrPasswordBreached
		}
	}
	return nil
}
