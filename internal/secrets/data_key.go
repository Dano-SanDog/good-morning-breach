package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const dataKeySize = 32

func LoadDataKey() ([]byte, error) {
	path, err := dataKeyPath()
	if err != nil {
		return nil, err
	}
	return readDataKey(path)
}

func CreateDataKeyIfMissing() ([]byte, error) {
	path, err := dataKeyPath()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create application configuration directory: %w", err)
	}
	if err := checkPrivateDirectory(dir); err != nil {
		return nil, err
	}

	key := make([]byte, dataKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.New("generate data encryption key")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return readDataKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create data encryption key file: %w", err)
	}
	_, writeErr := io.WriteString(file, hex.EncodeToString(key))
	closeErr := file.Close()
	if writeErr != nil {
		return nil, fmt.Errorf("write data encryption key file: %w", writeErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close data encryption key file: %w", closeErr)
	}
	return key, nil
}

func dataKeyPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find application configuration directory: %w", err)
	}
	return filepath.Join(configDir, "good-morning-breach", "data-key"), nil
}

func readDataKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read data encryption key file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("data encryption key file must be a regular 0600 file")
	}
	if err := checkPrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read data encryption key file: %w", err)
	}
	key := make([]byte, dataKeySize)
	if len(encoded) != hex.EncodedLen(dataKeySize) {
		return nil, errors.New("data encryption key file has an invalid format")
	}
	if _, err := hex.Decode(key, encoded); err != nil {
		return nil, errors.New("data encryption key file has an invalid format")
	}
	return key, nil
}

func checkPrivateDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect application configuration directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("application configuration directory must be a private directory")
	}
	return nil
}
