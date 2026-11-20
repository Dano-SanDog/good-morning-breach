package alerting

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileMailer is a development-only mail sink for password reset messages. It
// writes each message to a private file instead of sending it, so local use
// works without an SMTP server. It is enabled only by an explicit
// GB_DEV_MAIL_DIR and never when SMTP is configured.
type FileMailer struct {
	dir string
	now func() time.Time
}

// NewFileMailer creates dir (mode 0700) if needed and requires that only the
// current user can access it.
func NewFileMailer(dir string) (*FileMailer, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("GB_DEV_MAIL_DIR must be an absolute path")
	}
	dir = filepath.Clean(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create dev mail directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect dev mail directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, errors.New("GB_DEV_MAIL_DIR must be a real directory with mode 0700")
	}
	return &FileMailer{dir: dir, now: time.Now}, nil
}

// SendText writes the message to a new 0600 file and returns without logging
// its contents, because reset messages contain a secret link.
func (m *FileMailer) SendText(_ context.Context, to, subject, text string) error {
	if strings.ContainsAny(to, "\r\n") || strings.ContainsAny(subject, "\r\n") {
		return errors.New("invalid message header")
	}
	name := fmt.Sprintf("%s-%s.txt", m.now().UTC().Format("20060102T150405Z"), rand.Text()[:8])
	file, err := os.OpenFile(filepath.Join(m.dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write dev mail: %w", err)
	}
	_, err = fmt.Fprintf(file, "To: %s\nSubject: %s\n\n%s", to, subject, text)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}
