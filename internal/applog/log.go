package applog

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	logDirectoryName = "logs"
	logFilePrefix    = "gmb-"
	logFileSuffix    = ".jsonl"
	logRetention     = 30 * 24 * time.Hour
)

type dailyWriter struct {
	mu   sync.Mutex
	dir  string
	now  func() time.Time
	date string
	file *os.File
}

func Configure() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("find application configuration directory: %w", err)
	}
	writer, err := newDailyWriter(filepath.Join(configDir, "good-morning-breach", logDirectoryName), time.Now)
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(io.MultiWriter(os.Stdout, writer), nil)))
	return nil
}

func newDailyWriter(dir string, now func() time.Time) (*dailyWriter, error) {
	if now == nil {
		return nil, errors.New("clock is required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create application log directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect application log directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, errors.New("application log directory must be a private 0700 directory")
	}
	writer := &dailyWriter{dir: dir, now: now}
	if err := writer.rotate(now()); err != nil {
		return nil, err
	}
	return writer, nil
}

func (w *dailyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if date := w.now().Format("2006-01-02"); date != w.date {
		if err := w.rotate(w.now()); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(p)
	if err != nil {
		return n, err
	}
	if n != len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func (w *dailyWriter) rotate(now time.Time) error {
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return fmt.Errorf("close application log file: %w", err)
		}
	}
	if err := pruneLogs(w.dir, now); err != nil {
		return err
	}
	date := now.Format("2006-01-02")
	path := filepath.Join(w.dir, logFilePrefix+date+logFileSuffix)
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
			return errors.New("application log file must be a regular 0600 file")
		}
		w.file, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	} else if errors.Is(err, os.ErrNotExist) {
		w.file, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_APPEND|os.O_WRONLY, 0600)
	}
	if err != nil {
		return fmt.Errorf("open application log file: %w", err)
	}
	w.date = date
	return nil
}

func pruneLogs(dir string, now time.Time) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read application log directory: %w", err)
	}
	cutoff := now.Add(-logRetention)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, logFilePrefix) || !strings.HasSuffix(name, logFileSuffix) {
			continue
		}
		if _, err := time.Parse("2006-01-02", strings.TrimSuffix(strings.TrimPrefix(name, logFilePrefix), logFileSuffix)); err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect application log file: %w", err)
		}
		if info.Mode().IsRegular() && info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return fmt.Errorf("remove expired application log file: %w", err)
			}
		}
	}
	return nil
}
