package applog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDailyWriterRotatesAndKeepsPrivateFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 11, 17, 23, 59, 0, 0, time.UTC)
	writer, err := newDailyWriter(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := writer.Write([]byte("second\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.file.Close(); err != nil {
		t.Fatal(err)
	}

	for _, date := range []string{"2026-11-17", "2026-11-18"} {
		info, err := os.Stat(filepath.Join(dir, logFilePrefix+date+logFileSuffix))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("log file mode = %04o; want 0600", info.Mode().Perm())
		}
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("log directory mode = %04o; want 0700", info.Mode().Perm())
	}
}

func TestDailyWriterPrunesExpiredLogs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	expired := filepath.Join(dir, logFilePrefix+"2026-09-01"+logFileSuffix)
	if err := os.WriteFile(expired, []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(expired, now.Add(-31*24*time.Hour), now.Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	writer, err := newDailyWriter(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(expired); !os.IsNotExist(err) {
		t.Fatalf("expired log still exists: %v", err)
	}
}
