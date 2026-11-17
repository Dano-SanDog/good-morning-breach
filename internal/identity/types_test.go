package identity

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestSensitiveIdentityTypesAreRedactedInLogs(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logger.Info("sensitive values",
		"account", Account{
			Email:                "private@example.test",
			PasswordHash:         "password-hash",
			TOTPSecretCiphertext: []byte("encrypted-secret"),
			TOTPNonce:            []byte("nonce"),
		},
		"session", Session{CreatedAt: time.Now()},
		"user", AuthenticatedUser{Email: "private@example.test"},
		"login", LoginResult{Token: "session-token"},
	)
	record := output.String()
	for _, secret := range []string{
		"private@example.test",
		"password-hash",
		"encrypted-secret",
		"nonce",
		"session-token",
	} {
		if strings.Contains(record, secret) {
			t.Errorf("log record leaked %q: %s", secret, record)
		}
	}
	if strings.Count(record, "[redacted]") != 4 {
		t.Fatalf("redacted values = %d; want 4: %s", strings.Count(record, "[redacted]"), record)
	}
}
