package identity

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestFirstLoginEnrollsTOTPAndRejectsCodeReplay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	passwordHash, err := HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryIdentityStore{
		account: Account{
			ID:           1,
			Email:        "admin@example.test",
			Role:         "admin",
			PasswordHash: passwordHash,
			Enabled:      true,
			LastTOTPStep: -1,
		},
		sessions: make(map[string]Session),
	}
	service, err := NewService(store, make([]byte, 32), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }

	firstLogin, err := service.PasswordLogin(context.Background(), "ADMIN@example.test", "a sufficiently long password", "")
	if err != nil {
		t.Fatal(err)
	}
	if firstLogin.Next != SetupTOTP {
		t.Fatalf("first login step = %q; want %q", firstLogin.Next, SetupTOTP)
	}
	secret, err := service.BeginTOTPSetup(context.Background(), firstLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	opts := totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	code, err := totp.GenerateCodeCustom(secret, now, opts)
	if err != nil {
		t.Fatal(err)
	}
	user, authenticatedToken, err := service.CompleteTOTP(context.Background(), firstLogin.Token, code, true)
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "admin@example.test" || user.Role != "admin" {
		t.Fatalf("authenticated user = %#v", user)
	}
	if _, err := service.CurrentUser(context.Background(), authenticatedToken); err != nil {
		t.Fatalf("completed setup did not create an authenticated session: %v", err)
	}

	secondLogin, err := service.PasswordLogin(
		context.Background(),
		"admin@example.test",
		"a sufficiently long password",
		authenticatedToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	if secondLogin.Next != LoginTOTP {
		t.Fatalf("subsequent login step = %q; want %q", secondLogin.Next, LoginTOTP)
	}
	if _, _, err := service.CompleteTOTP(context.Background(), secondLogin.Token, code, false); !errors.Is(err, ErrCredentials) {
		t.Fatalf("replayed TOTP error = %v; want generic credentials error", err)
	}

	futureCode, err := totp.GenerateCodeCustom(secret, now.Add(30*time.Second), opts)
	if err != nil {
		t.Fatal(err)
	}
	_, finalToken, err := service.CompleteTOTP(context.Background(), secondLogin.Token, futureCode, false)
	if err != nil {
		t.Fatalf("next valid code was rejected: %v", err)
	}
	if _, err := service.CurrentUser(context.Background(), finalToken); err != nil {
		t.Fatalf("new session after TOTP login is invalid: %v", err)
	}
}

func TestPasswordLoginFailureLogsOneRedactedSecurityEvent(t *testing.T) {
	passwordHash, err := HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryIdentityStore{
		account: Account{
			ID:           9,
			Email:        "admin@example.test",
			PasswordHash: passwordHash,
			Enabled:      true,
		},
		sessions: make(map[string]Session),
	}
	service, err := NewService(store, make([]byte, 32), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(previousLogger)

	password := "incorrect password"
	if _, err := service.PasswordLogin(context.Background(), "admin@example.test", password, ""); !errors.Is(err, ErrCredentials) {
		t.Fatalf("login error = %v; want generic credential error", err)
	}
	record := output.String()
	if strings.Count(record, "\n") != 1 ||
		!strings.Contains(record, `"event":"login_failure"`) ||
		!strings.Contains(record, `"account_id":9`) ||
		!strings.Contains(record, `"outcome":"failure"`) {
		t.Fatalf("failure event was not logged exactly once: %q", record)
	}
	if strings.Contains(record, password) || strings.Contains(record, "password") {
		t.Fatalf("login log contains credential data: %q", record)
	}
}

type memoryIdentityStore struct {
	account  Account
	sessions map[string]Session
	failures int
}

func (s *memoryIdentityStore) CreateAdmin(context.Context, string, string) (int64, error) {
	return 1, nil
}

func (s *memoryIdentityStore) AccountByEmail(_ context.Context, email string) (Account, error) {
	if email != s.account.Email {
		return Account{}, ErrNotFound
	}
	return s.account, nil
}

func (s *memoryIdentityStore) RecordFailedLogin(_ context.Context, _ int64, _ time.Time) (bool, error) {
	s.failures++
	return false, nil
}

func (s *memoryIdentityStore) CreatePartialSession(
	_ context.Context,
	previousHash, tokenHash []byte,
	accountID int64,
	now, partialExpiresAt time.Time,
) error {
	if len(previousHash) > 0 {
		delete(s.sessions, hex.EncodeToString(previousHash))
	}
	s.sessions[hex.EncodeToString(tokenHash)] = Session{
		Account:          s.account,
		CreatedAt:        now,
		LastSeenAt:       now,
		ExpiresAt:        now.Add(8 * time.Hour),
		PartialExpiresAt: &partialExpiresAt,
	}
	return nil
}

func (s *memoryIdentityStore) LoadSession(_ context.Context, tokenHash []byte, now time.Time) (Session, error) {
	session, ok := s.sessions[hex.EncodeToString(tokenHash)]
	if !ok || !session.ExpiresAt.After(now) ||
		now.Sub(session.LastSeenAt) > 30*time.Minute ||
		(session.PartialExpiresAt != nil && !session.PartialExpiresAt.After(now)) {
		return Session{}, ErrSession
	}
	session.Account = s.account
	return session, nil
}

func (s *memoryIdentityStore) TouchSession(_ context.Context, tokenHash []byte, now time.Time) error {
	key := hex.EncodeToString(tokenHash)
	session, ok := s.sessions[key]
	if !ok || session.PartialExpiresAt != nil {
		return ErrSession
	}
	session.LastSeenAt = now
	s.sessions[key] = session
	return nil
}

func (s *memoryIdentityStore) BeginTOTPSetup(
	_ context.Context,
	sessionHash []byte,
	accountID int64,
	ciphertext, nonce []byte,
	_ time.Time,
) error {
	if _, ok := s.sessions[hex.EncodeToString(sessionHash)]; !ok || accountID != s.account.ID {
		return ErrSession
	}
	s.account.TOTPSecretCiphertext = ciphertext
	s.account.TOTPNonce = nonce
	return nil
}

func (s *memoryIdentityStore) CompleteTOTP(
	_ context.Context,
	oldHash, newHash []byte,
	step int64,
	now time.Time,
	setup bool,
) (Account, error) {
	session, ok := s.sessions[hex.EncodeToString(oldHash)]
	if !ok || session.PartialExpiresAt == nil || !session.PartialExpiresAt.After(now) {
		return Account{}, ErrSession
	}
	if setup == s.account.TOTPEnrolled {
		return Account{}, ErrTOTPSetup
	}
	if step <= s.account.LastTOTPStep {
		return Account{}, ErrOTPReplay
	}
	delete(s.sessions, hex.EncodeToString(oldHash))
	s.account.TOTPEnrolled = true
	s.account.LastTOTPStep = step
	s.sessions[hex.EncodeToString(newHash)] = Session{
		Account:    s.account,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(8 * time.Hour),
	}
	return s.account, nil
}

func (s *memoryIdentityStore) DeleteSession(_ context.Context, tokenHash []byte) error {
	delete(s.sessions, hex.EncodeToString(tokenHash))
	return nil
}

func (s *memoryIdentityStore) ListStories(context.Context, time.Time) ([]Story, error) {
	return []Story{}, nil
}

var _ Store = (*memoryIdentityStore)(nil)
