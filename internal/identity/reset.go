package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log/slog"
	"time"
)

const (
	resetTokenLifetime = 30 * time.Minute
	resetRateWindow    = time.Hour
	resetRateLimit     = 3
)

var ErrResetToken = errors.New("password reset link is invalid or expired")

// ResetStore persists single-use reset tokens (FR-6.9, SC-055, SC-058).
type ResetStore interface {
	// CreateResetToken stores the token for an enabled account and returns its
	// email address. It returns false when the account is unknown, disabled, or
	// over the hourly limit.
	CreateResetToken(ctx context.Context, email string, tokenHash []byte, now, expires time.Time, limit int, window time.Duration) (string, bool, error)
	// ConsumeResetToken sets the password, deletes all tokens, and ends all
	// sessions of the account in one transaction.
	ConsumeResetToken(ctx context.Context, tokenHash []byte, passwordHash string, now time.Time) (int64, error)
}

type ResetMailer interface {
	SendText(ctx context.Context, to, subject, text string) error
}

type passwordReset struct {
	store   ResetStore
	mailer  ResetMailer
	baseURL string
	async   func(func())
}

// EnablePasswordReset turns on the reset flow. baseURL is the HTTPS address of
// this server; the token travels in the URL fragment so it is not sent in requests.
func (s *Service) EnablePasswordReset(store ResetStore, mailer ResetMailer, baseURL string) {
	s.reset = &passwordReset{store: store, mailer: mailer, baseURL: baseURL, async: func(f func()) { go f() }}
}

// RequestPasswordReset never reveals whether the address has an account (SC-055).
func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	if s.reset == nil {
		slog.Warn("password reset requested but not configured", "event", "password_reset_request", "outcome", "unavailable")
		return nil
	}
	email = normalizeEmail(email)
	if !validEmail(email) {
		return nil
	}
	token := rand.Text()
	hash := sha256.Sum256([]byte(token))
	now := s.now()
	to, created, err := s.reset.store.CreateResetToken(ctx, email, hash[:], now, now.Add(resetTokenLifetime), resetRateLimit, resetRateWindow)
	if err != nil {
		return err
	}
	if !created {
		slog.Info("password reset not issued", "event", "password_reset_request", "outcome", "ignored")
		return nil
	}
	link := s.reset.baseURL + "/#reset=" + token
	text := "Someone asked to reset the password for your Good Morning Breach account.\n\n" +
		"Open this link within 30 minutes to choose a new password:\n" + link +
		"\n\nIf you did not ask for this, ignore this message. Your password has not changed.\n"
	s.reset.async(func() {
		sendCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := s.reset.mailer.SendText(sendCtx, to, "Reset your Good Morning Breach password", text); err != nil {
			slog.Error("password reset email failed", "event", "password_reset_request", "outcome", "failure", "error", err)
			return
		}
		slog.Info("password reset email sent", "event", "password_reset_request", "outcome", "success")
	})
	return nil
}

// ResetPassword sets a new password with a reset token. The token is used
// only if the new password is acceptable.
func (s *Service) ResetPassword(ctx context.Context, token, password string) error {
	if s.reset == nil || token == "" || len(token) > 128 {
		return ErrResetToken
	}
	if err := ValidateNewPassword(ctx, s.client, password); err != nil {
		return err
	}
	passwordHash, err := HashPassword(password)
	if err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(token))
	accountID, err := s.reset.store.ConsumeResetToken(ctx, hash[:], passwordHash, s.now())
	if err != nil {
		return err
	}
	slog.Info("password reset completed", "event", "password_reset", "account_id", accountID, "outcome", "success")
	return nil
}
