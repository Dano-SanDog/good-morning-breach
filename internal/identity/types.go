package identity

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

var (
	ErrNotFound     = errors.New("identity record not found")
	ErrAdminExists  = errors.New("an administrator already exists")
	ErrCredentials  = errors.New("email, password, or code is incorrect")
	ErrSession      = errors.New("session is invalid")
	ErrOTPReplay    = errors.New("one-time code has already been used")
	ErrTOTPEnrolled = errors.New("time-based code is already enrolled")
	ErrTOTPSetup    = errors.New("time-based code setup is not pending")
)

type Account struct {
	ID                   int64
	Email                string
	Role                 string
	PasswordHash         string
	Enabled              bool
	TOTPSecretCiphertext []byte
	TOTPNonce            []byte
	TOTPEnrolled         bool
	LastTOTPStep         int64
	LockedUntil          *time.Time
}

type Session struct {
	Account          Account
	CreatedAt        time.Time
	LastSeenAt       time.Time
	ExpiresAt        time.Time
	PartialExpiresAt *time.Time
}

func (Account) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

func (Session) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

func (LoginResult) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

type Story struct {
	ID          int64      `json:"id"`
	Title       string     `json:"title"`
	URL         string     `json:"url"`
	Sources     []string   `json:"sources"`
	PublishedAt *time.Time `json:"publishedAt"`
	Categories  []string   `json:"categories"`
	Risk        string     `json:"risk"`
	Sentiment   string     `json:"sentiment"`
}

type Store interface {
	CreateAdmin(context.Context, string, string) (int64, error)
	AccountByEmail(context.Context, string) (Account, error)
	RecordFailedLogin(context.Context, int64, time.Time) (bool, error)
	CreatePartialSession(context.Context, []byte, []byte, int64, time.Time, time.Time) error
	LoadSession(context.Context, []byte, time.Time) (Session, error)
	TouchSession(context.Context, []byte, time.Time) error
	BeginTOTPSetup(context.Context, []byte, int64, []byte, []byte, time.Time) error
	CompleteTOTP(context.Context, []byte, []byte, int64, time.Time, bool) (Account, error)
	DeleteSession(context.Context, []byte) error
	ListStories(context.Context, time.Time) ([]Story, error)
}
