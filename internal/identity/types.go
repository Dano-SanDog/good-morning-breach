package identity

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/contentrights"
)

var (
	ErrNotFound             = errors.New("identity record not found")
	ErrAdminExists          = errors.New("an administrator already exists")
	ErrCredentials          = errors.New("email or password is incorrect")
	ErrSession              = errors.New("session is invalid")
	ErrAdminRequired        = errors.New("administrator role required")
	ErrAccountExists        = errors.New("account already exists")
	ErrLastAdmin            = errors.New("the last active administrator cannot be removed")
	ErrSelfManagement       = errors.New("an administrator cannot disable, delete, or demote their own account")
	ErrInvalidEmail         = errors.New("enter a valid email address")
	ErrInvalidRole          = errors.New("account role must be admin or user")
	ErrInvalidAccountUpdate = errors.New("provide a valid role or enabled status change")
	ErrInvalidAlertSettings = errors.New("invalid alert settings")
)

type Account struct {
	ID           int64
	Email        string
	Role         string
	PasswordHash string
	Enabled      bool
	LockedUntil  *time.Time
}

type Session struct {
	Account    Account
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

type ManagedAccount struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

type AdminAuditRecord struct {
	ID              int64     `json:"id"`
	ActorAccountID  int64     `json:"actorAccountId"`
	TargetAccountID int64     `json:"targetAccountId"`
	TargetKind      string    `json:"targetKind"`
	TargetID        string    `json:"targetId"`
	Action          string    `json:"action"`
	Details         string    `json:"details"`
	CreatedAt       time.Time `json:"createdAt"`
}

type SourceStatus struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Enabled          bool       `json:"enabled"`
	LastSuccessAt    *time.Time `json:"lastSuccessAt"`
	LastFailureAt    *time.Time `json:"lastFailureAt"`
	LastFailureCause *string    `json:"lastFailureCause"`
	FailingSince     *time.Time `json:"failingSince"`
	Warning          bool       `json:"warning"`
}

type AttackTechnique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
	URL     string   `json:"url"`
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
	ID int64 `json:"id"`
	// Content is set only by contentrights.Gate (SC-023).
	contentrights.Content
	Sources          []string          `json:"sources"`
	Attributions     []string          `json:"attributions"`
	PublishedAt      *time.Time        `json:"publishedAt"`
	Categories       []string          `json:"categories"`
	Risk             string            `json:"risk"`
	Sentiment        string            `json:"sentiment"`
	AttackTechniques []AttackTechnique `json:"attackTechniques"`
	CVEs             []string          `json:"cves"`
	Related          []RelatedStory    `json:"related"`
}

// RelatedStory is another story that names the same CVE (FR-1.13). It carries
// only the headline and link, which every content policy permits.
type RelatedStory struct {
	ID    int64  `json:"id"`
	Title string `json:"title"`
	URL   string `json:"url"`
	CVE   string `json:"cve"`
}

type StoryFilter struct {
	After    time.Time
	Before   *time.Time
	Search   string
	Category string
	Risk     string
	Source   string
	Attack   string
	Offset   int
}

type AlertSettings struct {
	Enabled     bool    `json:"enabled"`
	Time        string  `json:"time"`
	TimeZone    string  `json:"timeZone"`
	Days        []int16 `json:"days"`
	MinimumRisk string  `json:"minimumRisk"`
}

type Store interface {
	CreateAdmin(context.Context, string, string) (int64, error)
	ListAccounts(context.Context) ([]ManagedAccount, error)
	CreateAccount(context.Context, int64, string, string, string) (ManagedAccount, error)
	UpdateAccount(context.Context, int64, int64, *string, *bool) error
	DeleteAccount(context.Context, int64, int64) error
	ListAdminAudit(context.Context) ([]AdminAuditRecord, error)
	ListSourceStatuses(context.Context) ([]SourceStatus, error)
	GetAlertSettings(context.Context, int64) (AlertSettings, error)
	SaveAlertSettings(context.Context, int64, AlertSettings) error
	AccountByEmail(context.Context, string) (Account, error)
	RecordFailedLogin(context.Context, int64, time.Time) (bool, error)
	CreateSession(context.Context, []byte, []byte, int64, time.Time) error
	LoadSession(context.Context, []byte, time.Time) (Session, error)
	TouchSession(context.Context, []byte, time.Time) error
	DeleteSession(context.Context, []byte) error
	ListStories(context.Context, StoryFilter) ([]Story, error)
}
