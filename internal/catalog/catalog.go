// Package catalog lets administrators manage story categories and data sources.
package catalog

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Dano-SanDog/good-morning-breach/internal/egress"
	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
	"github.com/Dano-SanDog/good-morning-breach/internal/ingest"
)

var (
	ErrNotFound  = errors.New("record not found")
	ErrConflict  = errors.New("a record with that name already exists")
	ErrInUse     = errors.New("this record has collected history, so disable it instead of deleting it")
	ErrProtected = errors.New("the Other category is the fallback category and cannot be disabled or deleted")
)

// ValidationError is safe to show to an administrator.
type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }

func invalid(format string, args ...any) error {
	return &ValidationError{Message: fmt.Sprintf(format, args...)}
}

const (
	FallbackCategoryID    = "other"
	MinPollIntervalSecond = 3600
	MaxPollIntervalSecond = 3600 // FR-1.8: every enabled source is collected at least hourly
)

type Category struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Enabled    bool      `json:"enabled"`
	StoryCount int64     `json:"storyCount"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type Source struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Address              string    `json:"address"`
	Format               string    `json:"format"`
	LicenseName          string    `json:"licenseName"`
	LicenseURL           string    `json:"licenseUrl"`
	PermittedUse         string    `json:"permittedUse"`
	Attribution          string    `json:"attribution"`
	ContentPolicy        string    `json:"contentPolicy"`
	PollIntervalSeconds  int64     `json:"pollIntervalSeconds"`
	Enabled              bool      `json:"enabled"`
	RequireCompleteTitle bool      `json:"requireCompleteTitle"`
	StoryCount           int64     `json:"storyCount"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

type SourcePatch struct {
	Name                 *string
	Address              *string
	Format               *string
	LicenseName          *string
	LicenseURL           *string
	PermittedUse         *string
	Attribution          *string
	ContentPolicy        *string
	PollIntervalSeconds  *int64
	Enabled              *bool
	RequireCompleteTitle *bool
}

// Store persists catalog changes. Mutations must write their audit record in the same transaction.
type Store interface {
	ListCategories(context.Context) ([]Category, error)
	GetCategory(context.Context, string) (Category, error)
	CreateCategory(ctx context.Context, actorID int64, id, name string) (Category, error)
	UpdateCategory(ctx context.Context, actorID int64, id, name string, enabled bool) error
	DeleteCategory(ctx context.Context, actorID int64, id string) error
	ListSources(context.Context) ([]Source, error)
	GetSource(context.Context, string) (Source, error)
	CreateSource(ctx context.Context, actorID int64, source Source) (Source, error)
	UpdateSource(ctx context.Context, actorID int64, source Source) error
	DeleteSource(ctx context.Context, actorID int64, id string) error
}

type Authorizer interface {
	RequireAdmin(ctx context.Context, token string) (identity.AuthenticatedUser, error)
}

type Service struct {
	store Store
	auth  Authorizer
}

func NewService(store Store, auth Authorizer) (*Service, error) {
	if store == nil || auth == nil {
		return nil, errors.New("catalog store and authorizer are required")
	}
	return &Service{store: store, auth: auth}, nil
}

func (s *Service) ListCategories(ctx context.Context, token string) ([]Category, error) {
	if _, err := s.auth.RequireAdmin(ctx, token); err != nil {
		return nil, err
	}
	return s.store.ListCategories(ctx)
}

func (s *Service) CreateCategory(ctx context.Context, token, name string) (Category, error) {
	admin, err := s.auth.RequireAdmin(ctx, token)
	if err != nil {
		return Category{}, err
	}
	name, err = cleanText("category name", name, 80)
	if err != nil {
		return Category{}, err
	}
	id := slug(name, 80)
	if id == "" {
		return Category{}, invalid("category name must contain letters or digits")
	}
	return s.store.CreateCategory(ctx, admin.AccountID, id, name)
}

func (s *Service) UpdateCategory(ctx context.Context, token, id string, name *string, enabled *bool) error {
	admin, err := s.auth.RequireAdmin(ctx, token)
	if err != nil {
		return err
	}
	if name == nil && enabled == nil {
		return invalid("provide a name or enabled change")
	}
	current, err := s.store.GetCategory(ctx, id)
	if err != nil {
		return err
	}
	if name != nil {
		cleaned, err := cleanText("category name", *name, 80)
		if err != nil {
			return err
		}
		if slug(cleaned, 80) == "" {
			return invalid("category name must contain letters or digits")
		}
		current.Name = cleaned
	}
	if enabled != nil {
		if !*enabled && current.ID == FallbackCategoryID {
			return ErrProtected
		}
		current.Enabled = *enabled
	}
	return s.store.UpdateCategory(ctx, admin.AccountID, current.ID, current.Name, current.Enabled)
}

func (s *Service) DeleteCategory(ctx context.Context, token, id string) error {
	admin, err := s.auth.RequireAdmin(ctx, token)
	if err != nil {
		return err
	}
	if id == FallbackCategoryID {
		return ErrProtected
	}
	return s.store.DeleteCategory(ctx, admin.AccountID, id)
}

func (s *Service) ListSources(ctx context.Context, token string) ([]Source, error) {
	if _, err := s.auth.RequireAdmin(ctx, token); err != nil {
		return nil, err
	}
	return s.store.ListSources(ctx)
}

func (s *Service) CreateSource(ctx context.Context, token string, source Source) (Source, error) {
	admin, err := s.auth.RequireAdmin(ctx, token)
	if err != nil {
		return Source{}, err
	}
	source, err = normalizeSource(source)
	if err != nil {
		return Source{}, err
	}
	source.ID = slug(source.Name, 60)
	if source.ID == "" {
		return Source{}, invalid("source name must contain letters or digits")
	}
	return s.store.CreateSource(ctx, admin.AccountID, source)
}

func (s *Service) UpdateSource(ctx context.Context, token, id string, patch SourcePatch) error {
	admin, err := s.auth.RequireAdmin(ctx, token)
	if err != nil {
		return err
	}
	current, err := s.store.GetSource(ctx, id)
	if err != nil {
		return err
	}
	applyPatch(&current, patch)
	current, err = normalizeSource(current)
	if err != nil {
		return err
	}
	return s.store.UpdateSource(ctx, admin.AccountID, current)
}

func (s *Service) DeleteSource(ctx context.Context, token, id string) error {
	admin, err := s.auth.RequireAdmin(ctx, token)
	if err != nil {
		return err
	}
	return s.store.DeleteSource(ctx, admin.AccountID, id)
}

func applyPatch(source *Source, patch SourcePatch) {
	if patch.Name != nil {
		source.Name = *patch.Name
	}
	if patch.Address != nil {
		source.Address = *patch.Address
	}
	if patch.Format != nil {
		source.Format = *patch.Format
	}
	if patch.LicenseName != nil {
		source.LicenseName = *patch.LicenseName
	}
	if patch.LicenseURL != nil {
		source.LicenseURL = *patch.LicenseURL
	}
	if patch.PermittedUse != nil {
		source.PermittedUse = *patch.PermittedUse
	}
	if patch.Attribution != nil {
		source.Attribution = *patch.Attribution
	}
	if patch.ContentPolicy != nil {
		source.ContentPolicy = *patch.ContentPolicy
	}
	if patch.PollIntervalSeconds != nil {
		source.PollIntervalSeconds = *patch.PollIntervalSeconds
	}
	if patch.Enabled != nil {
		source.Enabled = *patch.Enabled
	}
	if patch.RequireCompleteTitle != nil {
		source.RequireCompleteTitle = *patch.RequireCompleteTitle
	}
}

// normalizeSource enforces FR-8.2, FR-8.3, FR-8.8, FR-1.6, FR-1.15, and SC-015.
func normalizeSource(source Source) (Source, error) {
	var err error
	if source.Name, err = cleanText("source name", source.Name, 120); err != nil {
		return Source{}, err
	}
	if source.LicenseName, err = cleanText("license name", source.LicenseName, 200); err != nil {
		return Source{}, err
	}
	if source.PermittedUse, err = cleanText("permitted use", source.PermittedUse, 2000); err != nil {
		return Source{}, err
	}
	if source.Attribution, err = cleanText("attribution", source.Attribution, 1000); err != nil {
		return Source{}, err
	}
	if source.Address, err = validateHTTPSURL("source address", source.Address); err != nil {
		return Source{}, err
	}
	if source.LicenseURL, err = validateHTTPSURL("license link", source.LicenseURL); err != nil {
		return Source{}, err
	}
	if blockedSource(source.Name, source.Address) {
		return Source{}, invalid("this source is out of scope or its terms prohibit use")
	}
	if source.PollIntervalSeconds < MinPollIntervalSecond || source.PollIntervalSeconds > MaxPollIntervalSecond {
		return Source{}, invalid("poll interval must be between %d and %d seconds", MinPollIntervalSecond, MaxPollIntervalSecond)
	}
	if source.Format == "" {
		source.Format = string(ingest.FormatRSS)
	}
	candidate := ingest.Source{
		ID: "x", Name: source.Name, Address: source.Address, LicenseName: source.LicenseName,
		LicenseURL: source.LicenseURL, PermittedUse: source.PermittedUse, Attribution: source.Attribution,
		ContentPolicy: ingest.ContentPolicy(source.ContentPolicy), Format: ingest.Format(source.Format),
		PollInterval: time.Duration(source.PollIntervalSeconds) * time.Second,
	}
	if err := candidate.Validate(); err != nil {
		return Source{}, invalid("%s", err.Error())
	}
	return source, nil
}

var blockedHostSuffixes = []string{
	"reddit.com", "redd.it", "redditmedia.com", "cloudflare.com", "first.org", "abuse.ch",
	"cyber.gov.au", "alienvault.com", "levelblue.com", "greynoise.io", "openphish.com",
	"spamhaus.org", "shadowserver.org",
}

var blockedNameWords = []string{
	"reddit", "cloudflare", "epss", "vulnrichment", "abuse.ch", "feodo", "urlhaus", "threatfox",
	"malwarebazaar", "acsc", "alienvault", "greynoise", "openphish", "spamhaus", "shadowserver",
}

func blockedSource(name, address string) bool {
	lowerName := strings.ToLower(name)
	for _, word := range blockedNameWords {
		if strings.Contains(lowerName, word) {
			return true
		}
	}
	parsed, err := url.Parse(address)
	if err != nil {
		return true
	}
	host := strings.TrimRight(strings.ToLower(parsed.Hostname()), ".")
	for _, suffix := range blockedHostSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(parsed.Path), "/cisagov/vulnrichment")
}

// validateHTTPSURL accepts only absolute https URLs on public hosts. The outbound client
// still blocks private addresses and redirects at connect time (SC-020).
func validateHTTPSURL(field, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 || !utf8.ValidString(raw) {
		return "", invalid("%s must be an absolute HTTPS URL", field)
	}
	for _, r := range raw {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", invalid("%s must be an absolute HTTPS URL", field)
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Opaque != "" || parsed.Fragment != "" {
		return "", invalid("%s must be an absolute HTTPS URL", field)
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return "", invalid("%s must use the default HTTPS port", field)
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		if egress.IsBlockedAddr(ip) {
			return "", invalid("%s must not point at a private or reserved address", field)
		}
		return raw, nil
	}
	if !strings.Contains(host, ".") || host == "localhost" ||
		strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".localdomain") {
		return "", invalid("%s must use a public host name", field)
	}
	return raw, nil
}

func cleanText(field, value string, maxRunes int) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", invalid("%s is required", field)
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxRunes {
		return "", invalid("%s must be valid text of at most %d characters", field, maxRunes)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", invalid("%s must not contain control characters", field)
		}
	}
	return value, nil
}

func slug(name string, maxLen int) string {
	var builder strings.Builder
	pendingDash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			if pendingDash && builder.Len() > 0 {
				builder.WriteByte('-')
			}
			pendingDash = false
			builder.WriteRune(r)
		default:
			pendingDash = true
		}
	}
	out := builder.String()
	if len(out) > maxLen {
		out = strings.TrimRight(out[:maxLen], "-")
	}
	return out
}
