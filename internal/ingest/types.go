package ingest

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

type ContentPolicy string

const (
	ContentFullText        ContentPolicy = "full_text"
	ContentVerbatimExcerpt ContentPolicy = "verbatim_excerpt"
	ContentSystemSummary   ContentPolicy = "system_summary"
	ContentHeadlineLink    ContentPolicy = "headline_link"
)

type Format string

const (
	FormatRSS              Format = "rss"
	FormatCISAKEV          Format = "cisa_kev_json"
	FormatGitHubAdvisories Format = "github_advisories_json"
)

type Source struct {
	Format Format
	// CompleteTitles skips items whose title would be shortened, for sources whose terms forbid changes.
	CompleteTitles bool
	ID             string
	Name           string
	Address        string
	LicenseName    string
	LicenseURL     string
	PermittedUse   string
	Attribution    string
	ContentPolicy  ContentPolicy
	PollInterval   time.Duration
	LastSuccessAt  *time.Time
}

func (s Source) Validate() error {
	if strings.TrimSpace(s.ID) == "" ||
		strings.TrimSpace(s.Name) == "" ||
		strings.TrimSpace(s.LicenseName) == "" ||
		strings.TrimSpace(s.PermittedUse) == "" ||
		strings.TrimSpace(s.Attribution) == "" {
		return errors.New("source license record is incomplete")
	}
	if !isHTTPSURL(s.Address) || !isHTTPSURL(s.LicenseURL) {
		return errors.New("source and license addresses must be absolute HTTPS URLs")
	}
	if s.PollInterval <= 0 {
		return errors.New("source poll interval must be positive")
	}
	switch s.Format {
	case FormatRSS, FormatCISAKEV, FormatGitHubAdvisories:
	default:
		return errors.New("source format is invalid")
	}
	switch s.ContentPolicy {
	case ContentFullText, ContentVerbatimExcerpt, ContentSystemSummary, ContentHeadlineLink:
		return nil
	default:
		return errors.New("source content policy is invalid")
	}
}

func isHTTPSURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil &&
		parsed.Scheme == "https" &&
		parsed.Host != "" &&
		parsed.User == nil &&
		parsed.Opaque == ""
}

type Item struct {
	Title        string
	CanonicalURL string
	PublishedAt  *time.Time
}

type Run struct {
	StartedAt     time.Time
	FinishedAt    time.Time
	ItemsReceived int
	ItemsSkipped  int
}

type Store interface {
	AcquireCollectionLock(context.Context) (func(context.Context) error, error)
	ListEnabledSources(context.Context) ([]Source, error)
	CompleteCollection(context.Context, Source, Run, []Item) (int, error)
	RecordFailure(context.Context, Source, Run, string) error
}
