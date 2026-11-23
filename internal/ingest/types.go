package ingest

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/contentrights"
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
	FormatNVD              Format = "nvd_json"
	FormatHIBPBreaches     Format = "hibp_breaches_json"
	FormatHackerNews       Format = "hacker_news_json"
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
	RightsClass    string // empty means licensed
	PollInterval   time.Duration
	LastSuccessAt  *time.Time
	LastAttemptAt  *time.Time // latest success or failure; gates the next fetch
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
	case FormatRSS, FormatCISAKEV, FormatGitHubAdvisories, FormatNVD, FormatHIBPBreaches, FormatHackerNews:
	default:
		return errors.New("source format is invalid")
	}
	rights := s.RightsClass
	if rights == "" {
		rights = contentrights.RightsLicensed
	}
	return contentrights.ValidateSource(contentrights.Source{Policy: string(s.ContentPolicy), Rights: rights})
}

// storesExcerpt reports whether the content-rights gate lets this source's
// verbatim excerpt be stored. Other sources keep headline and link only.
func (s Source) storesExcerpt() bool {
	rights := s.RightsClass
	if rights == "" {
		rights = contentrights.RightsLicensed
	}
	return contentrights.Resolve([]contentrights.Source{{Policy: string(s.ContentPolicy), Rights: rights}}).Excerpt
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
	Excerpt      string // plain-text verbatim prefix; set only for sources whose rights permit it
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
