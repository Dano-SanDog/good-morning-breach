package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/egress"
	"github.com/Dano-SanDog/good-morning-breach/internal/retention"
	"github.com/mmcdole/gofeed"
)

const (
	maxFeedBytes         = 10 * 1024 * 1024
	collectionTimeout    = 30 * time.Second
	failureRecordTimeout = 5 * time.Second
)

type Result struct {
	SourceID      string
	ItemsReceived int
	ItemsSaved    int
	ItemsSkipped  int
	Skipped       bool
	Failure       string
}

type Collector struct {
	client *http.Client
	parser *gofeed.Parser
	store  Store
}

func NewCollector(client *http.Client, store Store) (*Collector, error) {
	if client == nil || store == nil {
		return nil, errors.New("collector requires an HTTP client and a store")
	}
	return &Collector{
		client: client,
		parser: gofeed.NewParser(),
		store:  store,
	}, nil
}

func (c *Collector) Run(ctx context.Context) (results []Result, runErr error) {
	releaseLock, err := c.store.AcquireCollectionLock(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire collection lock: %w", err)
	}
	if releaseLock == nil {
		return nil, errors.New("store returned no collection lock release function")
	}
	defer func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), failureRecordTimeout)
		defer releaseCancel()
		if err := releaseLock(releaseCtx); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("release collection lock: %w", err))
		}
	}()

	sources, err := c.store.ListEnabledSources(ctx)
	if err != nil {
		return nil, fmt.Errorf("list enabled sources: %w", err)
	}

	results = make([]Result, 0, len(sources))
	var failures []error
	for _, source := range sources {
		if ctx.Err() != nil {
			failures = append(failures, ctx.Err())
			break
		}
		result, err := c.collectSource(ctx, source)
		results = append(results, result)
		if err != nil {
			failures = append(failures, err)
		}
	}
	return results, errors.Join(failures...)
}

func (c *Collector) collectSource(parentCtx context.Context, source Source) (Result, error) {
	result := Result{SourceID: source.ID}
	startedAt := time.Now().UTC()
	ctx, cancel := context.WithTimeout(parentCtx, collectionTimeout)
	defer cancel()

	fail := func(cause string) (Result, error) {
		result.Failure = cause
		if parentCtx.Err() != nil {
			return result, fmt.Errorf("collection canceled: %w", parentCtx.Err())
		}
		run := Run{
			StartedAt:     startedAt,
			FinishedAt:    time.Now().UTC(),
			ItemsReceived: result.ItemsReceived,
			ItemsSkipped:  result.ItemsSkipped,
		}
		recordCtx, recordCancel := context.WithTimeout(context.WithoutCancel(parentCtx), failureRecordTimeout)
		defer recordCancel()
		if err := c.store.RecordFailure(recordCtx, source, run, cause); err != nil {
			return result, errors.Join(errors.New(cause), errors.New("failed to record collection failure"))
		}
		return result, errors.New(cause)
	}

	if err := source.Validate(); err != nil {
		return fail("source license record or configuration is invalid")
	}
	lastAttempt := source.LastAttemptAt
	if lastAttempt == nil {
		lastAttempt = source.LastSuccessAt
	}
	if lastAttempt != nil && time.Since(*lastAttempt) < source.PollInterval {
		result.Skipped = true
		return result, nil
	}

	var items []Item
	var received, skipped int
	switch source.Format {
	case FormatHackerNews:
		var failure string
		items, received, skipped, failure = c.collectHackerNews(ctx, source)
		if failure != "" {
			return fail(failure)
		}
	case FormatCISAKEV, FormatGitHubAdvisories, FormatNVD, FormatHIBPBreaches:
		address := source.Address
		if source.Format == FormatNVD {
			address = nvdRequestURL(source.Address, time.Now())
		}
		body, failure := c.fetchURL(ctx, address, "application/json", "json")
		if failure != "" {
			return fail(failure)
		}
		var ok bool
		switch source.Format {
		case FormatCISAKEV:
			items, received, skipped, ok = parseCISAKEV(body, time.Now())
		case FormatNVD:
			items, received, skipped, ok = parseNVD(body)
		case FormatHIBPBreaches:
			items, received, skipped, ok = parseHIBPBreaches(body, time.Now())
		default:
			items, received, skipped, ok = parseGitHubAdvisories(body)
		}
		if !ok {
			return fail("feed document is invalid")
		}
	default:
		feed, failure := c.fetchFeed(ctx, source)
		if failure != "" {
			return fail(failure)
		}
		items, skipped = normalizeItems(feed, source.CompleteTitles, source.storesExcerpt())
		received = len(feed.Items)
	}
	// Items older than the retention window would be re-created with a fresh
	// collection time after retention deletes them, so they are not stored.
	items, expired := dropExpired(items, time.Now())
	skipped += expired
	result.ItemsReceived = received
	result.ItemsSkipped = skipped
	run := Run{
		StartedAt:     startedAt,
		FinishedAt:    time.Now().UTC(),
		ItemsReceived: received,
		ItemsSkipped:  skipped,
	}
	saved, err := c.store.CompleteCollection(ctx, source, run, items)
	if err != nil {
		return fail("database write failed")
	}
	result.ItemsSaved = saved
	return result, nil
}

func dropExpired(items []Item, now time.Time) ([]Item, int) {
	cutoff := now.Add(-retention.StoryRetention)
	kept := items[:0:0]
	for _, item := range items {
		if item.PublishedAt != nil && item.PublishedAt.Before(cutoff) {
			continue
		}
		kept = append(kept, item)
	}
	return kept, len(items) - len(kept)
}

func (c *Collector) fetchFeed(ctx context.Context, source Source) (*gofeed.Feed, string) {
	body, failure := c.fetchBody(ctx, source, "application/rss+xml, application/atom+xml, application/xml, text/xml", "xml")
	if failure != "" {
		return nil, failure
	}
	feed, err := c.parser.Parse(io.LimitReader(bytes.NewReader(body), maxFeedBytes))
	if err != nil {
		return nil, "feed document is invalid"
	}
	return feed, ""
}

func (c *Collector) fetchBody(ctx context.Context, source Source, accept, mediaSubstring string) ([]byte, string) {
	return c.fetchURL(ctx, source.Address, accept, mediaSubstring)
}

func (c *Collector) fetchURL(ctx context.Context, address, accept, mediaSubstring string) ([]byte, string) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, "feed request could not be created"
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("User-Agent", "GoodMorningBreach/0.1 (personal non-commercial use)")

	response, err := c.client.Do(request)
	if err != nil {
		switch {
		case errors.Is(err, egress.ErrRedirect):
			return nil, "feed redirect refused"
		case errors.Is(err, context.DeadlineExceeded):
			return nil, "feed request timed out"
		case isTimeout(err):
			return nil, "feed request timed out"
		default:
			return nil, "feed request failed"
		}
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Sprintf("feed returned HTTP %d", response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || !strings.Contains(strings.ToLower(mediaType), mediaSubstring) {
			return nil, "feed returned an unsupported content type"
		}
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxFeedBytes+1))
	if err != nil {
		return nil, "feed response could not be read"
	}
	if len(body) > maxFeedBytes {
		return nil, "feed response exceeds the 10 MiB limit"
	}
	return body, ""
}

func normalizeItems(feed *gofeed.Feed, completeTitles, withExcerpt bool) ([]Item, int) {
	items := make([]Item, 0, len(feed.Items))
	seen := make(map[string]struct{}, len(feed.Items))
	skipped := 0

	for _, feedItem := range feed.Items {
		if feedItem == nil {
			skipped++
			continue
		}
		title, truncated := normalizeTitleChecked(feedItem.Title)
		if completeTitles && truncated {
			skipped++
			continue
		}
		link := normalizeLink(feedItem.Link)
		if title == "" || link == "" {
			skipped++
			continue
		}
		if _, ok := seen[link]; ok {
			skipped++
			continue
		}
		seen[link] = struct{}{}

		item := Item{Title: title, CanonicalURL: link}
		if withExcerpt {
			item.Excerpt = normalizeExcerpt(feedItem.Description)
		}
		if feedItem.PublishedParsed != nil {
			publishedAt := feedItem.PublishedParsed.UTC()
			item.PublishedAt = &publishedAt
		}
		items = append(items, item)
	}
	return items, skipped
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}
