package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type memoryStore struct {
	sources       []Source
	completed     []Item
	failures      []string
	failedSources []string
	listError     error
	completeError error
	lockError     error
	unlockError   error
	lockCalls     int
	unlockCalls   int
	lockHeld      bool
}

func (s *memoryStore) AcquireCollectionLock(context.Context) (func(context.Context) error, error) {
	s.lockCalls++
	if s.lockError != nil {
		return nil, s.lockError
	}
	s.lockHeld = true
	return func(context.Context) error {
		s.unlockCalls++
		s.lockHeld = false
		return s.unlockError
	}, nil
}

func (s *memoryStore) ListEnabledSources(context.Context) ([]Source, error) {
	return s.sources, s.listError
}

func (s *memoryStore) CompleteCollection(_ context.Context, _ Source, _ Run, items []Item) (int, error) {
	if s.completeError != nil {
		return 0, s.completeError
	}
	s.completed = append(s.completed, items...)
	return len(items), nil
}

func (s *memoryStore) RecordFailure(_ context.Context, source Source, _ Run, cause string) error {
	s.failures = append(s.failures, cause)
	s.failedSources = append(s.failedSources, source.ID)
	return nil
}

func testSource(id string) Source {
	return Source{
		ID:            id,
		Name:          "CERT-EU",
		Address:       "https://cert.europa.eu/publications/security-advisories-rss",
		LicenseName:   "Creative Commons Attribution 4.0 International",
		LicenseURL:    "https://cert.europa.eu/legal-notice",
		PermittedUse:  "Reuse with attribution and indication of changes.",
		Attribution:   "Source: CERT-EU. Licensed under CC BY 4.0.",
		ContentPolicy: ContentHeadlineLink,
		Format:        FormatRSS,
		PollInterval:  24 * time.Hour,
	}
}

func TestRunNormalizesAndDeduplicatesFeedItems(t *testing.T) {
	store := &memoryStore{sources: []Source{testSource("cert-eu")}}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return feedResponse(`<?xml version="1.0"?>
			<rss version="2.0"><channel>
			<title>Feed</title><item>
			<title>&amp;lt;img src=x onerror=alert(1)&amp;gt; CERT-EU advisory</title>
			<link>https://cert.europa.eu/advisory/#section</link>
			<pubDate>Mon, 16 Nov 2026 10:00:00 GMT</pubDate>
			</item><item><title>Duplicate</title>
			<link>https://cert.europa.eu/advisory/</link></item>
			<item><title>Unsafe link</title><link>javascript:alert(1)</link></item>
			</channel></rss>`), nil
	})}
	collector, err := NewCollector(client, store)
	if err != nil {
		t.Fatal(err)
	}

	results, err := collector.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ItemsReceived != 3 || results[0].ItemsSaved != 1 || results[0].ItemsSkipped != 2 {
		t.Fatalf("unexpected result: %+v", results)
	}
	if len(store.completed) != 1 {
		t.Fatalf("stored %d items, want 1", len(store.completed))
	}
	item := store.completed[0]
	if strings.ContainsAny(item.Title, "<>") || item.Title != "CERT-EU advisory" {
		t.Fatalf("title was not normalized to plain text: %q", item.Title)
	}
	if item.CanonicalURL != "https://cert.europa.eu/advisory/" {
		t.Fatalf("canonical URL = %q", item.CanonicalURL)
	}
	if item.PublishedAt == nil || item.PublishedAt.Location() != time.UTC {
		t.Fatalf("published timestamp was not normalized to UTC: %v", item.PublishedAt)
	}
}

func TestRunRecordsFailuresAndContinuesToOtherSources(t *testing.T) {
	first := testSource("unavailable")
	second := testSource("available")
	first.Address = "https://cert.europa.eu/unavailable"
	second.Address = "https://cert.europa.eu/available"
	store := &memoryStore{sources: []Source{first, second}}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if strings.Contains(request.URL.Path, "unavailable") {
			return nil, errors.New("network failure")
		}
		return feedResponse(`<rss version="2.0"><channel><title>Feed</title></channel></rss>`), nil
	})}
	collector, err := NewCollector(client, store)
	if err != nil {
		t.Fatal(err)
	}

	results, err := collector.Run(context.Background())
	if err == nil {
		t.Fatal("expected a collection failure")
	}
	if len(results) != 2 || results[0].Failure == "" || results[1].Failure != "" {
		t.Fatalf("unexpected results: %+v", results)
	}
	if len(store.failedSources) != 1 || store.failedSources[0] != "unavailable" {
		t.Fatalf("failed sources = %v", store.failedSources)
	}
}

func TestRunRecordsInvalidFeedAndContinues(t *testing.T) {
	first := testSource("invalid")
	second := testSource("valid")
	first.Address = "https://cert.europa.eu/invalid"
	second.Address = "https://cert.europa.eu/valid"
	store := &memoryStore{sources: []Source{first, second}}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if strings.Contains(request.URL.Path, "invalid") {
			return feedResponse(`<rss><channel><item>`), nil
		}
		return feedResponse(`<rss version="2.0"><channel><title>Feed</title></channel></rss>`), nil
	})}
	collector, err := NewCollector(client, store)
	if err != nil {
		t.Fatal(err)
	}

	results, err := collector.Run(context.Background())
	if err == nil || len(results) != 2 {
		t.Fatalf("Run() = (%v, %v), want an invalid-feed failure and continued collection", results, err)
	}
	if results[0].Failure != "feed document is invalid" || results[1].Failure != "" {
		t.Fatalf("unexpected results: %+v", results)
	}
	if len(store.failedSources) != 1 || store.failedSources[0] != "invalid" {
		t.Fatalf("failed sources = %v", store.failedSources)
	}
}

func TestRunRejectsOversizedFeedAndRecordsCause(t *testing.T) {
	store := &memoryStore{sources: []Source{testSource("large")}}
	body := `<rss version="2.0"><channel><title>` +
		strings.Repeat("x", maxFeedBytes+1) +
		`</title></channel></rss>`
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return feedResponse(body), nil
	})}
	collector, err := NewCollector(client, store)
	if err != nil {
		t.Fatal(err)
	}

	results, err := collector.Run(context.Background())
	if err == nil || len(results) != 1 {
		t.Fatalf("Run() = (%v, %v), want an oversized-feed failure", results, err)
	}
	if results[0].Failure != "feed response exceeds the 10 MiB limit" {
		t.Fatalf("failure = %q", results[0].Failure)
	}
	if len(store.failures) != 1 || store.failures[0] != results[0].Failure {
		t.Fatalf("recorded failures = %v", store.failures)
	}
}

func TestRunSkipsSourceUntilItsPollInterval(t *testing.T) {
	lastSuccess := time.Now().Add(-time.Hour)
	source := testSource("recent")
	source.LastSuccessAt = &lastSuccess
	store := &memoryStore{sources: []Source{source}}
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, fmt.Errorf("unexpected request")
	})}
	collector, err := NewCollector(client, store)
	if err != nil {
		t.Fatal(err)
	}

	results, err := collector.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].Skipped || requests != 0 {
		t.Fatalf("results = %+v, requests = %d", results, requests)
	}
}

func TestRunReleasesCollectionLockAfterSourceListingFailure(t *testing.T) {
	store := &memoryStore{listError: errors.New("database unavailable")}
	collector, err := NewCollector(&http.Client{}, store)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := collector.Run(context.Background()); err == nil {
		t.Fatal("expected source listing failure")
	}
	if store.lockCalls != 1 || store.unlockCalls != 1 || store.lockHeld {
		t.Fatalf("collection lock state: acquired %d times, released %d times, held = %v",
			store.lockCalls, store.unlockCalls, store.lockHeld)
	}
}

func TestRunReportsCollectionLockReleaseFailure(t *testing.T) {
	store := &memoryStore{unlockError: errors.New("unlock failed")}
	collector, err := NewCollector(&http.Client{}, store)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := collector.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "release collection lock") {
		t.Fatalf("Run() error = %v, want a lock-release failure", err)
	}
}

func TestSourceValidationRequiresLicenseRecordAndHTTPS(t *testing.T) {
	source := testSource("cert-eu")
	source.LicenseURL = "http://example.test/license"
	if err := source.Validate(); err == nil {
		t.Fatal("expected non-HTTPS license address to be rejected")
	}
	source = testSource("cert-eu")
	source.LicenseName = ""
	if err := source.Validate(); err == nil {
		t.Fatal("expected incomplete license record to be rejected")
	}
}

func feedResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/rss+xml"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestParseCISAKEVKeepsRecentEntriesWithNVDLinks(t *testing.T) {
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	body := `{"vulnerabilities":[
		{"cveID":"CVE-2024-10441","vendorProject":"Synology","product":"DSM","vulnerabilityName":"<b>Escaping</b> flaw","dateAdded":"2026-11-18"},
		{"cveID":"CVE-2020-0001","vendorProject":"Old","product":"Thing","vulnerabilityName":"Old","dateAdded":"2020-01-01"},
		{"cveID":"bad\"><x","vendorProject":"V","product":"P","vulnerabilityName":"N","dateAdded":"2026-11-18"},
		{"cveID":"CVE-2024-10441","vendorProject":"Synology","product":"DSM","vulnerabilityName":"dup","dateAdded":"2026-11-18"}]}`
	items, received, skipped, ok := parseCISAKEV([]byte(body), now)
	if !ok || len(items) != 1 || received != 2 || skipped != 2 {
		t.Fatalf("items=%d received=%d skipped=%d ok=%v", len(items), received, skipped, ok)
	}
	if items[0].Title != "CVE-2024-10441: Synology DSM - Escaping flaw" ||
		items[0].CanonicalURL != "https://nvd.nist.gov/vuln/detail/CVE-2024-10441" ||
		items[0].PublishedAt == nil {
		t.Fatalf("unexpected item %+v", items[0])
	}
	if _, _, _, ok := parseCISAKEV([]byte(`{"x":1}`), now); ok {
		t.Fatal("expected a document without vulnerabilities to be invalid")
	}
}

func TestParseGitHubAdvisoriesRebuildsLinksFromValidIDs(t *testing.T) {
	body := `[
		{"ghsa_id":"GHSA-mc8w-wjhw-45x5","summary":"Pre-auth <i>file</i> read","html_url":"https://evil.example/x","published_at":"2026-11-18T10:00:00Z"},
		{"ghsa_id":"not-an-id","summary":"x","published_at":"2026-11-18T10:00:00Z"},
		{"ghsa_id":"GHSA-mc8w-wjhw-45x5","summary":"dup"}]`
	items, received, skipped, ok := parseGitHubAdvisories([]byte(body))
	if !ok || len(items) != 1 || received != 3 || skipped != 2 {
		t.Fatalf("items=%d received=%d skipped=%d ok=%v", len(items), received, skipped, ok)
	}
	if items[0].Title != "Pre-auth file read" ||
		items[0].CanonicalURL != "https://github.com/advisories/GHSA-mc8w-wjhw-45x5" ||
		items[0].PublishedAt == nil {
		t.Fatalf("unexpected item %+v", items[0])
	}
}

func TestRunCollectsJSONSourceAndRejectsInvalidJSON(t *testing.T) {
	source := testSource("ghsa")
	source.Format = FormatGitHubAdvisories
	source.Address = "https://api.github.com/advisories"
	body := `[{"ghsa_id":"GHSA-mc8w-wjhw-45x5","summary":"A flaw"}]`
	store := &memoryStore{sources: []Source{source}}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected Accept %q", r.Header.Get("Accept"))
		}
		return jsonResponse(body), nil
	})}
	collector, _ := NewCollector(client, store)
	if _, err := collector.Run(context.Background()); err != nil || len(store.completed) != 1 {
		t.Fatalf("err=%v completed=%d", err, len(store.completed))
	}

	store = &memoryStore{sources: []Source{source}}
	client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(`<html>`), nil
	})}
	collector, _ = NewCollector(client, store)
	if _, err := collector.Run(context.Background()); err == nil || len(store.failures) != 1 {
		t.Fatalf("expected a recorded failure, err=%v", err)
	}
}
