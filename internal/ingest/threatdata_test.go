package ingest

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNVDRequestURLAsksForRecentCriticalCVEs(t *testing.T) {
	got := nvdRequestURL("https://services.nvd.nist.gov/rest/json/cves/2.0", time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC))
	for _, want := range []string{"cvssV3Severity=CRITICAL", "pubStartDate=2026-11-17T12%3A00%3A00.000%2B00%3A00", "pubEndDate=2026-11-20T12%3A00%3A00.000%2B00%3A00"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
}

func TestParseNVDBuildsHeadlinesAndRebuildsLinks(t *testing.T) {
	body := `{"totalResults":3,"vulnerabilities":[
		{"cve":{"id":"CVE-2026-1111","published":"2026-11-18T12:17:10.783","descriptions":[{"lang":"es","value":"no"},{"lang":"en","value":"<b>RCE</b> in Widget"}]}},
		{"cve":{"id":"bad\"><x","descriptions":[{"lang":"en","value":"x"}]}},
		{"cve":{"id":"CVE-2026-1111","descriptions":[]}}]}`
	items, received, skipped, ok := parseNVD([]byte(body))
	if !ok || len(items) != 1 || received != 3 || skipped != 2 {
		t.Fatalf("items=%d received=%d skipped=%d ok=%v", len(items), received, skipped, ok)
	}
	if items[0].Title != "CVE-2026-1111: RCE in Widget" || items[0].CanonicalURL != "https://nvd.nist.gov/vuln/detail/CVE-2026-1111" || items[0].PublishedAt == nil {
		t.Fatalf("unexpected item %+v", items[0])
	}
	if _, _, _, ok := parseNVD([]byte(`{"totalResults":0,"vulnerabilities":[]}`)); !ok {
		t.Fatal("an empty result is valid")
	}
	if _, _, _, ok := parseNVD([]byte(`{"x":1}`)); ok {
		t.Fatal("a document without totalResults is invalid")
	}
}

func TestParseHIBPBreachesKeepsRecentRealBreaches(t *testing.T) {
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	body := `[
		{"Name":"Careers360","Title":"Careers<i>360</i>","AddedDate":"2026-11-20T03:44:54Z","PwnCount":3609421},
		{"Name":"Old","Title":"Old","AddedDate":"2020-01-01T00:00:00Z","PwnCount":1},
		{"Name":"Fake","Title":"Fake","AddedDate":"2026-11-19T00:00:00Z","PwnCount":1,"IsFabricated":true},
		{"Name":"bad/../name","Title":"x","AddedDate":"2026-11-19T00:00:00Z"}]`
	items, received, skipped, ok := parseHIBPBreaches([]byte(body), now)
	if !ok || len(items) != 1 || received != 2 || skipped != 2 {
		t.Fatalf("items=%d received=%d skipped=%d ok=%v", len(items), received, skipped, ok)
	}
	if items[0].Title != "Careers360 data breach: 3,609,421 accounts" || items[0].CanonicalURL != "https://haveibeenpwned.com/Breach/Careers360" {
		t.Fatalf("unexpected item %+v", items[0])
	}
}

func TestRunCollectsHackerNewsSecurityTitlesOnly(t *testing.T) {
	source := testSource("hn")
	source.Format = FormatHackerNews
	source.Address = "https://hacker-news.firebaseio.com/v0/topstories.json"
	store := &memoryStore{sources: []Source{source}}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/v0/topstories.json":
			return jsonResponse(`[1,2,3,4]`), nil
		case "/v0/item/1.json":
			return jsonResponse(`{"id":1,"type":"story","title":"Ransomware hits <b>hospital</b>","url":"https://example.org/a","time":1790000000}`), nil
		case "/v0/item/2.json":
			return jsonResponse(`{"id":2,"type":"story","title":"A new text editor","url":"https://example.org/b"}`), nil
		case "/v0/item/3.json":
			return jsonResponse(`{"id":3,"type":"story","title":"Ask HN: zero-day in my router?"}`), nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: http.NoBody}, nil
	})}
	collector, _ := NewCollector(client, store)
	if _, err := collector.Run(context.Background()); err != nil {
		t.Fatalf("err=%v", err)
	}
	items := store.completed
	if len(items) != 1 || items[0].Title != "Ransomware hits hospital" || items[0].CanonicalURL != "https://example.org/a" {
		t.Fatalf("unexpected items %+v", items)
	}
}
