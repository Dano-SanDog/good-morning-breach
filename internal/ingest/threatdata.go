package ingest

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	nvdLookback        = 72 * time.Hour
	hibpLookback       = 30 * 24 * time.Hour
	hackerNewsTopCount = 100
	hackerNewsWorkers  = 16
	hackerNewsSuffix   = "/topstories.json"
	nvdTimeLayout      = "2006-01-02T15:04:05.000"
)

var (
	hibpNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	// Hacker News is general-interest, so only security-related titles are kept.
	hackerNewsSecurityPattern = regexp.MustCompile(`(?i)\b(cve-\d{4}-\d{4,}|vulnerabilit\w*|exploit\w*|ransomware|malware|data breach|breached|zero-?day|0-day|phishing|botnet|backdoor\w*|supply[- ]chain attack|cyber-?attack\w*|cybersecurity|infosec|ddos|spyware|infostealer|security (flaw|hole|bug|incident|advisory|patch)|hacked|hackers?|rce)\b`)
)

// nvdRequestURL asks only for recent critical (CVSS v3) CVEs, which keeps the
// feed small enough for the unauthenticated NVD rate limit.
func nvdRequestURL(base string, now time.Time) string {
	end := now.UTC()
	start := end.Add(-nvdLookback)
	query := url.Values{}
	query.Set("cvssV3Severity", "CRITICAL")
	query.Set("pubStartDate", start.Format(nvdTimeLayout)+"+00:00")
	query.Set("pubEndDate", end.Format(nvdTimeLayout)+"+00:00")
	separator := "?"
	if strings.Contains(base, "?") {
		separator = "&"
	}
	return base + separator + query.Encode()
}

func parseNVD(body []byte) (items []Item, received, skipped int, ok bool) {
	var document struct {
		TotalResults    *int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if !decodeStrict(body, &document) || document.TotalResults == nil {
		return nil, 0, 0, false
	}
	received = len(document.Vulnerabilities)
	seen := map[string]struct{}{}
	for _, entry := range document.Vulnerabilities {
		description := ""
		for _, d := range entry.CVE.Descriptions {
			if d.Lang == "en" {
				description = d.Value
				break
			}
		}
		if !cveIDPattern.MatchString(entry.CVE.ID) {
			skipped++
			continue
		}
		title := normalizeTitle(entry.CVE.ID + ": " + description)
		if description == "" {
			title = entry.CVE.ID
		}
		link := "https://nvd.nist.gov/vuln/detail/" + entry.CVE.ID
		if _, dup := seen[link]; dup {
			skipped++
			continue
		}
		seen[link] = struct{}{}
		item := Item{Title: title, CanonicalURL: link}
		if published, err := time.Parse(nvdTimeLayout, entry.CVE.Published); err == nil {
			published = published.UTC()
			item.PublishedAt = &published
		}
		items = append(items, item)
	}
	return items, received, skipped, true
}

func parseHIBPBreaches(body []byte, now time.Time) (items []Item, received, skipped int, ok bool) {
	var breaches []struct {
		Name         string `json:"Name"`
		Title        string `json:"Title"`
		AddedDate    string `json:"AddedDate"`
		PwnCount     int64  `json:"PwnCount"`
		IsFabricated bool   `json:"IsFabricated"`
		IsSpamList   bool   `json:"IsSpamList"`
	}
	if !decodeStrict(body, &breaches) || len(breaches) == 0 {
		return nil, 0, 0, false
	}
	cutoff := now.UTC().Add(-hibpLookback)
	seen := map[string]struct{}{}
	for _, breach := range breaches {
		added, err := time.Parse(time.RFC3339, breach.AddedDate)
		if err != nil || !hibpNamePattern.MatchString(breach.Name) {
			skipped++
			continue
		}
		if added.Before(cutoff) {
			continue
		}
		received++
		name := normalizeTitle(breach.Title)
		link := "https://haveibeenpwned.com/Breach/" + breach.Name
		if breach.IsFabricated || breach.IsSpamList || name == "" {
			skipped++
			continue
		}
		if _, dup := seen[link]; dup {
			skipped++
			continue
		}
		seen[link] = struct{}{}
		title := name + " data breach"
		if breach.PwnCount > 0 {
			title += ": " + groupDigits(breach.PwnCount) + " accounts"
		}
		published := added.UTC()
		items = append(items, Item{Title: normalizeTitle(title), CanonicalURL: link, PublishedAt: &published})
	}
	return items, received, skipped, true
}

func groupDigits(n int64) string {
	digits := strconv.FormatInt(n, 10)
	var out strings.Builder
	for i, d := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteRune(d)
	}
	return out.String()
}

type hackerNewsItem struct {
	ID      int64  `json:"id"`
	Type    string `json:"type"`
	Title   string `json:"title"`
	URL     string `json:"url"`
	Time    int64  `json:"time"`
	Dead    bool   `json:"dead"`
	Deleted bool   `json:"deleted"`
}

func (c *Collector) collectHackerNews(ctx context.Context, source Source) (items []Item, received, skipped int, failure string) {
	if !strings.HasSuffix(source.Address, hackerNewsSuffix) {
		return nil, 0, 0, "source configuration is invalid"
	}
	body, failure := c.fetchURL(ctx, source.Address, "application/json", "json")
	if failure != "" {
		return nil, 0, 0, failure
	}
	var ids []int64
	if !decodeStrict(body, &ids) || len(ids) == 0 {
		return nil, 0, 0, "feed document is invalid"
	}
	if len(ids) > hackerNewsTopCount {
		ids = ids[:hackerNewsTopCount]
	}
	base := strings.TrimSuffix(source.Address, hackerNewsSuffix)

	fetched := make([]*hackerNewsItem, len(ids))
	jobs := make(chan int, len(ids))
	for i := range ids {
		jobs <- i
	}
	close(jobs)
	var wg sync.WaitGroup
	for w := 0; w < hackerNewsWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil || ids[i] <= 0 {
					continue
				}
				data, failure := c.fetchURL(ctx, fmt.Sprintf("%s/item/%d.json", base, ids[i]), "application/json", "json")
				var item hackerNewsItem
				if failure == "" && decodeStrict(data, &item) && item.ID == ids[i] {
					fetched[i] = &item
				}
			}
		}()
	}
	wg.Wait()
	received = len(ids)
	valid := 0
	seen := map[string]struct{}{}
	for _, entry := range fetched {
		if entry == nil {
			skipped++
			continue
		}
		valid++
		title := normalizeTitle(entry.Title)
		link := normalizeLink(entry.URL)
		if entry.Type != "story" || entry.Dead || entry.Deleted || title == "" || link == "" ||
			!hackerNewsSecurityPattern.MatchString(title) {
			skipped++
			continue
		}
		if _, dup := seen[link]; dup {
			skipped++
			continue
		}
		seen[link] = struct{}{}
		item := Item{Title: title, CanonicalURL: link}
		if entry.Time > 0 {
			published := time.Unix(entry.Time, 0).UTC()
			item.PublishedAt = &published
		}
		items = append(items, item)
	}
	if valid == 0 {
		return nil, 0, 0, "feed document is invalid"
	}
	return items, received, skipped, ""
}
