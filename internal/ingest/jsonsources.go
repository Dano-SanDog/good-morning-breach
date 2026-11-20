package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const kevCatalogURL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

const kevLookback = 30 * 24 * time.Hour

var (
	cveIDPattern  = regexp.MustCompile(`^CVE-\d{4}-\d{4,19}$`)
	ghsaIDPattern = regexp.MustCompile(`^GHSA(-[2-9cfghjmpqrvwx]{4}){3}$`)
)

func decodeStrict(body []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(target) != nil {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func parseCISAKEV(body []byte, now time.Time) (items []Item, received, skipped int, ok bool) {
	var catalog struct {
		Vulnerabilities []struct {
			CVEID             string `json:"cveID"`
			VendorProject     string `json:"vendorProject"`
			Product           string `json:"product"`
			VulnerabilityName string `json:"vulnerabilityName"`
			DateAdded         string `json:"dateAdded"`
		} `json:"vulnerabilities"`
	}
	if !decodeStrict(body, &catalog) || len(catalog.Vulnerabilities) == 0 {
		return nil, 0, 0, false
	}
	cutoff := now.UTC().Add(-kevLookback)
	seen := map[string]struct{}{}
	for _, entry := range catalog.Vulnerabilities {
		added, err := time.Parse("2006-01-02", entry.DateAdded)
		if err != nil || !cveIDPattern.MatchString(entry.CVEID) {
			skipped++
			continue
		}
		if added.Before(cutoff) {
			continue
		}
		received++
		title := normalizeTitle(fmt.Sprintf("%s: %s %s - %s", entry.CVEID, entry.VendorProject, entry.Product, entry.VulnerabilityName))
		link := normalizeLink(kevCatalogURL + "?search_api_fulltext=" + entry.CVEID)
		if _, dup := seen[link]; dup || title == "" || link == "" {
			skipped++
			continue
		}
		seen[link] = struct{}{}
		publishedAt := added
		items = append(items, Item{Title: title, CanonicalURL: link, PublishedAt: &publishedAt})
	}
	return items, received, skipped, true
}

func parseGitHubAdvisories(body []byte) (items []Item, received, skipped int, ok bool) {
	var advisories []struct {
		GHSAID      string `json:"ghsa_id"`
		Summary     string `json:"summary"`
		PublishedAt string `json:"published_at"`
	}
	if !decodeStrict(body, &advisories) || len(advisories) == 0 {
		return nil, 0, 0, false
	}
	received = len(advisories)
	seen := map[string]struct{}{}
	for _, advisory := range advisories {
		title := normalizeTitle(advisory.Summary)
		// The link is rebuilt from the validated GHSA ID, not taken from the response.
		if !ghsaIDPattern.MatchString(advisory.GHSAID) || title == "" {
			skipped++
			continue
		}
		link := "https://github.com/advisories/" + advisory.GHSAID
		if _, dup := seen[link]; dup {
			skipped++
			continue
		}
		seen[link] = struct{}{}
		item := Item{Title: strings.TrimSpace(title), CanonicalURL: link}
		if published, err := time.Parse(time.RFC3339, advisory.PublishedAt); err == nil {
			published = published.UTC()
			item.PublishedAt = &published
		}
		items = append(items, item)
	}
	return items, received, skipped, true
}
