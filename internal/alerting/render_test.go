package alerting

import (
	"strings"
	"testing"
	"time"
)

func TestRenderCVEsRelatedAndAttribution(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	story := Story{
		Title: "Exploit for CVE-2026-1234", URL: "https://example.org/a", Sources: []string{"Have I Been Pwned"},
		Attributions: []string{"Source: Have I Been Pwned (https://haveibeenpwned.com), CC BY 4.0."},
		Categories:   []string{"Data Breach"}, Risk: "Critical", Sentiment: "Negative",
		CVEs:    []string{"CVE-2026-1234", `CVE-<b>`},
		Related: []RelatedStory{{Title: "Other <i>report</i>", URL: "https://example.net/b", CVE: "CVE-2026-1234"}},
	}
	message, err := Render([]Story{story}, Settings{TimeZone: "UTC", MinimumRisk: "Low"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CVE: CVE-2026-1234", "Other", "https://example.net/b", "haveibeenpwned.com"} {
		if !strings.Contains(message.Text, want) || !strings.Contains(message.HTML, strings.ReplaceAll(want, "CVE: ", "CVE: ")) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(message.HTML, "<i>") || strings.Contains(message.HTML, "CVE-<b>") || strings.Contains(message.Text, "CVE-<b>") {
		t.Fatal("untrusted text was not escaped or validated")
	}
	if strings.Contains(message.Text, "MITRE") || strings.Contains(message.HTML, "MITRE") {
		t.Fatal("MITRE notice shown without ATT&CK tags")
	}
}

func TestRenderUnsafeLinksAndControlCharacters(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for _, link := range []string{"javascript:alert(1)", "http://example.org/a", "https://user:pw@example.org/", "//example.org", "https://example.org/a b", ""} {
		story := Story{Title: "Title\r\nBcc: x@example.org", URL: link, Risk: "High", Sentiment: "Neutral",
			Sources: []string{"S"}, Categories: []string{"Other"},
			Techniques: []Technique{{ID: "T1190", Name: "N", URL: "http://attack.mitre.org/techniques/T1190/"}}}
		message, err := Render([]Story{story}, Settings{TimeZone: "UTC", MinimumRisk: "Low"}, now)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(message.HTML, "<a ") || strings.Contains(message.HTML, "href") {
			t.Fatalf("link %q rendered as an anchor: %s", link, message.HTML)
		}
		if strings.ContainsAny(message.Subject, "\r\n") || strings.Contains(message.Text, "\r") {
			t.Fatalf("control characters survived for %q", link)
		}
		if strings.Contains(message.Text, "javascript:") || strings.Contains(message.Text, "http://") {
			t.Fatalf("unsafe link in text part for %q", link)
		}
	}
}
