package alerting

import (
	"strings"
	"testing"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/contentrights"
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

// Until a summary or excerpt is rendered through the gate (SC-023), no output
// may carry them, even if a Story somehow holds them.
func TestOutputsNeverEmitExcerptOrSummary(t *testing.T) {
	story := Story{Content: contentrights.Content{Title: "T", URL: "https://example.org/a", Excerpt: "SECRET-EXCERPT", Summary: "SECRET-SUMMARY"},
		Sources: []string{"Example"}, Risk: "High", Categories: []string{"Malware"}}
	settings := Settings{TimeZone: "UTC", MinimumRisk: "Medium"}
	msg, err := Render([]Story{story}, settings, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	slack, err := RenderSlack([]Story{story}, settings, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	all := msg.HTML + msg.Text + slack
	if strings.Contains(all, "SECRET-") {
		t.Fatal("rendered output contains ungated content")
	}
}

func TestEmailCarriesInlineLogo(t *testing.T) {
	message := Message{Subject: "s", Text: "plain", HTML: `<img src="cid:` + logoCID + `">`, LogoPNG: logoEmailPNG}
	raw, err := buildMessage("a@example.org", "b@example.org", message, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{"multipart/related", "Content-Id: <" + logoCID + ">", "image/png", "cid:" + logoCID} {
		if !strings.Contains(strings.ToLower(got), strings.ToLower(want)) {
			t.Errorf("message missing %q", want)
		}
	}
	if len(logoEmailPNG) == 0 || len(logoEmailPNG) > 60*1024 {
		t.Errorf("logo size %d out of range", len(logoEmailPNG))
	}
	rendered, err := Render(nil, Settings{TimeZone: "UTC", MinimumRisk: "Medium"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.HTML, "cid:"+logoCID) || strings.Contains(rendered.Text, "cid:") || len(rendered.LogoPNG) == 0 {
		t.Error("rendered alert must reference the inline logo only in HTML")
	}
}

func TestSlackPayloadStartsWithLogoImageBlock(t *testing.T) {
	payload := slackPayload("*Good Morning Breach*: one\n" + strings.Repeat("line of text\n", 400))
	if payload.Blocks[0].Type != "image" || payload.Blocks[0].ImageURL != SlackLogoURL || payload.Blocks[0].AltText == "" {
		t.Fatalf("first block = %+v", payload.Blocks[0])
	}
	if len(payload.Blocks) < 3 {
		t.Fatalf("long text should split into sections, got %d blocks", len(payload.Blocks))
	}
	for _, block := range payload.Blocks[1:] {
		if block.Type != "section" || len(block.Text.Text) > 3000 {
			t.Fatalf("bad section block %+v", block)
		}
	}
}

func TestEveryAlertCarriesSourceNotices(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	settings := Settings{TimeZone: "UTC", MinimumRisk: "Low"}
	story := Story{Title: "A", URL: "https://example.org/a", Sources: []string{"X"}, Risk: "Low", Sentiment: "Neutral"}
	for _, stories := range [][]Story{nil, {story}} {
		message, err := Render(stories, settings, now)
		if err != nil {
			t.Fatal(err)
		}
		slack, err := RenderSlack(stories, settings, now)
		if err != nil {
			t.Fatal(err)
		}
		for name, got := range map[string]string{"text": message.Text, "html": message.HTML, "slack": slack} {
			for _, want := range []string{"haveibeenpwned.com", "CC BY-NC-SA 4.0"} {
				if !strings.Contains(got, want) {
					t.Fatalf("%s alert with %d stories missing %q", name, len(stories), want)
				}
			}
		}
	}
}
