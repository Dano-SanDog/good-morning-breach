package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const slackPurpose = "slack_webhook"

var ErrInvalidWebhook = errors.New("not a Slack incoming webhook address")

// ValidateSlackWebhook accepts only https://hooks.slack.com/services/... with no
// userinfo, port, query, or fragment (SC-013, FR-4.16).
func ValidateSlackWebhook(raw string) (string, error) {
	if len(raw) > 300 || strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return "", ErrInvalidWebhook
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "hooks.slack.com" ||
		parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.ForceQuery || parsed.Opaque != "" ||
		!strings.HasPrefix(parsed.Path, "/services/") || len(parsed.Path) <= len("/services/") ||
		strings.Contains(parsed.Path, "..") || strings.Contains(parsed.Path, "//") {
		return "", ErrInvalidWebhook
	}
	return parsed.String(), nil
}

type Unsealer interface {
	Open(purpose string, accountID int64, sealed []byte) ([]byte, error)
}

// SlackChannel posts the alert to a user-supplied incoming webhook.
type SlackChannel struct {
	client *http.Client
	box    Unsealer
	// target maps the validated webhook address to the address to post to. It is
	// the identity function outside tests.
	target func(string) string
}

func NewSlackChannel(client *http.Client, box Unsealer) *SlackChannel {
	return &SlackChannel{client: client, box: box, target: func(s string) string { return s }}
}

func (*SlackChannel) Name() string    { return ChannelSlack }
func (*SlackChannel) StoryLimit() int { return MaxStories }
func (*SlackChannel) Enabled(r Recipient) bool {
	return r.Contacts.SlackEnabled && len(r.Contacts.SlackWebhookSealed) > 0
}

func (c *SlackChannel) Deliver(ctx context.Context, r Recipient, stories []Story, now time.Time) error {
	raw, err := c.box.Open(slackPurpose, r.AccountID, r.Contacts.SlackWebhookSealed)
	if err != nil {
		return &DeliveryError{Cause: "saved Slack webhook could not be read"}
	}
	text, err := RenderSlack(stories, r.Settings, now)
	if err != nil {
		return err
	}
	return c.post(ctx, string(raw), text)
}

// SendTest posts a short message to confirm the webhook works (FR-4.17).
func (c *SlackChannel) SendTest(ctx context.Context, webhook string) error {
	validated, err := ValidateSlackWebhook(webhook)
	if err != nil {
		return err
	}
	return c.post(ctx, validated, "Good Morning Breach: this is a test message. Your morning alert will arrive in this channel.")
}

func (c *SlackChannel) post(ctx context.Context, webhook, text string) error {
	validated, err := ValidateSlackWebhook(webhook)
	if err != nil {
		return &DeliveryError{Cause: "saved Slack webhook is not valid"}
	}
	body, err := json.Marshal(struct {
		Text string `json:"text"`
	}{text})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.target(validated), bytes.NewReader(body))
	if err != nil {
		return &DeliveryError{Cause: "Slack request could not be built"}
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		// url.Error text contains the webhook address, which is a secret (SC-070).
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return &DeliveryError{Cause: "Slack request failed", Err: err}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	switch {
	case response.StatusCode == http.StatusOK:
		return nil
	case response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone:
		return &DeliveryError{Cause: fmt.Sprintf("Slack rejected the webhook (HTTP %d); replace it", response.StatusCode)}
	default:
		return &DeliveryError{Cause: fmt.Sprintf("Slack returned HTTP %d", response.StatusCode)}
	}
}

// slackText escapes the three characters Slack treats as control characters, so
// collected text cannot mention, link, or notify (SC-034).
func slackText(value string, limit int) string {
	value = plain(value, limit)
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(value)
}

func slackLink(rawURL, label string) string {
	link := safeLink(rawURL)
	if link == "" {
		return label
	}
	link = strings.NewReplacer("|", "%7C", "<", "%3C", ">", "%3E", "&", "%26").Replace(link)
	return "<" + link + "|" + label + ">"
}

// RenderSlack builds the Slack alert text from headlines and links only
// (FR-4.12, FR-8.8).
func RenderSlack(stories []Story, settings Settings, now time.Time) (string, error) {
	location, err := time.LoadLocation(settings.TimeZone)
	if err != nil {
		return "", fmt.Errorf("load alert time zone: %w", err)
	}
	var out strings.Builder
	if len(stories) == 0 {
		out.WriteString("Good Morning Breach: there are no new stories at or above " + slackText(settings.MinimumRisk, 20) + " since your last alert.")
		return out.String(), nil
	}
	noun := "stories"
	if len(stories) == 1 {
		noun = "story"
	}
	fmt.Fprintf(&out, "*Good Morning Breach*: %d new %s at or above %s, highest risk first.\n",
		len(stories), noun, slackText(settings.MinimumRisk, 20))
	anyTechniques := false
	for _, story := range stories {
		fmt.Fprintf(&out, "\n*[%s]* %s\n", slackText(story.Risk, 20), slackLink(story.URL, slackText(story.Title, 300)))
		published := "unknown"
		if story.PublishedAt != nil {
			published = story.PublishedAt.In(location).Format("2 Jan 2006 15:04 MST")
		}
		fmt.Fprintf(&out, "Source: %s. Published: %s. Tone: %s.\nCategories: %s\n",
			slackText(strings.Join(story.Sources, ", "), 200), published, slackText(story.Sentiment, 20),
			slackText(strings.Join(story.Categories, ", "), 200))
		if cves := validCVEs(story.CVEs); len(cves) > 0 {
			out.WriteString("CVE: " + strings.Join(cves, ", ") + "\n")
		}
		var tags []string
		for _, technique := range story.Techniques {
			if len(tags) >= 8 {
				break
			}
			if safeLink(technique.URL) == "" {
				continue
			}
			tags = append(tags, slackLink(technique.URL, slackText(technique.ID+" "+technique.Name, 120)))
		}
		if len(tags) > 0 {
			anyTechniques = true
			out.WriteString("ATT&amp;CK: " + strings.Join(tags, ", ") + "\n")
		}
		for _, attribution := range story.Attributions {
			if cleaned := slackText(attribution, 1000); cleaned != "" {
				out.WriteString(cleaned + "\n")
			}
		}
	}
	if anyTechniques {
		out.WriteString("\nTechnique tags: (c) 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.\n")
	}
	return out.String(), nil
}
