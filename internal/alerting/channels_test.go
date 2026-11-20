package alerting

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/secrets"
)

const testWebhook = "https://hooks.slack.com/services/T000/B000/SECRETVALUE"

func testBox(t *testing.T) *secrets.Box {
	t.Helper()
	box, err := secrets.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func TestValidateSlackWebhook(t *testing.T) {
	for _, bad := range []string{
		"https://hooks.slack.com.evil.example/services/x",
		"http://hooks.slack.com/services/x",
		"https://hooks.slack.com@10.0.0.1/services/x",
		"https://hooks.slack.com:8443/services/x",
		"https://hooks.slack.com/services/x?a=b",
		"https://hooks.slack.com/services/x#f",
		"https://hooks.slack.com/other/x",
		"https://hooks.slack.com/services/",
		"https://hooks.slack.com/services/a b",
		"",
	} {
		if _, err := ValidateSlackWebhook(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := ValidateSlackWebhook(testWebhook); err != nil {
		t.Fatal(err)
	}
}

func TestSlackEscapesStoryText(t *testing.T) {
	story := Story{Title: "<!channel> <https://evil|x> & more", URL: "https://example.org/a?x=1&y=<2>|z",
		Sources: []string{"CERT-EU"}, Risk: "High", Categories: []string{"Malware"}}
	text, err := RenderSlack([]Story{story}, Settings{TimeZone: "UTC", MinimumRisk: "Medium"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "<!channel>") || strings.Contains(text, "<https://evil|x>") {
		t.Fatalf("control text not escaped: %s", text)
	}
	if !strings.Contains(text, "&lt;!channel&gt;") || !strings.Contains(text, "&amp; more") {
		t.Fatalf("missing escaped title: %s", text)
	}
	if !strings.Contains(text, "<https://example.org/a?x=1%26y=%3C2%3E%7Cz|") {
		t.Fatalf("link not encoded: %s", text)
	}
}

func slackFixture(t *testing.T, status int, got *string) (*SlackChannel, *secrets.Box) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*got = string(body)
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	box := testBox(t)
	channel := NewSlackChannel(server.Client(), box)
	channel.target = func(string) string { return server.URL }
	return channel, box
}

func TestSlackDeliverAndErrorsNeverLeakWebhook(t *testing.T) {
	var got string
	channel, box := slackFixture(t, http.StatusOK, &got)
	sealed, _ := box.Seal(slackPurpose, 7, []byte(testWebhook))
	recipient := Recipient{AccountID: 7, Contacts: Contacts{SlackEnabled: true, SlackWebhookSealed: sealed},
		Settings: Settings{TimeZone: "UTC", MinimumRisk: "Medium"}}
	if !channel.Enabled(recipient) {
		t.Fatal("channel not enabled")
	}
	if err := channel.Deliver(context.Background(), recipient, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "no new stories") {
		t.Fatalf("payload = %s", got)
	}
	// A sealed value moved to another account cannot be opened.
	recipient.AccountID = 8
	if err := channel.Deliver(context.Background(), recipient, nil, time.Now()); err == nil {
		t.Fatal("webhook opened for another account")
	}

	// Connection failures must not expose the webhook address.
	dead := NewSlackChannel(&http.Client{Timeout: time.Second}, box)
	dead.target = func(string) string { return "http://127.0.0.1:1/" + "SECRETVALUE" }
	err := dead.SendTest(context.Background(), testWebhook)
	if err == nil || strings.Contains(err.Error(), "SECRETVALUE") {
		t.Fatalf("err = %v", err)
	}
	var d *DeliveryError
	if errors.As(err, &d) && strings.Contains(d.Err.Error(), "SECRETVALUE") {
		t.Fatal("wrapped error leaks the webhook")
	}
}

func TestSlackRejectedWebhookCause(t *testing.T) {
	var got string
	channel, _ := slackFixture(t, http.StatusNotFound, &got)
	err := channel.SendTest(context.Background(), testWebhook)
	if err == nil || !strings.Contains(err.Error(), "replace it") {
		t.Fatalf("err = %v", err)
	}
}

type recordingChannel struct {
	name string
	err  error
	n    int
	max  int
}

func (c *recordingChannel) Name() string           { return c.name }
func (c *recordingChannel) Enabled(Recipient) bool { return true }
func (c *recordingChannel) StoryLimit() int        { return c.max }
func (c *recordingChannel) Deliver(context.Context, Recipient, []Story, time.Time) error {
	c.n++
	return c.err
}

func TestChannelFailureDoesNotStopOthers(t *testing.T) {
	now := time.Date(2026, 11, 17, 7, 1, 0, 0, time.UTC)
	store := &fakeStore{recipients: []Recipient{emailRecipient()}}
	bad := &recordingChannel{name: ChannelSlack, err: &DeliveryError{Cause: "Slack returned HTTP 500"}, max: 10}
	good := &recordingChannel{name: ChannelEmail, max: 3}
	service, _ := NewService(store, bad, good)
	if err := service.RunOnce(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if store.failures[ChannelSlack] != 1 || store.successes[ChannelEmail] != 1 || good.n != 1 {
		t.Fatalf("failures %v successes %v", store.failures, store.successes)
	}
	if store.causes[0] != "Slack returned HTTP 500" {
		t.Fatalf("cause = %q", store.causes[0])
	}
	if len(store.limits) != 2 || store.limits[0] != 10 || store.limits[1] != 3 {
		t.Fatalf("limits = %v", store.limits)
	}
}

type fakeContactStore struct {
	allow   bool
	record  ContactRecord
	sealed  []byte
	channel [2]bool
}

func (f *fakeContactStore) ReserveMessage(context.Context, int64, Quota, time.Time) (bool, error) {
	return f.allow, nil
}

func (f *fakeContactStore) GetContacts(context.Context, int64) (ContactRecord, error) {
	r := f.record
	r.SlackWebhookSealed = f.sealed
	return r, nil
}
func (f *fakeContactStore) SaveChannels(_ context.Context, _ int64, e, s bool) error {
	f.channel = [2]bool{e, s}
	return nil
}
func (f *fakeContactStore) SaveSlackWebhook(_ context.Context, _ int64, sealed []byte) error {
	f.sealed = sealed
	return nil
}

func TestContactServiceRules(t *testing.T) {
	var slackBody string
	slack, box := slackFixture(t, 200, &slackBody)
	store := &fakeContactStore{allow: true, record: ContactRecord{EmailEnabled: true}}
	service, _ := NewContactService(store, box, slack)
	ctx := context.Background()

	if err := service.SaveChannels(ctx, 1, false, false); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("all channels off accepted")
	}
	if err := service.SaveChannels(ctx, 1, true, true); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("Slack enabled without a webhook")
	}
	if _, err := service.SaveSlackWebhook(ctx, 1, "https://example.org/services/x"); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("foreign webhook accepted")
	}
	result, err := service.SaveSlackWebhook(ctx, 1, testWebhook)
	if err != nil || !result.Saved || result.TestFailed {
		t.Fatalf("save: %+v %v", result, err)
	}
	if strings.Contains(string(store.sealed), "SECRETVALUE") {
		t.Fatal("webhook stored in clear")
	}
	view, _ := service.View(ctx, 1)
	if !view.SlackWebhookSaved {
		t.Fatalf("view = %+v", view)
	}

	store.allow = false
	if _, err := service.SaveSlackWebhook(ctx, 1, testWebhook); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("test rate limit: %v", err)
	}
}
