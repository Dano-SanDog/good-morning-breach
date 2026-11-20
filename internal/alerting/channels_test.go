package alerting

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
	good := &recordingChannel{name: ChannelSMS, max: 3}
	service, _ := NewService(store, bad, good)
	if err := service.RunOnce(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if store.failures[ChannelSlack] != 1 || store.successes[ChannelSMS] != 1 || good.n != 1 {
		t.Fatalf("failures %v successes %v", store.failures, store.successes)
	}
	if store.causes[0] != "Slack returned HTTP 500" {
		t.Fatalf("cause = %q", store.causes[0])
	}
	if len(store.limits) != 2 || store.limits[0] != 10 || store.limits[1] != 3 {
		t.Fatalf("limits = %v", store.limits)
	}
}

func TestRenderSMS(t *testing.T) {
	stories := []Story{
		{Title: "Alpha <b>é</b>", Risk: "Critical"}, {Title: strings.Repeat("x", 200), Risk: "High"},
		{Title: "Gamma", Risk: "High"}, {Title: "Delta", Risk: "Medium"},
	}
	text := RenderSMS(stories, Settings{MinimumRisk: "Medium"})
	if strings.Count(text, "[") != 3 || strings.Contains(text, "Delta") || !strings.Contains(text, "and more") ||
		!strings.HasSuffix(text, DashboardURL) {
		t.Fatalf("text = %q", text)
	}
	for _, r := range text {
		if r > 0x7e {
			t.Fatalf("non-ASCII %q in %q", r, text)
		}
	}
	if len(text) > 320 {
		t.Fatalf("text too long: %d", len(text))
	}
	if got := RenderSMS(nil, Settings{MinimumRisk: "High"}); !strings.Contains(got, "no new stories at or above High") {
		t.Fatalf("empty = %q", got)
	}
}

func TestValidPhone(t *testing.T) {
	for _, bad := range []string{"5551234", "+0123", "+1 555 123", "+15551234567890123", "", "+1555\n"} {
		if ValidPhone(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	if !ValidPhone("+15551234567") {
		t.Fatal("rejected valid number")
	}
}

func writeTwilioSecret(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "twilio")
	if err := os.WriteFile(path, []byte("secretvalue\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func setTwilioEnv(t *testing.T, secretPath string) {
	t.Setenv("GB_TWILIO_ACCOUNT_SID", "AC"+strings.Repeat("a", 32))
	t.Setenv("GB_TWILIO_API_KEY_SID", "SK"+strings.Repeat("b", 32))
	t.Setenv("GB_TWILIO_API_KEY_SECRET_FILE", secretPath)
	t.Setenv("GB_TWILIO_FROM", "+15550001111")
}

func TestLoadTwilioConfig(t *testing.T) {
	t.Setenv("GB_TWILIO_ACCOUNT_SID", "")
	if _, ok, err := LoadTwilioConfig(); ok || err != nil {
		t.Fatalf("unset: %v %v", ok, err)
	}
	setTwilioEnv(t, writeTwilioSecret(t, 0o600))
	config, ok, err := LoadTwilioConfig()
	if err != nil || !ok || config.APIKeySecret != "secretvalue" || config.DailyCap != DefaultSMSDailyCap {
		t.Fatalf("config = %+v %v %v", config, ok, err)
	}
	if strings.Contains(config.String(), "secretvalue") {
		t.Fatal("secret in String")
	}

	setTwilioEnv(t, writeTwilioSecret(t, 0o644))
	if _, _, err := LoadTwilioConfig(); err == nil {
		t.Fatal("group-readable secret accepted")
	}
	setTwilioEnv(t, writeTwilioSecret(t, 0o600))
	t.Setenv("GB_TWILIO_API_KEY_SID", "AC"+strings.Repeat("b", 32))
	if _, _, err := LoadTwilioConfig(); err == nil {
		t.Fatal("non-API-key SID accepted")
	}
}

type fakeSMSSupport struct {
	allow    bool
	disabled bool
	quotas   []Quota
}

func (f *fakeSMSSupport) ReserveMessage(_ context.Context, _ int64, q Quota, _ time.Time) (bool, error) {
	f.quotas = append(f.quotas, q)
	return f.allow, nil
}
func (f *fakeSMSSupport) DisableSMS(context.Context, int64) error { f.disabled = true; return nil }

func twilioFixture(t *testing.T, status int, response string, form *url.Values, auth *[2]string) *TwilioClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		*form = r.PostForm
		auth[0], auth[1], _ = r.BasicAuth()
		w.WriteHeader(status)
		io.WriteString(w, response)
	}))
	t.Cleanup(server.Close)
	client, err := NewTwilioClient(TwilioConfig{AccountSID: "AC" + strings.Repeat("a", 32),
		APIKeySID: "SK" + strings.Repeat("b", 32), APIKeySecret: "secretvalue", From: "+15550001111"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.baseURL = server.URL
	return client
}

func TestSMSChannelDeliver(t *testing.T) {
	var form url.Values
	var auth [2]string
	client := twilioFixture(t, 201, `{"sid":"SM1"}`, &form, &auth)
	support := &fakeSMSSupport{allow: true}
	channel := NewSMSChannel(client, support)
	recipient := Recipient{AccountID: 1, Settings: Settings{MinimumRisk: "Medium"},
		Contacts: Contacts{SMSEnabled: true, PhoneVerified: true, Phone: "+15551234567"}}
	if !channel.Enabled(recipient) {
		t.Fatal("not enabled")
	}
	recipient.Contacts.PhoneVerified = false
	if channel.Enabled(recipient) {
		t.Fatal("enabled for unverified number")
	}
	recipient.Contacts.PhoneVerified = true
	if err := channel.Deliver(context.Background(), recipient, []Story{{Title: "T", Risk: "High"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if form.Get("To") != "+15551234567" || form.Get("From") != "+15550001111" || !strings.Contains(form.Get("Body"), "[High] T") {
		t.Fatalf("form = %v", form)
	}
	if auth[0] != "SK"+strings.Repeat("b", 32) || auth[1] != "secretvalue" {
		t.Fatalf("auth = %v", auth)
	}
	if support.quotas[0].GlobalDaily != DefaultSMSDailyCap {
		t.Fatalf("quota = %+v", support.quotas[0])
	}

	support.allow = false
	err := channel.Deliver(context.Background(), recipient, nil, time.Now())
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestSMSOptOutDisablesChannel(t *testing.T) {
	var form url.Values
	var auth [2]string
	client := twilioFixture(t, 400, `{"code":21610,"message":"unsubscribed"}`, &form, &auth)
	support := &fakeSMSSupport{allow: true}
	channel := NewSMSChannel(client, support)
	recipient := Recipient{AccountID: 1, Contacts: Contacts{SMSEnabled: true, PhoneVerified: true, Phone: "+15551234567"}}
	err := channel.Deliver(context.Background(), recipient, nil, time.Now())
	if !errors.Is(err, ErrSMSOptedOut) || !support.disabled {
		t.Fatalf("err = %v disabled = %v", err, support.disabled)
	}
	if strings.Contains(err.Error(), "+1555") || strings.Contains(err.Error(), "secretvalue") {
		t.Fatalf("error leaks data: %v", err)
	}
}

type fakeContactStore struct {
	fakeSMSSupport
	record  ContactRecord
	verif   Verification
	hasV    bool
	sealed  []byte
	failed  int
	channel [3]bool
}

func (f *fakeContactStore) GetContacts(context.Context, int64) (ContactRecord, error) {
	r := f.record
	r.SlackWebhookSealed = f.sealed
	return r, nil
}
func (f *fakeContactStore) SaveChannels(_ context.Context, _ int64, e, s, m bool) error {
	f.channel = [3]bool{e, s, m}
	return nil
}
func (f *fakeContactStore) SaveSlackWebhook(_ context.Context, _ int64, sealed []byte) error {
	f.sealed = sealed
	return nil
}
func (f *fakeContactStore) StartPhoneVerification(_ context.Context, _ int64, phone string, hash []byte, exp, _ time.Time) error {
	f.verif = Verification{Phone: phone, CodeHash: hash, ExpiresAt: exp}
	f.hasV = true
	return nil
}
func (f *fakeContactStore) ConsumeVerificationAttempt(_ context.Context, _ int64, max int, now time.Time) (Verification, bool, error) {
	if !f.hasV || f.failed >= max || !now.Before(f.verif.ExpiresAt) {
		return Verification{}, false, nil
	}
	f.failed++
	return f.verif, true, nil
}
func (f *fakeContactStore) ConfirmPhone(_ context.Context, _ int64, phone string, _ time.Time) error {
	f.record.Phone, f.record.PhoneVerified = phone, true
	f.hasV = false
	return nil
}

func TestPhoneVerificationFlow(t *testing.T) {
	var form url.Values
	var auth [2]string
	twilio := twilioFixture(t, 201, `{}`, &form, &auth)
	store := &fakeContactStore{fakeSMSSupport: fakeSMSSupport{allow: true}}
	var slackBody string
	slack, _ := slackFixture(t, 200, &slackBody)
	box := testBox(t)
	service, err := NewContactService(store, box, slack, twilio)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 17, 7, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	ctx := context.Background()

	if err := service.StartPhoneVerification(ctx, 1, "555-1234"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid number: %v", err)
	}
	if err := service.StartPhoneVerification(ctx, 1, "+15551234567"); err != nil {
		t.Fatal(err)
	}
	body := form.Get("Body")
	code := body[strings.Index(body, ": ")+2:][:6]
	if !strings.Contains(body, "STOP") {
		t.Fatalf("body = %q", body)
	}
	if strings.Contains(string(store.verif.CodeHash), code) {
		t.Fatal("code stored in clear")
	}

	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	if err := service.VerifyPhone(ctx, 1, wrong); !errors.Is(err, ErrCodeRejected) {
		t.Fatalf("wrong code: %v", err)
	}
	if err := service.VerifyPhone(ctx, 1, code); err != nil || !store.record.PhoneVerified {
		t.Fatalf("correct code: %v", err)
	}

	// Expiry.
	_ = service.StartPhoneVerification(ctx, 1, "+15551234567")
	body = form.Get("Body")
	code = body[strings.Index(body, ": ")+2:][:6]
	now = now.Add(11 * time.Minute)
	if err := service.VerifyPhone(ctx, 1, code); !errors.Is(err, ErrCodeRejected) {
		t.Fatalf("expired code accepted: %v", err)
	}

	// Five wrong entries invalidate the code, even the right one.
	now = now.Add(time.Minute)
	_ = service.StartPhoneVerification(ctx, 1, "+15551234567")
	body = form.Get("Body")
	code = body[strings.Index(body, ": ")+2:][:6]
	store.failed = 0
	store.record.PhoneVerified = false
	for i := 0; i < maxCodeAttempts; i++ {
		_ = service.VerifyPhone(ctx, 1, wrong)
	}
	if err := service.VerifyPhone(ctx, 1, code); !errors.Is(err, ErrCodeRejected) || store.record.PhoneVerified {
		t.Fatalf("code accepted after 5 wrong entries: %v", err)
	}

	store.allow = false
	if err := service.StartPhoneVerification(ctx, 1, "+15551234567"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("rate limit: %v", err)
	}
}

func TestContactServiceRules(t *testing.T) {
	var slackBody string
	slack, box := slackFixture(t, 200, &slackBody)
	store := &fakeContactStore{fakeSMSSupport: fakeSMSSupport{allow: true}, record: ContactRecord{EmailEnabled: true}}
	service, _ := NewContactService(store, box, slack, nil)
	ctx := context.Background()

	if err := service.SaveChannels(ctx, 1, false, false, false); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("all channels off accepted")
	}
	if err := service.SaveChannels(ctx, 1, true, true, false); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("Slack enabled without a webhook")
	}
	if err := service.SaveChannels(ctx, 1, true, false, true); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("text enabled without a verified number")
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
	if !view.SlackWebhookSaved || view.SMSAvailable {
		t.Fatalf("view = %+v", view)
	}
	if err := service.StartPhoneVerification(ctx, 1, "+15551234567"); !errors.Is(err, ErrSMSUnavailable) {
		t.Fatalf("SMS without Twilio: %v", err)
	}

	store.allow = false
	if _, err := service.SaveSlackWebhook(ctx, 1, testWebhook); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("test rate limit: %v", err)
	}
}

func TestMaskPhoneAndConfigLogging(t *testing.T) {
	if got := maskPhone("+15551234567"); strings.Contains(got, "5551234") || !strings.HasSuffix(got, "4567") {
		t.Fatalf("mask = %q", got)
	}
	config := TwilioConfig{AccountSID: "AC1", APIKeySecret: "topsecret", From: "+15550001111"}
	if strings.Contains(slog.AnyValue(config).Resolve().String(), "topsecret") {
		t.Fatal("secret logged")
	}
}
