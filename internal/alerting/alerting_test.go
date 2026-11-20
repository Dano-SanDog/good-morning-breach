package alerting

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func tp(t time.Time) *time.Time { return &t }

func TestDue(t *testing.T) {
	la, _ := time.LoadLocation("America/Los_Angeles")
	settings := Settings{Time: "07:00", TimeZone: "America/Los_Angeles", Days: []int16{1, 2, 3, 4, 5}, MinimumRisk: "Medium"}
	tuesday := time.Date(2026, 11, 17, 7, 0, 0, 0, la)

	if _, ok := Due(settings, State{}, tuesday.Add(-time.Minute)); ok {
		t.Fatal("alert due before its time")
	}
	slot, ok := Due(settings, State{}, tuesday.Add(time.Minute))
	if !ok || !slot.Equal(tuesday) {
		t.Fatalf("slot = %v, %v", slot, ok)
	}
	if _, ok := Due(settings, State{LastSentSlotAt: tp(tuesday)}, tuesday.Add(time.Hour)); ok {
		t.Fatal("duplicate alert for a sent slot")
	}
	if _, ok := Due(settings, State{}, tuesday.Add(3*time.Hour)); ok {
		t.Fatal("stale slot was sent")
	}
	saturday := time.Date(2026, 11, 21, 7, 5, 0, 0, la)
	if _, ok := Due(settings, State{}, saturday); ok {
		t.Fatal("alert due on an unselected day")
	}
}

func TestDueRetryLimits(t *testing.T) {
	settings := Settings{Time: "07:00", TimeZone: "UTC", Days: []int16{0, 1, 2, 3, 4, 5, 6}, MinimumRisk: "Low"}
	slot := time.Date(2026, 11, 17, 7, 0, 0, 0, time.UTC)
	state := State{RetrySlotAt: tp(slot), RetryAttempts: 1, LastAttemptAt: tp(slot.Add(time.Minute))}
	if _, ok := Due(settings, state, slot.Add(5*time.Minute)); ok {
		t.Fatal("retry before interval")
	}
	if _, ok := Due(settings, state, slot.Add(12*time.Minute)); !ok {
		t.Fatal("retry not due after interval")
	}
	state.RetryAttempts = 4
	if _, ok := Due(settings, state, slot.Add(90*time.Minute)); ok {
		t.Fatal("retries exceeded the limit")
	}
}

func TestRisksAtOrAbove(t *testing.T) {
	got := strings.Join(RisksAtOrAbove("Medium"), ",")
	if got != "Critical,High,Medium" {
		t.Fatalf("got %s", got)
	}
}

func TestRenderEscapesAndAttributes(t *testing.T) {
	published := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	story := Story{
		Title: `<script>alert(1)</script>`, URL: "https://example.org/a", Sources: []string{"CERT-EU"},
		Attributions: []string{"Source: CERT-EU."}, PublishedAt: &published, Categories: []string{"Malware"},
		Risk: "High", Sentiment: "Negative",
		Techniques: []Technique{{ID: "T1190", Name: "Exploit Public-Facing Application", Tactics: []string{"initial-access"}, URL: "https://attack.mitre.org/techniques/T1190/"}},
	}
	settings := Settings{TimeZone: "UTC", MinimumRisk: "Medium"}
	message, err := Render([]Story{story}, settings, published)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(message.HTML, "<script>") {
		t.Fatal("title was not escaped")
	}
	for _, want := range []string{"https://example.org/a", "CERT-EU", "High", "Negative", "T1190", "Malware"} {
		if !strings.Contains(message.HTML, want) || !strings.Contains(message.Text, want) {
			t.Fatalf("missing %q", want)
		}
	}
	empty, err := Render(nil, settings, published)
	if err != nil || !strings.Contains(empty.Text, "no new stories at or above Medium") {
		t.Fatalf("empty alert: %v %q", err, empty.Text)
	}
}

type fakeStore struct {
	recipients []Recipient
	stories    []Story
	successes  int
	failures   int
	since      time.Time
}

func (f *fakeStore) ListRecipients(context.Context) ([]Recipient, error) { return f.recipients, nil }
func (f *fakeStore) StoriesForAlert(_ context.Context, _ []string, since, _ time.Time, _ int) ([]Story, error) {
	f.since = since
	return f.stories, nil
}
func (f *fakeStore) RecordSuccess(_ context.Context, _ int64, slot, until, _ time.Time, _ int) error {
	f.successes++
	f.recipients[0].State.LastSentSlotAt = &slot
	f.recipients[0].State.LastAlertAt = &until
	return nil
}
func (f *fakeStore) RecordFailure(context.Context, int64, time.Time, time.Time, string) error {
	f.failures++
	return nil
}

type fakeSender struct {
	sent []string
	err  error
}

func (f *fakeSender) Send(_ context.Context, to string, _ Message) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, to)
	return nil
}

func TestRunOnceSendsOnceAndRecordsFailures(t *testing.T) {
	now := time.Date(2026, 11, 17, 7, 1, 0, 0, time.UTC)
	store := &fakeStore{recipients: []Recipient{{
		AccountID: 1, Email: "a@example.org",
		Settings: Settings{Time: "07:00", TimeZone: "UTC", Days: []int16{2}, MinimumRisk: "Medium"},
	}}}
	sender := &fakeSender{}
	service, _ := NewService(store, sender)

	if err := service.RunOnce(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if err := service.RunOnce(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 || store.successes != 1 {
		t.Fatalf("sent %d, recorded %d", len(sender.sent), store.successes)
	}
	if !store.since.Equal(now.Add(-24 * time.Hour)) {
		t.Fatalf("first alert window starts at %v", store.since)
	}

	failing := &fakeStore{recipients: []Recipient{store.recipients[0]}}
	failing.recipients[0].State = State{}
	sender.err = errors.New("boom")
	service, _ = NewService(failing, sender)
	if err := service.RunOnce(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if failing.failures != 1 || failing.successes != 0 {
		t.Fatalf("failures %d successes %d", failing.failures, failing.successes)
	}
}

func TestSMTPRequiresSTARTTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("220 test\r\n"))
		buf := make([]byte, 512)
		conn.Read(buf)
		conn.Write([]byte("250 test\r\n"))
		conn.Read(buf)
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	sender, err := NewSMTPSender(SMTPConfig{Host: "127.0.0.1", Port: port, From: "from@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	err = sender.Send(context.Background(), "to@example.org", Message{Subject: "s", Text: "t", HTML: "h"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v", err)
	}
}

func TestSMTPRejectsHeaderInjection(t *testing.T) {
	sender, _ := NewSMTPSender(SMTPConfig{Host: "127.0.0.1", Port: 1, From: "from@example.org"})
	if err := sender.Send(context.Background(), "to@example.org\r\nBcc: x@example.org", Message{}); err == nil {
		t.Fatal("recipient with CRLF accepted")
	}
	if err := sender.Send(context.Background(), "to@example.org", Message{Subject: "a\r\nBcc: x@example.org"}); err == nil {
		t.Fatal("subject with CRLF accepted")
	}
}

func TestFileMailer(t *testing.T) {
	dir := t.TempDir() + "/mail"
	mailer, err := NewFileMailer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := mailer.SendText(context.Background(), "a@example.org", "Reset", "link"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v, %v", entries, err)
	}
	info, _ := entries[0].Info()
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
	data, _ := os.ReadFile(dir + "/" + entries[0].Name())
	if !strings.Contains(string(data), "To: a@example.org") || !strings.HasSuffix(string(data), "\n\nlink") {
		t.Fatalf("content = %q", data)
	}
	if err := mailer.SendText(context.Background(), "a@example.org\nBcc: x", "Reset", "x"); err == nil {
		t.Fatal("header injection accepted")
	}
}

func TestFileMailerRejectsUnsafeDirectories(t *testing.T) {
	if _, err := NewFileMailer("relative/mail"); err == nil {
		t.Fatal("relative path accepted")
	}
	open := t.TempDir() + "/open"
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileMailer(open); err == nil {
		t.Fatal("group-readable directory accepted")
	}
}
