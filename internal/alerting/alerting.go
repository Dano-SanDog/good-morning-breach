package alerting

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"
)

const (
	MaxStories         = 10
	maxAttempts        = 4
	retryInterval      = 10 * time.Minute
	catchUpWindow      = 2 * time.Hour
	firstAlertLookback = 24 * time.Hour
	sendTimeout        = 60 * time.Second
)

var riskOrder = []string{"Critical", "High", "Medium", "Low", "Informational"}

type Settings struct {
	Time        string
	TimeZone    string
	Days        []int16
	MinimumRisk string
}

type State struct {
	LastSentSlotAt *time.Time
	LastAlertAt    *time.Time
	RetrySlotAt    *time.Time
	RetryAttempts  int
	LastAttemptAt  *time.Time
}

// Channel names, stored in delivery records and channel state.
const (
	ChannelEmail = "email"
	ChannelSlack = "slack"
	ChannelSMS   = "sms"
)

// Contacts holds the per-account channel choices and the decrypted contact data
// that only the alerting path may read (SC-074).
type Contacts struct {
	EmailEnabled       bool
	SlackEnabled       bool
	SMSEnabled         bool
	SlackWebhookSealed []byte
	Phone              string
	PhoneVerified      bool
}

type Recipient struct {
	AccountID int64
	Email     string
	Settings  Settings
	Contacts  Contacts
	States    map[string]State
}

type Technique struct {
	ID      string
	Name    string
	Tactics []string
	URL     string
}

type RelatedStory struct {
	Title string
	URL   string
	CVE   string
}

type Story struct {
	ID           int64
	CVEs         []string
	Related      []RelatedStory
	Title        string
	URL          string
	Sources      []string
	Attributions []string
	PublishedAt  *time.Time
	Categories   []string
	Risk         string
	Sentiment    string
	Techniques   []Technique
}

type Store interface {
	ListRecipients(context.Context) ([]Recipient, error)
	StoriesForAlert(ctx context.Context, risks []string, since, until time.Time, limit int) ([]Story, error)
	RecordSuccess(ctx context.Context, accountID int64, channel string, slot, until, attemptedAt time.Time, stories int) error
	RecordFailure(ctx context.Context, accountID int64, channel string, slot, attemptedAt time.Time, cause string) error
}

type Sender interface {
	Send(ctx context.Context, to string, message Message) error
}

// Channel delivers one rendered alert over one medium. Each channel keeps its own
// schedule state and retries, so a failure on one never stops another (FR-4.18).
type Channel interface {
	Name() string
	// Enabled reports whether the recipient chose this channel and it is usable.
	Enabled(Recipient) bool
	// StoryLimit is the maximum number of stories the channel shows.
	StoryLimit() int
	// Deliver renders the stories for this channel and sends them. The returned
	// error text is stored as the failure cause, so it must hold no secrets.
	Deliver(ctx context.Context, recipient Recipient, stories []Story, now time.Time) error
}

type Service struct {
	store    Store
	channels []Channel
}

func NewService(store Store, channels ...Channel) (*Service, error) {
	if store == nil || len(channels) == 0 {
		return nil, errors.New("alert store and at least one channel are required")
	}
	return &Service{store: store, channels: channels}, nil
}

// EmailChannel sends the full alert through a Sender.
type EmailChannel struct{ sender Sender }

func NewEmailChannel(sender Sender) *EmailChannel { return &EmailChannel{sender: sender} }

func (*EmailChannel) Name() string             { return ChannelEmail }
func (*EmailChannel) Enabled(r Recipient) bool { return r.Contacts.EmailEnabled && r.Email != "" }
func (*EmailChannel) StoryLimit() int          { return MaxStories }
func (c *EmailChannel) Deliver(ctx context.Context, r Recipient, stories []Story, now time.Time) error {
	message, err := Render(stories, r.Settings, now)
	if err != nil {
		return err
	}
	return c.sender.Send(ctx, r.Email, message)
}

// RisksAtOrAbove returns the risk values that meet a minimum risk (FR-4.9, FR-4.10).
func RisksAtOrAbove(minimum string) []string {
	index := slices.Index(riskOrder, minimum)
	if index < 0 {
		return nil
	}
	return slices.Clone(riskOrder[:index+1])
}

// Due returns the scheduled time of the alert that should be sent now, if any.
// It never returns a slot that was already sent, a slot older than the catch-up
// window, or a slot whose retries are exhausted or not yet due (FR-4.5, FR-4.6, FR-4.18).
func Due(settings Settings, state State, now time.Time) (time.Time, bool) {
	location, err := time.LoadLocation(settings.TimeZone)
	if err != nil || settings.TimeZone == "Local" {
		return time.Time{}, false
	}
	var hour, minute int
	if _, err := fmt.Sscanf(settings.Time, "%02d:%02d", &hour, &minute); err != nil ||
		hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return time.Time{}, false
	}
	local := now.In(location)
	var slot time.Time
	for back := 0; back < 8; back++ {
		day := local.AddDate(0, 0, -back)
		candidate := time.Date(day.Year(), day.Month(), day.Day(), hour, minute, 0, 0, location)
		if candidate.After(now) || !slices.Contains(settings.Days, int16(candidate.Weekday())) {
			continue
		}
		slot = candidate
		break
	}
	if slot.IsZero() || now.Sub(slot) > catchUpWindow {
		return time.Time{}, false
	}
	if state.LastSentSlotAt != nil && !slot.After(*state.LastSentSlotAt) {
		return time.Time{}, false
	}
	if state.RetrySlotAt != nil && state.RetrySlotAt.Equal(slot) {
		if state.RetryAttempts >= maxAttempts {
			return time.Time{}, false
		}
		if state.LastAttemptAt != nil && now.Sub(*state.LastAttemptAt) < retryInterval {
			return time.Time{}, false
		}
	}
	return slot, true
}

// RunOnce delivers every alert that is due at now, on every enabled channel.
func (s *Service) RunOnce(ctx context.Context, now time.Time) error {
	recipients, err := s.store.ListRecipients(ctx)
	if err != nil {
		return fmt.Errorf("list alert recipients: %w", err)
	}
	for _, recipient := range recipients {
		for _, channel := range s.channels {
			if ctx.Err() != nil {
				return nil
			}
			if !channel.Enabled(recipient) {
				continue
			}
			slot, due := Due(recipient.Settings, recipient.States[channel.Name()], now)
			if !due {
				continue
			}
			s.deliver(ctx, channel, recipient, slot, now)
		}
	}
	return nil
}

func (s *Service) deliver(ctx context.Context, channel Channel, recipient Recipient, slot, now time.Time) {
	name := channel.Name()
	state := recipient.States[name]
	since := now.Add(-firstAlertLookback)
	if state.LastAlertAt != nil {
		since = *state.LastAlertAt
	}
	fail := func(cause string, err error) {
		slog.Error("morning alert failed",
			"event", "alert_delivery", "outcome", "failure",
			"account_id", recipient.AccountID, "channel", name, "reason", cause, "error", err)
		recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if recordErr := s.store.RecordFailure(recordCtx, recipient.AccountID, name, slot, now, cause); recordErr != nil {
			slog.Error("record alert failure", "event", "alert_delivery", "account_id", recipient.AccountID, "channel", name, "error", recordErr)
		}
	}

	stories, err := s.store.StoriesForAlert(ctx, RisksAtOrAbove(recipient.Settings.MinimumRisk), since, now, channel.StoryLimit())
	if err != nil {
		fail("could not select stories", err)
		return
	}
	sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	if err := channel.Deliver(sendCtx, recipient, stories, now); err != nil {
		var delivery *DeliveryError
		if errors.As(err, &delivery) {
			fail(delivery.Cause, err)
		} else {
			fail(name+" delivery failed", err)
		}
		return
	}
	recordCtx, recordCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer recordCancel()
	if err := s.store.RecordSuccess(recordCtx, recipient.AccountID, name, slot, now, now, len(stories)); err != nil {
		slog.Error("record alert success", "event", "alert_delivery", "account_id", recipient.AccountID, "channel", name, "error", err)
		return
	}
	slog.Info("morning alert sent",
		"event", "alert_delivery", "outcome", "success",
		"account_id", recipient.AccountID, "channel", name, "stories", len(stories))
}

// DeliveryError carries a failure cause that is safe to store and show: it never
// contains a webhook address, credential, phone number, or response body.
type DeliveryError struct {
	Cause string
	Err   error
}

func (e *DeliveryError) Error() string { return e.Cause }
func (e *DeliveryError) Unwrap() error { return e.Err }

// RunPeriodically checks for due alerts until ctx ends.
func RunPeriodically(ctx context.Context, service *Service, interval time.Duration) error {
	if service == nil {
		return errors.New("alert service is required")
	}
	if interval <= 0 {
		return errors.New("alert check interval must be positive")
	}
	for {
		if err := service.RunOnce(ctx, time.Now()); err != nil && ctx.Err() == nil {
			slog.Error("alert check failed", "event", "alert_scheduler", "outcome", "failure", "error", err)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
