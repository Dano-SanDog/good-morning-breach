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
	deliveryRetention  = 90 * 24 * time.Hour
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

type Recipient struct {
	AccountID int64
	Email     string
	Settings  Settings
	State     State
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
	RecordSuccess(ctx context.Context, accountID int64, slot, until, attemptedAt time.Time, stories int) error
	RecordFailure(ctx context.Context, accountID int64, slot, attemptedAt time.Time, cause string) error
	DeleteDeliveriesBefore(context.Context, time.Time) error
}

type Sender interface {
	Send(ctx context.Context, to string, message Message) error
}

type Service struct {
	store  Store
	sender Sender
}

func NewService(store Store, sender Sender) (*Service, error) {
	if store == nil || sender == nil {
		return nil, errors.New("alert store and sender are required")
	}
	return &Service{store: store, sender: sender}, nil
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

// RunOnce delivers every alert that is due at now.
func (s *Service) RunOnce(ctx context.Context, now time.Time) error {
	recipients, err := s.store.ListRecipients(ctx)
	if err != nil {
		return fmt.Errorf("list alert recipients: %w", err)
	}
	for _, recipient := range recipients {
		if ctx.Err() != nil {
			return nil
		}
		slot, due := Due(recipient.Settings, recipient.State, now)
		if !due {
			continue
		}
		s.deliver(ctx, recipient, slot, now)
	}
	if err := s.store.DeleteDeliveriesBefore(ctx, now.Add(-deliveryRetention)); err != nil {
		return fmt.Errorf("delete expired delivery records: %w", err)
	}
	return nil
}

func (s *Service) deliver(ctx context.Context, recipient Recipient, slot, now time.Time) {
	since := now.Add(-firstAlertLookback)
	if recipient.State.LastAlertAt != nil {
		since = *recipient.State.LastAlertAt
	}
	fail := func(cause string, err error) {
		slog.Error("morning alert failed",
			"event", "alert_delivery", "outcome", "failure",
			"account_id", recipient.AccountID, "channel", "email", "reason", cause, "error", err)
		recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if recordErr := s.store.RecordFailure(recordCtx, recipient.AccountID, slot, now, cause); recordErr != nil {
			slog.Error("record alert failure", "event", "alert_delivery", "account_id", recipient.AccountID, "error", recordErr)
		}
	}

	stories, err := s.store.StoriesForAlert(ctx, RisksAtOrAbove(recipient.Settings.MinimumRisk), since, now, MaxStories)
	if err != nil {
		fail("could not select stories", err)
		return
	}
	message, err := Render(stories, recipient.Settings, now)
	if err != nil {
		fail("could not render the alert", err)
		return
	}
	sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	if err := s.sender.Send(sendCtx, recipient.Email, message); err != nil {
		fail("email delivery failed", err)
		return
	}
	recordCtx, recordCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer recordCancel()
	if err := s.store.RecordSuccess(recordCtx, recipient.AccountID, slot, now, now, len(stories)); err != nil {
		slog.Error("record alert success", "event", "alert_delivery", "account_id", recipient.AccountID, "error", err)
		return
	}
	slog.Info("morning alert sent",
		"event", "alert_delivery", "outcome", "success",
		"account_id", recipient.AccountID, "channel", "email", "stories", len(stories))
}

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
