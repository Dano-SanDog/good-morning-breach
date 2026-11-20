package alerting

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

const (
	slackTestsPerHour  = 5
	rateWindow         = time.Hour
	contactSendTimeout = 30 * time.Second
)

var (
	ErrInvalidInput = errors.New("invalid channel settings")
	ErrRateLimited  = errors.New("too many requests, try again later")
)

// Quota limits how many messages the system sends per account (SC-058).
type Quota struct {
	Kind       string
	PerAccount int
	Window     time.Duration
}

// ContactRecord is the stored channel state of one account. The Slack webhook
// stays sealed.
type ContactRecord struct {
	EmailEnabled       bool
	SlackEnabled       bool
	SlackWebhookSealed []byte
}

type ContactStore interface {
	GetContacts(ctx context.Context, accountID int64) (ContactRecord, error)
	SaveChannels(ctx context.Context, accountID int64, email, slack bool) error
	SaveSlackWebhook(ctx context.Context, accountID int64, sealed []byte) error
	// ReserveMessage records one outbound message if the quota allows it.
	ReserveMessage(ctx context.Context, accountID int64, quota Quota, now time.Time) (bool, error)
}

type Box interface {
	Unsealer
	Seal(purpose string, accountID int64, plaintext []byte) ([]byte, error)
}

// ChannelView is what the client may see: no webhook address (NFR-3.3, SC-070).
type ChannelView struct {
	EmailEnabled      bool `json:"emailEnabled"`
	SlackEnabled      bool `json:"slackEnabled"`
	SlackWebhookSaved bool `json:"slackWebhookSaved"`
}

// SlackSaveResult tells the user whether the test message arrived (FR-4.17).
type SlackSaveResult struct {
	Saved      bool `json:"saved"`
	TestFailed bool `json:"testFailed"`
}

// ContactService manages one account's alert channels. The caller supplies the
// account ID from the session, never from the request (SC-064).
type ContactService struct {
	store ContactStore
	box   Box
	slack *SlackChannel
	now   func() time.Time
}

func NewContactService(store ContactStore, box Box, slack *SlackChannel) (*ContactService, error) {
	if store == nil || box == nil || slack == nil {
		return nil, errors.New("contact store, encryption, and Slack channel are required")
	}
	return &ContactService{store: store, box: box, slack: slack, now: time.Now}, nil
}

func (s *ContactService) View(ctx context.Context, accountID int64) (ChannelView, error) {
	record, err := s.store.GetContacts(ctx, accountID)
	if err != nil {
		return ChannelView{}, err
	}
	return ChannelView{
		EmailEnabled: record.EmailEnabled, SlackEnabled: record.SlackEnabled,
		SlackWebhookSaved: len(record.SlackWebhookSealed) > 0,
	}, nil
}

// SaveChannels stores the channel choice. At least one channel must stay on
// (FR-4.7), and Slack needs a saved webhook.
func (s *ContactService) SaveChannels(ctx context.Context, accountID int64, email, slack bool) error {
	record, err := s.store.GetContacts(ctx, accountID)
	if err != nil {
		return err
	}
	if !email && !slack {
		return ErrInvalidInput
	}
	if slack && len(record.SlackWebhookSealed) == 0 {
		return ErrInvalidInput
	}
	return s.store.SaveChannels(ctx, accountID, email, slack)
}

// SaveSlackWebhook validates, encrypts, and stores a webhook, enables Slack, and
// sends a test message (FR-4.16, FR-4.17).
func (s *ContactService) SaveSlackWebhook(ctx context.Context, accountID int64, webhook string) (SlackSaveResult, error) {
	validated, err := ValidateSlackWebhook(webhook)
	if err != nil {
		return SlackSaveResult{}, ErrInvalidInput
	}
	now := s.now()
	ok, err := s.store.ReserveMessage(ctx, accountID, Quota{Kind: "slack_test", PerAccount: slackTestsPerHour, Window: rateWindow}, now)
	if err != nil {
		return SlackSaveResult{}, err
	}
	if !ok {
		return SlackSaveResult{}, ErrRateLimited
	}
	sealed, err := s.box.Seal(slackPurpose, accountID, []byte(validated))
	if err != nil {
		return SlackSaveResult{}, err
	}
	if err := s.store.SaveSlackWebhook(ctx, accountID, sealed); err != nil {
		return SlackSaveResult{}, err
	}
	testCtx, cancel := context.WithTimeout(ctx, contactSendTimeout)
	defer cancel()
	result := SlackSaveResult{Saved: true}
	if err := s.slack.SendTest(testCtx, validated); err != nil {
		result.TestFailed = true
		slog.Warn("Slack webhook test failed", "event", "slack_test", "outcome", "failure", "account_id", accountID, "error", err)
	} else {
		slog.Info("Slack webhook test sent", "event", "slack_test", "outcome", "success", "account_id", accountID)
	}
	return result, nil
}
