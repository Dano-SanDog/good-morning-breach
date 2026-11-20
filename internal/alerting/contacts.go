package alerting

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"
)

const (
	phonePurpose       = "phone_code"
	codeLifetime       = 10 * time.Minute
	maxCodeAttempts    = 5
	codesPerHour       = 3
	slackTestsPerHour  = 5
	rateWindow         = time.Hour
	contactSendTimeout = 30 * time.Second
)

var (
	ErrInvalidInput   = errors.New("invalid channel settings")
	ErrRateLimited    = errors.New("too many requests, try again later")
	ErrSMSUnavailable = errors.New("text messages are not set up on this server")
	ErrCodeRejected   = errors.New("verification code is wrong or expired")
	ErrSendFailed     = errors.New("could not send")
)

// ContactRecord is the stored channel state of one account. The Slack webhook
// stays sealed.
type ContactRecord struct {
	EmailEnabled       bool
	SlackEnabled       bool
	SMSEnabled         bool
	SlackWebhookSealed []byte
	Phone              string
	PhoneVerified      bool
	PendingPhone       string
}

type Verification struct {
	Phone          string
	CodeHash       []byte
	ExpiresAt      time.Time
	FailedAttempts int
}

type ContactStore interface {
	SMSSupport
	GetContacts(ctx context.Context, accountID int64) (ContactRecord, error)
	SaveChannels(ctx context.Context, accountID int64, email, slack, sms bool) error
	SaveSlackWebhook(ctx context.Context, accountID int64, sealed []byte) error
	StartPhoneVerification(ctx context.Context, accountID int64, phone string, codeHash []byte, expires, now time.Time) error
	// ConsumeVerificationAttempt atomically uses one attempt of the pending
	// code. It reports false when there is no live code or no attempts left.
	ConsumeVerificationAttempt(ctx context.Context, accountID int64, maxAttempts int, now time.Time) (Verification, bool, error)
	ConfirmPhone(ctx context.Context, accountID int64, phone string, now time.Time) error
}

type Box interface {
	Unsealer
	Seal(purpose string, accountID int64, plaintext []byte) ([]byte, error)
	Digest(purpose string, accountID int64, value string) []byte
}

// ChannelView is what the client may see: no webhook address, no code, and a
// masked phone number (NFR-3.3, SC-070).
type ChannelView struct {
	EmailEnabled       bool   `json:"emailEnabled"`
	SlackEnabled       bool   `json:"slackEnabled"`
	SMSEnabled         bool   `json:"smsEnabled"`
	SlackWebhookSaved  bool   `json:"slackWebhookSaved"`
	SMSAvailable       bool   `json:"smsAvailable"`
	PhoneMasked        string `json:"phoneMasked"`
	PhoneVerified      bool   `json:"phoneVerified"`
	PendingPhoneMasked string `json:"pendingPhoneMasked"`
}

// SlackSaveResult tells the user whether the test message arrived (FR-4.17).
type SlackSaveResult struct {
	Saved      bool `json:"saved"`
	TestFailed bool `json:"testFailed"`
}

// ContactService manages one account's alert channels. The caller supplies the
// account ID from the session, never from the request (SC-064).
type ContactService struct {
	store  ContactStore
	box    Box
	slack  *SlackChannel
	twilio *TwilioClient
	now    func() time.Time
}

func NewContactService(store ContactStore, box Box, slack *SlackChannel, twilio *TwilioClient) (*ContactService, error) {
	if store == nil || box == nil || slack == nil {
		return nil, errors.New("contact store, encryption, and Slack channel are required")
	}
	return &ContactService{store: store, box: box, slack: slack, twilio: twilio, now: time.Now}, nil
}

func maskPhone(phone string) string {
	if len(phone) < 5 {
		return ""
	}
	return "+•••••" + phone[len(phone)-4:]
}

func (s *ContactService) View(ctx context.Context, accountID int64) (ChannelView, error) {
	record, err := s.store.GetContacts(ctx, accountID)
	if err != nil {
		return ChannelView{}, err
	}
	return ChannelView{
		EmailEnabled: record.EmailEnabled, SlackEnabled: record.SlackEnabled, SMSEnabled: record.SMSEnabled,
		SlackWebhookSaved: len(record.SlackWebhookSealed) > 0, SMSAvailable: s.twilio != nil,
		PhoneMasked: maskPhone(record.Phone), PhoneVerified: record.PhoneVerified,
		PendingPhoneMasked: maskPhone(record.PendingPhone),
	}, nil
}

// SaveChannels stores the channel choice. At least one channel must stay on
// (FR-4.7), Slack needs a saved webhook, and text needs a verified number (FR-4.15).
func (s *ContactService) SaveChannels(ctx context.Context, accountID int64, email, slack, sms bool) error {
	record, err := s.store.GetContacts(ctx, accountID)
	if err != nil {
		return err
	}
	if !email && !slack && !sms {
		return ErrInvalidInput
	}
	if slack && len(record.SlackWebhookSealed) == 0 {
		return ErrInvalidInput
	}
	if sms && (!record.PhoneVerified || (s.twilio == nil && !record.SMSEnabled)) {
		return ErrInvalidInput
	}
	return s.store.SaveChannels(ctx, accountID, email, slack, sms)
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

func sixDigitCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// StartPhoneVerification sends a 6-digit code to the number. A new code replaces
// the previous one (SC-056). At most 3 code messages per account per hour, and the
// global daily text cap applies (SC-058).
func (s *ContactService) StartPhoneVerification(ctx context.Context, accountID int64, phone string) error {
	if s.twilio == nil {
		return ErrSMSUnavailable
	}
	if !ValidPhone(phone) {
		return ErrInvalidInput
	}
	now := s.now()
	ok, err := s.store.ReserveMessage(ctx, accountID, Quota{
		Kind: "sms_code", PerAccount: codesPerHour, Window: rateWindow, GlobalDaily: s.twilio.CodeDailyCap()}, now)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRateLimited
	}
	code, err := sixDigitCode()
	if err != nil {
		return err
	}
	if err := s.store.StartPhoneVerification(ctx, accountID, phone, s.box.Digest(phonePurpose, accountID, phone+":"+code), now.Add(codeLifetime), now); err != nil {
		return err
	}
	sendCtx, cancel := context.WithTimeout(ctx, contactSendTimeout)
	defer cancel()
	body := "Good Morning Breach code: " + code + ". It expires in 10 minutes. Reply STOP to opt out."
	if err := s.twilio.SendSMS(sendCtx, phone, body); err != nil {
		slog.Warn("verification text failed", "event", "phone_verification", "outcome", "failure", "account_id", accountID, "error", err)
		return ErrSendFailed
	}
	slog.Info("verification text sent", "event", "phone_verification", "outcome", "sent", "account_id", accountID)
	return nil
}

// VerifyPhone checks the code in constant time. The attempt is consumed before
// the comparison, so parallel guesses cannot exceed 5. The code is invalidated after 5
// entries or 10 minutes (SC-056).
func (s *ContactService) VerifyPhone(ctx context.Context, accountID int64, code string) error {
	now := s.now()
	verification, found, err := s.store.ConsumeVerificationAttempt(ctx, accountID, maxCodeAttempts, now)
	if err != nil {
		return err
	}
	if !found {
		return ErrCodeRejected
	}
	expected := s.box.Digest(phonePurpose, accountID, verification.Phone+":"+code)
	if len(code) != 6 || subtle.ConstantTimeCompare(expected, verification.CodeHash) != 1 {
		slog.Warn("verification code rejected", "event", "phone_verification", "outcome", "failure", "account_id", accountID)
		return ErrCodeRejected
	}
	if err := s.store.ConfirmPhone(ctx, accountID, verification.Phone, now); err != nil {
		return err
	}
	slog.Info("phone number verified", "event", "phone_verification", "outcome", "success", "account_id", accountID)
	return nil
}
