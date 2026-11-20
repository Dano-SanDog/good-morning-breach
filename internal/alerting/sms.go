package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// DashboardURL is where text messages point (FR-4.13). It only opens on the
	// machine that runs the server.
	DashboardURL = "https://localhost:8443"

	DefaultSMSDailyCap = 20
	maxSMSDailyCap     = 1000
	smsTitles          = 3
	smsTitleLength     = 60
)

var (
	// ErrSMSOptedOut means the recipient replied STOP to the sender number, so
	// Twilio refuses further messages (Twilio error 21610).
	ErrSMSOptedOut = errors.New("recipient opted out of text messages")

	e164Pattern      = regexp.MustCompile(`^\+[1-9][0-9]{1,14}$`)
	twilioAccountSID = regexp.MustCompile(`^AC[0-9a-fA-F]{32}$`)
	twilioAPIKeySID  = regexp.MustCompile(`^SK[0-9a-fA-F]{32}$`)
)

// ValidPhone reports whether value is an E.164 phone number (SC-014).
func ValidPhone(value string) bool { return e164Pattern.MatchString(value) }

// TwilioConfig holds the Twilio credentials. It authenticates with an API key,
// never the account auth token (SC-072).
type TwilioConfig struct {
	AccountSID   string
	APIKeySID    string
	APIKeySecret string
	From         string
	DailyCap     int
}

func (c TwilioConfig) LogValue() slog.Value {
	return slog.StringValue(c.String())
}

func (c TwilioConfig) String() string {
	return fmt.Sprintf("Twilio account %s sender %s", c.AccountSID, c.From)
}

func (c TwilioConfig) GoString() string { return c.String() }

// LoadTwilioConfig reads GB_TWILIO_ACCOUNT_SID, GB_TWILIO_API_KEY_SID,
// GB_TWILIO_API_KEY_SECRET_FILE (a 0600 file), GB_TWILIO_FROM, and the optional
// GB_SMS_DAILY_CAP. It returns false when GB_TWILIO_ACCOUNT_SID is unset.
func LoadTwilioConfig() (TwilioConfig, bool, error) {
	account := os.Getenv("GB_TWILIO_ACCOUNT_SID")
	if account == "" {
		return TwilioConfig{}, false, nil
	}
	config := TwilioConfig{
		AccountSID: account,
		APIKeySID:  os.Getenv("GB_TWILIO_API_KEY_SID"),
		From:       os.Getenv("GB_TWILIO_FROM"),
		DailyCap:   DefaultSMSDailyCap,
	}
	if raw := os.Getenv("GB_SMS_DAILY_CAP"); raw != "" {
		cap, err := strconv.Atoi(raw)
		if err != nil || cap < 1 || cap > maxSMSDailyCap {
			return TwilioConfig{}, false, errors.New("GB_SMS_DAILY_CAP must be from 1 to 1000")
		}
		config.DailyCap = cap
	}
	path := os.Getenv("GB_TWILIO_API_KEY_SECRET_FILE")
	if path == "" {
		return TwilioConfig{}, false, errors.New("GB_TWILIO_API_KEY_SECRET_FILE is required when GB_TWILIO_ACCOUNT_SID is set")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return TwilioConfig{}, false, fmt.Errorf("inspect Twilio API key secret file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return TwilioConfig{}, false, errors.New("Twilio API key secret file must be a regular 0600 file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return TwilioConfig{}, false, fmt.Errorf("read Twilio API key secret file: %w", err)
	}
	config.APIKeySecret = strings.TrimRight(string(data), "\r\n")
	if err := config.validate(); err != nil {
		return TwilioConfig{}, false, err
	}
	return config, true, nil
}

func (c TwilioConfig) validate() error {
	switch {
	case !twilioAccountSID.MatchString(c.AccountSID):
		return errors.New("GB_TWILIO_ACCOUNT_SID must be an Account SID starting with AC")
	case !twilioAPIKeySID.MatchString(c.APIKeySID):
		return errors.New("GB_TWILIO_API_KEY_SID must be a Standard or Restricted API key SID starting with SK, not the account auth token")
	case c.APIKeySecret == "":
		return errors.New("Twilio API key secret file is empty")
	case !ValidPhone(c.From):
		return errors.New("GB_TWILIO_FROM must be an E.164 phone number such as +15551234567")
	}
	return nil
}

// TwilioClient sends text messages through the Twilio Messages REST API.
type TwilioClient struct {
	config  TwilioConfig
	client  *http.Client
	baseURL string
}

func NewTwilioClient(config TwilioConfig, client *http.Client) (*TwilioClient, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if config.DailyCap < 1 {
		config.DailyCap = DefaultSMSDailyCap
	}
	return &TwilioClient{config: config, client: client, baseURL: "https://api.twilio.com"}, nil
}

func (c *TwilioClient) DailyCap() int { return c.config.DailyCap }

// SendSMS sends one message. Errors hold only a Twilio error code or HTTP status,
// never the phone number, message, or credentials.
func (c *TwilioClient) SendSMS(ctx context.Context, to, body string) error {
	if !ValidPhone(to) {
		return &DeliveryError{Cause: "recipient phone number is not valid"}
	}
	form := url.Values{"To": {to}, "From": {c.config.From}, "Body": {body}}
	endpoint := c.baseURL + "/2010-04-01/Accounts/" + c.config.AccountSID + "/Messages.json"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return &DeliveryError{Cause: "text message request could not be built"}
	}
	request.SetBasicAuth(c.config.APIKeySID, c.config.APIKeySecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return &DeliveryError{Cause: "Twilio request failed", Err: err}
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 8192))
	if response.StatusCode == http.StatusCreated || response.StatusCode == http.StatusOK {
		return nil
	}
	var failure struct {
		Code int `json:"code"`
	}
	_ = json.Unmarshal(data, &failure)
	if failure.Code == 21610 {
		return &DeliveryError{Cause: "recipient opted out of text messages (replied STOP)", Err: ErrSMSOptedOut}
	}
	if failure.Code != 0 {
		return &DeliveryError{Cause: fmt.Sprintf("Twilio error %d (HTTP %d)", failure.Code, response.StatusCode)}
	}
	return &DeliveryError{Cause: fmt.Sprintf("Twilio returned HTTP %d", response.StatusCode)}
}

// Quota limits how many messages the system sends, per account and overall (SC-058).
type Quota struct {
	Kind       string
	PerAccount int
	Window     time.Duration
	// GlobalDaily caps all text messages (codes and alerts) in the past 24 hours.
	GlobalDaily int
}

// ErrQuotaExceeded means a rate limit or the daily cost cap was reached.
var ErrQuotaExceeded = errors.New("message quota exceeded")

type SMSSupport interface {
	ReserveMessage(ctx context.Context, accountID int64, quota Quota, now time.Time) (bool, error)
	DisableSMS(ctx context.Context, accountID int64) error
}

// SMSChannel sends the short text alert to a verified number (FR-4.3, FR-4.13).
type SMSChannel struct {
	twilio  *TwilioClient
	support SMSSupport
}

func NewSMSChannel(twilio *TwilioClient, support SMSSupport) *SMSChannel {
	return &SMSChannel{twilio: twilio, support: support}
}

func (*SMSChannel) Name() string    { return ChannelSMS }
func (*SMSChannel) StoryLimit() int { return smsTitles }
func (*SMSChannel) Enabled(r Recipient) bool {
	return r.Contacts.SMSEnabled && r.Contacts.PhoneVerified && r.Contacts.Phone != ""
}

func (c *SMSChannel) Deliver(ctx context.Context, r Recipient, stories []Story, now time.Time) error {
	ok, err := c.support.ReserveMessage(ctx, r.AccountID, Quota{Kind: "sms_alert", GlobalDaily: c.twilio.DailyCap()}, now)
	if err != nil {
		return err
	}
	if !ok {
		return &DeliveryError{Cause: "daily text message cap reached", Err: ErrQuotaExceeded}
	}
	err = c.twilio.SendSMS(ctx, r.Contacts.Phone, RenderSMS(stories, r.Settings))
	if errors.Is(err, ErrSMSOptedOut) {
		disableCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if disableErr := c.support.DisableSMS(disableCtx, r.AccountID); disableErr != nil {
			slog.Error("disable text messages after opt-out", "event", "alert_delivery", "account_id", r.AccountID, "error", disableErr)
		}
	}
	return err
}

// smsText keeps printable ASCII only so a message stays in one GSM-7 segment where
// possible, and strips anything that could be control text.
func smsText(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > limit {
		value = strings.TrimSpace(value[:limit-3]) + "..."
	}
	return value
}

// RenderSMS builds the text alert: at most 3 titles with risk values and a link to
// the dashboard (FR-4.13, FR-4.14).
func RenderSMS(stories []Story, settings Settings) string {
	if len(stories) == 0 {
		return "Good Morning Breach: no new stories at or above " + smsText(settings.MinimumRisk, 20) + ". " + DashboardURL
	}
	var out strings.Builder
	out.WriteString("Good Morning Breach:")
	for i, story := range stories {
		if i >= smsTitles {
			break
		}
		fmt.Fprintf(&out, "\n[%s] %s", smsText(story.Risk, 20), smsText(story.Title, smsTitleLength))
	}
	if len(stories) > smsTitles {
		out.WriteString("\nand more")
	}
	out.WriteString("\n" + DashboardURL)
	return out.String()
}
