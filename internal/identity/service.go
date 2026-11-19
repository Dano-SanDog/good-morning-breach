package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	sessionLifetime  = 8 * time.Hour
	sessionIdleLimit = 30 * time.Minute
	partialLifetime  = 5 * time.Minute
)

type Service struct {
	store   Store
	dataKey []byte
	client  *http.Client
	now     func() time.Time
}

type LoginStep string

const (
	LoginTOTP LoginStep = "totp"
	SetupTOTP LoginStep = "setup"
)

type AuthenticatedUser struct {
	AccountID int64  `json:"-"`
	Email     string `json:"email"`
	Role      string `json:"role"`
}

func (AuthenticatedUser) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

type LoginResult struct {
	Token string
	Next  LoginStep
	User  *AuthenticatedUser
}

type Challenge struct {
	Next LoginStep `json:"next"`
}

func NewService(store Store, dataKey []byte, client *http.Client) (*Service, error) {
	if store == nil {
		return nil, errors.New("identity store is required")
	}
	if len(dataKey) != 32 {
		return nil, errors.New("data encryption key must contain 32 bytes")
	}
	if client == nil {
		return nil, errors.New("outbound HTTP client is required")
	}
	return &Service{
		store:   store,
		dataKey: append([]byte(nil), dataKey...),
		client:  client,
		now:     time.Now,
	}, nil
}

func (s *Service) CreateInitialAdmin(ctx context.Context, email, password string) error {
	email = normalizeEmail(email)
	if !validEmail(email) {
		return ErrInvalidEmail
	}
	if err := ValidateNewPassword(ctx, s.client, password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	accountID, err := s.store.CreateAdmin(ctx, email, hash)
	if err != nil {
		return err
	}
	slog.Info("initial administrator created", "event", "admin_bootstrap", "account_id", accountID, "outcome", "success")
	return nil
}

func (s *Service) ListAccounts(ctx context.Context, token string) ([]ManagedAccount, error) {
	if _, err := s.requireAdmin(ctx, token); err != nil {
		return nil, err
	}
	return s.store.ListAccounts(ctx)
}

func (s *Service) CreateAccount(
	ctx context.Context,
	token, email, password, role string,
) (ManagedAccount, error) {
	admin, err := s.requireAdmin(ctx, token)
	if err != nil {
		return ManagedAccount{}, err
	}
	email = normalizeEmail(email)
	if !validEmail(email) {
		return ManagedAccount{}, ErrInvalidEmail
	}
	if role != "admin" && role != "user" {
		return ManagedAccount{}, ErrInvalidRole
	}
	if err := ValidateNewPassword(ctx, s.client, password); err != nil {
		return ManagedAccount{}, err
	}
	passwordHash, err := HashPassword(password)
	if err != nil {
		return ManagedAccount{}, err
	}
	return s.store.CreateAccount(ctx, admin.AccountID, email, passwordHash, role)
}

func (s *Service) UpdateAccount(
	ctx context.Context,
	token string,
	targetID int64,
	role *string,
	enabled *bool,
) error {
	admin, err := s.requireAdmin(ctx, token)
	if err != nil {
		return err
	}
	if targetID < 1 || (role == nil && enabled == nil) {
		return ErrInvalidAccountUpdate
	}
	if role != nil && *role != "admin" && *role != "user" {
		return ErrInvalidRole
	}
	if targetID == admin.AccountID &&
		((role != nil && *role != "admin") || (enabled != nil && !*enabled)) {
		return ErrSelfManagement
	}
	return s.store.UpdateAccount(ctx, admin.AccountID, targetID, role, enabled)
}

func (s *Service) DeleteAccount(ctx context.Context, token string, targetID int64) error {
	admin, err := s.requireAdmin(ctx, token)
	if err != nil {
		return err
	}
	if targetID < 1 {
		return ErrInvalidAccountUpdate
	}
	if targetID == admin.AccountID {
		return ErrSelfManagement
	}
	return s.store.DeleteAccount(ctx, admin.AccountID, targetID)
}

func (s *Service) ListAdminAudit(ctx context.Context, token string) ([]AdminAuditRecord, error) {
	if _, err := s.requireAdmin(ctx, token); err != nil {
		return nil, err
	}
	return s.store.ListAdminAudit(ctx)
}

func (s *Service) ListSourceStatuses(ctx context.Context, token string) ([]SourceStatus, error) {
	if _, err := s.requireAdmin(ctx, token); err != nil {
		return nil, err
	}
	statuses, err := s.store.ListSourceStatuses(ctx)
	if err != nil {
		return nil, err
	}
	for i := range statuses {
		status := &statuses[i]
		status.Warning = status.Enabled && status.FailingSince != nil &&
			!status.FailingSince.After(s.now().Add(-24*time.Hour))
	}
	return statuses, nil
}

func (s *Service) GetAlertSettings(ctx context.Context, token string) (AlertSettings, error) {
	user, err := s.CurrentUser(ctx, token)
	if err != nil {
		return AlertSettings{}, err
	}
	return s.store.GetAlertSettings(ctx, user.AccountID)
}

func (s *Service) SaveAlertSettings(ctx context.Context, token string, settings AlertSettings) error {
	user, err := s.CurrentUser(ctx, token)
	if err != nil {
		return err
	}
	if err := ValidateAlertSettings(settings); err != nil {
		return err
	}
	return s.store.SaveAlertSettings(ctx, user.AccountID, settings)
}

func ValidateAlertSettings(settings AlertSettings) error {
	parsed, err := time.Parse("15:04", settings.Time)
	if err != nil || parsed.Format("15:04") != settings.Time ||
		settings.TimeZone == "" || settings.TimeZone == "Local" || len(settings.TimeZone) > 100 {
		return ErrInvalidAlertSettings
	}
	if _, err := time.LoadLocation(settings.TimeZone); err != nil {
		return ErrInvalidAlertSettings
	}
	switch settings.MinimumRisk {
	case "Critical", "High", "Medium", "Low", "Informational":
	default:
		return ErrInvalidAlertSettings
	}
	if len(settings.Days) < 1 || len(settings.Days) > 7 {
		return ErrInvalidAlertSettings
	}
	var seen [7]bool
	for _, day := range settings.Days {
		if day < 0 || day > 6 || seen[day] {
			return ErrInvalidAlertSettings
		}
		seen[day] = true
	}
	return nil
}

func (s *Service) requireAdmin(ctx context.Context, token string) (AuthenticatedUser, error) {
	user, err := s.CurrentUser(ctx, token)
	if err != nil {
		return AuthenticatedUser{}, err
	}
	if user.Role != "admin" {
		return AuthenticatedUser{}, ErrAdminRequired
	}
	return user, nil
}

func (s *Service) PasswordLogin(ctx context.Context, email, password, previousToken string) (LoginResult, error) {
	account, err := s.store.AccountByEmail(ctx, normalizeEmail(email))
	found := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return LoginResult{}, err
	}
	hash := dummyPasswordHash
	if found {
		hash = account.PasswordHash
	}
	passwordMatches := VerifyPassword(hash, password)
	now := s.now()
	if !found || !passwordMatches || !account.Enabled || isLocked(account.LockedUntil, now) {
		if found && !isLocked(account.LockedUntil, now) {
			if err := s.recordFailedLogin(ctx, account.ID, now); err != nil {
				return LoginResult{}, err
			}
		} else {
			accountID := int64(0)
			if found {
				accountID = account.ID
			}
			logLoginFailure(accountID)
		}
		return LoginResult{}, ErrCredentials
	}

	rawToken := rand.Text()
	tokenHash := hashSessionToken(rawToken)
	var previousHash []byte
	if previousToken != "" {
		previous := hashSessionToken(previousToken)
		previousHash = previous[:]
	}
	if !account.TOTPRequired {
		if err := s.store.CreateSession(ctx, previousHash, tokenHash[:], account.ID, now); err != nil {
			return LoginResult{}, err
		}
		user := AuthenticatedUser{AccountID: account.ID, Email: account.Email, Role: account.Role}
		slog.Info("sign-in succeeded", "event", "login_success", "account_id", account.ID, "outcome", "success")
		return LoginResult{Token: rawToken, User: &user}, nil
	}

	next := LoginTOTP
	if !account.TOTPEnrolled {
		next = SetupTOTP
	}
	if err := s.store.CreatePartialSession(
		ctx,
		previousHash,
		tokenHash[:],
		account.ID,
		now,
		now.Add(partialLifetime),
	); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Token: rawToken, Next: next}, nil
}

func (s *Service) BeginTOTPSetup(ctx context.Context, token string) (string, error) {
	session, err := s.loadSession(ctx, token)
	if err != nil {
		return "", err
	}
	if session.PartialExpiresAt == nil || !session.Account.TOTPRequired ||
		session.Account.TOTPEnrolled || !session.Account.Enabled {
		return "", ErrTOTPSetup
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Good Morning Breach",
		AccountName: session.Account.Email,
		SecretSize:  20,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", errors.New("generate time-based code")
	}
	ciphertext, nonce, err := encryptTOTPSecret(s.dataKey, session.Account.ID, []byte(key.Secret()))
	if err != nil {
		return "", err
	}
	sessionHash := hashSessionToken(token)
	if err := s.store.BeginTOTPSetup(
		ctx,
		sessionHash[:],
		session.Account.ID,
		ciphertext,
		nonce,
		s.now(),
	); err != nil {
		return "", err
	}
	return key.Secret(), nil
}

func (s *Service) CompleteTOTP(ctx context.Context, token, code string, setup bool) (AuthenticatedUser, string, error) {
	session, err := s.loadSession(ctx, token)
	if err != nil {
		return AuthenticatedUser{}, "", err
	}
	if session.PartialExpiresAt == nil || !session.Account.TOTPRequired || !session.Account.Enabled {
		return AuthenticatedUser{}, "", ErrSession
	}
	if setup == session.Account.TOTPEnrolled {
		return AuthenticatedUser{}, "", ErrTOTPSetup
	}
	if isLocked(session.Account.LockedUntil, s.now()) {
		logLoginFailure(session.Account.ID)
		return AuthenticatedUser{}, "", ErrCredentials
	}
	secret, err := decryptTOTPSecret(
		s.dataKey,
		session.Account.ID,
		session.Account.TOTPSecretCiphertext,
		session.Account.TOTPNonce,
	)
	if err != nil {
		return AuthenticatedUser{}, "", err
	}
	now := s.now()
	step, valid := validateTOTP(code, string(secret), now)
	if !valid {
		if err := s.recordFailedLogin(ctx, session.Account.ID, now); err != nil {
			return AuthenticatedUser{}, "", err
		}
		return AuthenticatedUser{}, "", ErrCredentials
	}

	rawToken := rand.Text()
	oldHash := hashSessionToken(token)
	newHash := hashSessionToken(rawToken)
	account, err := s.store.CompleteTOTP(ctx, oldHash[:], newHash[:], step, now, setup)
	if err != nil {
		if errors.Is(err, ErrOTPReplay) {
			if recordErr := s.recordFailedLogin(ctx, session.Account.ID, now); recordErr != nil {
				return AuthenticatedUser{}, "", recordErr
			}
			return AuthenticatedUser{}, "", ErrCredentials
		}
		if errors.Is(err, ErrCredentials) || errors.Is(err, ErrSession) || errors.Is(err, ErrTOTPSetup) {
			if errors.Is(err, ErrCredentials) {
				logLoginFailure(session.Account.ID)
			}
			return AuthenticatedUser{}, "", ErrCredentials
		}
		return AuthenticatedUser{}, "", err
	}
	slog.Info("sign-in succeeded", "event", "login_success", "account_id", account.ID, "outcome", "success")
	if setup {
		slog.Info("authenticator enrolled", "event", "totp_enrollment", "account_id", account.ID, "outcome", "success")
	}
	return AuthenticatedUser{AccountID: account.ID, Email: account.Email, Role: account.Role}, rawToken, nil
}

func (s *Service) CurrentUser(ctx context.Context, token string) (AuthenticatedUser, error) {
	session, err := s.loadSession(ctx, token)
	if err != nil {
		return AuthenticatedUser{}, err
	}
	if session.PartialExpiresAt != nil ||
		(session.Account.TOTPRequired && !session.Account.TOTPEnrolled) ||
		!session.Account.Enabled {
		return AuthenticatedUser{}, ErrSession
	}
	return AuthenticatedUser{AccountID: session.Account.ID, Email: session.Account.Email, Role: session.Account.Role}, nil
}

func (s *Service) CurrentChallenge(ctx context.Context, token string) (Challenge, error) {
	session, err := s.loadSession(ctx, token)
	if err != nil {
		return Challenge{}, err
	}
	if session.PartialExpiresAt == nil || !session.Account.TOTPRequired || !session.Account.Enabled {
		return Challenge{}, ErrSession
	}
	next := LoginTOTP
	if !session.Account.TOTPEnrolled {
		next = SetupTOTP
	}
	return Challenge{Next: next}, nil
}

func (s *Service) ListStories(ctx context.Context, token string, filter StoryFilter) ([]Story, error) {
	if _, err := s.CurrentUser(ctx, token); err != nil {
		return nil, err
	}
	if filter.After.IsZero() {
		filter.After = s.now().Add(-24 * time.Hour)
	}
	return s.store.ListStories(ctx, filter)
}

func (s *Service) TouchSession(ctx context.Context, token string) error {
	if _, err := s.CurrentUser(ctx, token); err != nil {
		return err
	}
	hash := hashSessionToken(token)
	return s.store.TouchSession(ctx, hash[:], s.now())
}

func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	hash := hashSessionToken(token)
	return s.store.DeleteSession(ctx, hash[:])
}

func (s *Service) recordFailedLogin(ctx context.Context, accountID int64, now time.Time) error {
	locked, err := s.store.RecordFailedLogin(ctx, accountID, now)
	if err != nil {
		return err
	}
	logLoginFailure(accountID)
	if locked {
		slog.Warn("account locked after failed sign-ins", "event", "account_lockout", "account_id", accountID, "outcome", "locked")
	}
	return nil
}

func logLoginFailure(accountID int64) {
	slog.Info("sign-in failed", "event", "login_failure", "account_id", accountID, "outcome", "failure")
}

func (s *Service) loadSession(ctx context.Context, token string) (Session, error) {
	if token == "" {
		return Session{}, ErrSession
	}
	hash := hashSessionToken(token)
	return s.store.LoadSession(ctx, hash[:], s.now())
}

func validateTOTP(code, secret string, now time.Time) (int64, bool) {
	if len(code) != 6 {
		return -1, false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return -1, false
		}
	}
	opts := totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	valid, err := totp.ValidateCustom(code, secret, now, opts)
	if err != nil || !valid {
		return -1, false
	}
	currentStep := now.Unix() / int64(opts.Period)
	acceptedStep := int64(-1)
	for step := currentStep - int64(opts.Skew); step <= currentStep+int64(opts.Skew); step++ {
		if step < 0 {
			continue
		}
		candidate, err := totp.GenerateCodeCustom(
			secret,
			time.Unix(step*int64(opts.Period), 0),
			opts,
		)
		if err == nil && subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 && step > acceptedStep {
			acceptedStep = step
		}
	}
	return acceptedStep, acceptedStep >= 0
}

func hashSessionToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validEmail(email string) bool {
	parsed, err := mail.ParseAddress(email)
	return len(email) <= 254 && err == nil && parsed.Address == email
}

func isLocked(lockedUntil *time.Time, now time.Time) bool {
	return lockedUntil != nil && lockedUntil.After(now)
}
