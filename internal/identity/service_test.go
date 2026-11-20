package identity

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPasswordLoginCreatesAuthenticatedSession(t *testing.T) {
	passwordHash, err := HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryIdentityStore{
		account: Account{
			ID:           4,
			Email:        "admin@example.test",
			Role:         "admin",
			PasswordHash: passwordHash,
			Enabled:      true,
		},
		sessions: make(map[string]Session),
	}
	service, err := NewService(store, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.PasswordLogin(context.Background(), "admin@example.test", "a sufficiently long password", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.User == nil || result.User.Email != "admin@example.test" {
		t.Fatalf("password-only login result = %#v", result)
	}
	if _, err := service.CurrentUser(context.Background(), result.Token); err != nil {
		t.Fatalf("password-only session is not authenticated: %v", err)
	}
}

func TestPasswordLoginFailureLogsOneRedactedSecurityEvent(t *testing.T) {
	passwordHash, err := HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryIdentityStore{
		account: Account{
			ID:           9,
			Email:        "admin@example.test",
			PasswordHash: passwordHash,
			Enabled:      true,
		},
		sessions: make(map[string]Session),
	}
	service, err := NewService(store, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(previousLogger)

	password := "incorrect password"
	if _, err := service.PasswordLogin(context.Background(), "admin@example.test", password, ""); !errors.Is(err, ErrCredentials) {
		t.Fatalf("login error = %v; want generic credential error", err)
	}
	record := output.String()
	if strings.Count(record, "\n") != 1 ||
		!strings.Contains(record, `"event":"login_failure"`) ||
		!strings.Contains(record, `"account_id":9`) ||
		!strings.Contains(record, `"outcome":"failure"`) {
		t.Fatalf("failure event was not logged exactly once: %q", record)
	}
	if strings.Contains(record, password) || strings.Contains(record, "password") {
		t.Fatalf("login log contains credential data: %q", record)
	}
}

func TestAdminAccountManagementRequiresAdminAndProtectsCurrentAccount(t *testing.T) {
	adminService, adminStore, adminToken := serviceWithAuthenticatedAccount(t, "admin")
	adminStore.managedAccounts = []ManagedAccount{{
		ID: 2, Email: "user@example.test", Role: "user", Enabled: true,
	}}
	accounts, err := adminService.ListAccounts(context.Background(), adminToken)
	if err != nil || len(accounts) != 1 || accounts[0].ID != 2 {
		t.Fatalf("ListAccounts() = %#v, %v", accounts, err)
	}

	demote := "user"
	if err := adminService.UpdateAccount(context.Background(), adminToken, 1, &demote, nil); !errors.Is(err, ErrSelfManagement) {
		t.Fatalf("self-demotion error = %v; want ErrSelfManagement", err)
	}
	disable := false
	if err := adminService.UpdateAccount(context.Background(), adminToken, 1, nil, &disable); !errors.Is(err, ErrSelfManagement) {
		t.Fatalf("self-disable error = %v; want ErrSelfManagement", err)
	}
	if err := adminService.DeleteAccount(context.Background(), adminToken, 1); !errors.Is(err, ErrSelfManagement) {
		t.Fatalf("self-deletion error = %v; want ErrSelfManagement", err)
	}

	userService, _, userToken := serviceWithAuthenticatedAccount(t, "user")
	if _, err := userService.ListAccounts(context.Background(), userToken); !errors.Is(err, ErrAdminRequired) {
		t.Fatalf("non-admin account listing error = %v; want ErrAdminRequired", err)
	}
	if _, err := userService.CreateAccount(context.Background(), userToken, "user2@example.test", "a sufficiently long password", "user"); !errors.Is(err, ErrAdminRequired) {
		t.Fatalf("non-admin account creation error = %v; want ErrAdminRequired", err)
	}
}

func TestCreateAccountValidatesEmailAndRoleBeforePasswordCheck(t *testing.T) {
	service, _, token := serviceWithAuthenticatedAccount(t, "admin")
	if _, err := service.CreateAccount(context.Background(), token, "not-an-email", "short", "user"); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("invalid email error = %v; want ErrInvalidEmail", err)
	}
	if _, err := service.CreateAccount(context.Background(), token, "user@example.test", "short", "owner"); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("invalid role error = %v; want ErrInvalidRole", err)
	}
}

func TestSourceHealthWarningsAndAuthorization(t *testing.T) {
	service, store, token := serviceWithAuthenticatedAccount(t, "admin")
	now := time.Now().UTC()
	service.now = func() time.Time { return now }
	atThreshold := now.Add(-24 * time.Hour)
	recent := now.Add(-24*time.Hour + time.Second)
	old := now.Add(-30 * time.Hour)
	store.sourceStatuses = []SourceStatus{
		{Name: "threshold", Enabled: true, FailingSince: &atThreshold},
		{Name: "recent failure", Enabled: true, FailingSince: &recent},
		{Name: "disabled", Enabled: false, FailingSince: &old},
		{Name: "no failure", Enabled: true},
	}
	statuses, err := service.ListSourceStatuses(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []bool{true, false, false, false} {
		if statuses[i].Warning != want {
			t.Errorf("%s warning = %v; want %v", statuses[i].Name, statuses[i].Warning, want)
		}
	}
	userService, _, userToken := serviceWithAuthenticatedAccount(t, "user")
	if _, err := userService.ListSourceStatuses(context.Background(), userToken); !errors.Is(err, ErrAdminRequired) {
		t.Fatalf("user source health error = %v", err)
	}
	if _, err := service.ListSourceStatuses(context.Background(), ""); !errors.Is(err, ErrSession) {
		t.Fatalf("unauthenticated source health error = %v", err)
	}
}

func TestAlertSettingsValidationAndAccountIsolation(t *testing.T) {
	service, store, firstToken := serviceWithAuthenticatedAccount(t, "user")
	valid := AlertSettings{Enabled: true, Time: "07:00", TimeZone: "America/Los_Angeles",
		Days: []int16{0, 1, 2, 3, 4, 5, 6}, MinimumRisk: "Medium"}
	if err := service.SaveAlertSettings(context.Background(), firstToken, valid); err != nil {
		t.Fatal(err)
	}
	secondService, secondStore, secondToken := serviceWithAuthenticatedAccount(t, "user")
	secondStore.account.ID = 2
	secondStore.alertSettings = store.alertSettings
	other := valid
	other.Time = "08:30"
	if err := secondService.SaveAlertSettings(context.Background(), secondToken, other); err != nil {
		t.Fatal(err)
	}
	saved, err := service.GetAlertSettings(context.Background(), firstToken)
	if err != nil || saved.Time != "07:00" || store.alertSettings[2].Time != "08:30" {
		t.Fatalf("settings were not isolated: first=%+v second=%+v err=%v", saved, store.alertSettings[2], err)
	}
	for _, invalid := range []AlertSettings{
		{Time: "7:00", TimeZone: valid.TimeZone, Days: valid.Days, MinimumRisk: "Medium"},
		{Time: "07:00", TimeZone: "Mars/Base", Days: valid.Days, MinimumRisk: "Medium"},
		{Time: "07:00", TimeZone: "Local", Days: valid.Days, MinimumRisk: "Medium"},
		{Time: "07:00", TimeZone: valid.TimeZone, Days: []int16{1, 1}, MinimumRisk: "Medium"},
		{Time: "07:00", TimeZone: valid.TimeZone, Days: []int16{7}, MinimumRisk: "Medium"},
		{Time: "07:00", TimeZone: valid.TimeZone, Days: nil, MinimumRisk: "Medium"},
		{Time: "07:00", TimeZone: valid.TimeZone, Days: valid.Days, MinimumRisk: "Severe"},
	} {
		if err := service.SaveAlertSettings(context.Background(), firstToken, invalid); !errors.Is(err, ErrInvalidAlertSettings) {
			t.Errorf("invalid settings %+v: %v", invalid, err)
		}
	}
	if store.alertSettings[1].Time != "07:00" {
		t.Fatal("invalid request changed saved settings")
	}
	if err := service.SaveAlertSettings(context.Background(), "", valid); !errors.Is(err, ErrSession) {
		t.Fatalf("unauthenticated save = %v", err)
	}
}

func serviceWithAuthenticatedAccount(t *testing.T, role string) (*Service, *memoryIdentityStore, string) {
	t.Helper()
	store := &memoryIdentityStore{
		account: Account{
			ID:      1,
			Email:   "admin@example.test",
			Role:    role,
			Enabled: true,
		},
		sessions: make(map[string]Session),
	}
	token := "valid-test-session-token"
	now := time.Now()
	tokenHash := hashSessionToken(token)
	store.sessions[hex.EncodeToString(tokenHash[:])] = Session{
		Account:    store.account,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(time.Hour),
	}
	service, err := NewService(store, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	return service, store, token
}

type memoryIdentityStore struct {
	resetTarget     int64
	account         Account
	sessions        map[string]Session
	failures        int
	managedAccounts []ManagedAccount
	adminAudit      []AdminAuditRecord
	sourceStatuses  []SourceStatus
	alertSettings   map[int64]AlertSettings
	nextAccountID   int64
}

func (s *memoryIdentityStore) CreateAdmin(context.Context, string, string) (int64, error) {
	return 1, nil
}

func (s *memoryIdentityStore) ListAccounts(context.Context) ([]ManagedAccount, error) {
	return s.managedAccounts, nil
}

func (s *memoryIdentityStore) CreateAccount(
	_ context.Context,
	_ int64,
	email, _, role string,
) (ManagedAccount, error) {
	s.nextAccountID++
	account := ManagedAccount{
		ID: s.nextAccountID, Email: email, Role: role, Enabled: true, CreatedAt: time.Now(),
	}
	s.managedAccounts = append(s.managedAccounts, account)
	return account, nil
}

func (s *memoryIdentityStore) UpdateAccount(
	_ context.Context,
	_, targetID int64,
	role *string,
	enabled *bool,
) error {
	for index := range s.managedAccounts {
		if s.managedAccounts[index].ID == targetID {
			if role != nil {
				s.managedAccounts[index].Role = *role
			}
			if enabled != nil {
				s.managedAccounts[index].Enabled = *enabled
			}
			return nil
		}
	}
	return ErrNotFound
}

func (s *memoryIdentityStore) DeleteAccount(_ context.Context, _, targetID int64) error {
	for index := range s.managedAccounts {
		if s.managedAccounts[index].ID == targetID {
			s.managedAccounts = append(s.managedAccounts[:index], s.managedAccounts[index+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

func (s *memoryIdentityStore) ListAdminAudit(context.Context) ([]AdminAuditRecord, error) {
	return s.adminAudit, nil
}

func (s *memoryIdentityStore) ListSourceStatuses(context.Context) ([]SourceStatus, error) {
	return s.sourceStatuses, nil
}
func (s *memoryIdentityStore) GetAlertSettings(_ context.Context, accountID int64) (AlertSettings, error) {
	return s.alertSettings[accountID], nil
}
func (s *memoryIdentityStore) SaveAlertSettings(_ context.Context, accountID int64, settings AlertSettings) error {
	if s.alertSettings == nil {
		s.alertSettings = make(map[int64]AlertSettings)
	}
	s.alertSettings[accountID] = settings
	return nil
}

func (s *memoryIdentityStore) AccountByEmail(_ context.Context, email string) (Account, error) {
	if email != s.account.Email {
		return Account{}, ErrNotFound
	}
	return s.account, nil
}

func (s *memoryIdentityStore) RecordFailedLogin(_ context.Context, _ int64, _ time.Time) (bool, error) {
	s.failures++
	return false, nil
}

func (s *memoryIdentityStore) CreateSession(
	_ context.Context,
	previousHash, tokenHash []byte,
	_ int64,
	now time.Time,
) error {
	if len(previousHash) > 0 {
		delete(s.sessions, hex.EncodeToString(previousHash))
	}
	s.sessions[hex.EncodeToString(tokenHash)] = Session{
		Account:    s.account,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(8 * time.Hour),
	}
	return nil
}

func (s *memoryIdentityStore) LoadSession(_ context.Context, tokenHash []byte, now time.Time) (Session, error) {
	session, ok := s.sessions[hex.EncodeToString(tokenHash)]
	if !ok || !session.ExpiresAt.After(now) ||
		now.Sub(session.LastSeenAt) > 30*time.Minute {
		return Session{}, ErrSession
	}
	session.Account = s.account
	return session, nil
}

func (s *memoryIdentityStore) TouchSession(_ context.Context, tokenHash []byte, now time.Time) error {
	key := hex.EncodeToString(tokenHash)
	session, ok := s.sessions[key]
	if !ok {
		return ErrSession
	}
	session.LastSeenAt = now
	s.sessions[key] = session
	return nil
}

func (s *memoryIdentityStore) DeleteSession(_ context.Context, tokenHash []byte) error {
	delete(s.sessions, hex.EncodeToString(tokenHash))
	return nil
}

func (s *memoryIdentityStore) ListStories(context.Context, StoryFilter) ([]Story, error) {
	return []Story{}, nil
}

var _ Store = (*memoryIdentityStore)(nil)
