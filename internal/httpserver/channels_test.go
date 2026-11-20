package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/alerting"
	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
)

type fakeContactStore struct {
	record  alerting.ContactRecord
	account int64
}

func (s *fakeContactStore) ReserveMessage(context.Context, int64, alerting.Quota, time.Time) (bool, error) {
	return true, nil
}
func (s *fakeContactStore) DisableSMS(context.Context, int64) error { return nil }
func (s *fakeContactStore) GetContacts(_ context.Context, id int64) (alerting.ContactRecord, error) {
	s.account = id
	return s.record, nil
}
func (s *fakeContactStore) SaveChannels(_ context.Context, id int64, _, _, _ bool) error {
	s.account = id
	return nil
}
func (s *fakeContactStore) SaveSlackWebhook(context.Context, int64, []byte) error { return nil }
func (s *fakeContactStore) StartPhoneVerification(context.Context, int64, string, []byte, time.Time, time.Time) error {
	return nil
}
func (s *fakeContactStore) GetVerification(context.Context, int64) (alerting.Verification, bool, error) {
	return alerting.Verification{}, false, nil
}
func (s *fakeContactStore) RecordFailedCode(context.Context, int64) error { return nil }
func (s *fakeContactStore) ConfirmPhone(context.Context, int64, string, time.Time) error {
	return nil
}

type fakeBox struct{}

func (fakeBox) Open(string, int64, []byte) ([]byte, error) { return nil, nil }
func (fakeBox) Seal(_ string, _ int64, p []byte) ([]byte, error) {
	return p, nil
}
func (fakeBox) Digest(string, int64, string) []byte { return []byte("d") }

func TestAlertChannelEndpoints(t *testing.T) {
	identityStore := &sourceHealthIdentityStore{role: "user"}
	service, err := identity.NewService(identityStore, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeContactStore{record: alerting.ContactRecord{
		EmailEnabled: true, SlackWebhookSealed: []byte("secret-hook"),
	}}
	slack := alerting.NewSlackChannel(http.DefaultClient, fakeBox{})
	contacts, err := alerting.NewContactService(store, fakeBox{}, slack, nil)
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRouter(service, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("x")}}, contacts)
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path, body string, csrf, session bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if csrf {
			request.Header.Set("X-GMB-CSRF", "1")
		}
		if session {
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "test-session"})
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	if r := do(http.MethodGet, "/api/alert-channels", "", false, false); r.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated view = %d", r.Code)
	}
	if r := do(http.MethodPut, "/api/alert-channels", `{"emailEnabled":true,"slackEnabled":false,"smsEnabled":false}`, false, true); r.Code != http.StatusForbidden {
		t.Errorf("missing CSRF = %d", r.Code)
	}
	view := do(http.MethodGet, "/api/alert-channels", "", false, true)
	if view.Code != http.StatusOK || strings.Contains(view.Body.String(), "secret-hook") ||
		!strings.Contains(view.Body.String(), `"slackWebhookSaved":true`) {
		t.Errorf("view = %d %s", view.Code, view.Body.String())
	}
	for _, tc := range []struct {
		path, body string
		want       int
	}{
		{"/api/alert-channels", `{"emailEnabled":true,"slackEnabled":false,"smsEnabled":false,"accountId":2}`, http.StatusBadRequest},
		{"/api/alert-channels", `{"emailEnabled":true}`, http.StatusBadRequest},
		{"/api/alert-channels", `{"emailEnabled":true,"slackEnabled":false,"smsEnabled":false}`, http.StatusNoContent},
		{"/api/alert-channels/slack", `{"webhook":"https://evil.example/services/x"}`, http.StatusBadRequest},
		{"/api/alert-channels/phone", `{"phone":"5551234"}`, http.StatusServiceUnavailable},
		{"/api/alert-channels/phone", `{"phone":"+15551234567"}`, http.StatusServiceUnavailable},
		{"/api/alert-channels/phone/verify", `{"code":"1234567"}`, http.StatusBadRequest},
	} {
		method := http.MethodPost
		if tc.path == "/api/alert-channels" {
			method = http.MethodPut
		}
		if r := do(method, tc.path, tc.body, true, true); r.Code != tc.want {
			t.Errorf("%s %s = %d; want %d (%s)", tc.path, tc.body, r.Code, tc.want, r.Body.String())
		}
	}
	if store.account != 1 {
		t.Errorf("account = %d; want session account 1", store.account)
	}
}
