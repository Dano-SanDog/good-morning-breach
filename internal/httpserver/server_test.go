package httpserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
	"github.com/gin-gonic/gin"
)

func TestNewConfiguresLocalTLSAndTimeouts(t *testing.T) {
	server, err := New()
	if err != nil {
		t.Fatal(err)
	}

	if server.Addr != "127.0.0.1:8443" {
		t.Fatalf("server address = %q", server.Addr)
	}
	if server.TLSConfig == nil || server.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS minimum version = %v", server.TLSConfig)
	}
	for name, timeout := range map[string]time.Duration{
		"ReadHeaderTimeout": server.ReadHeaderTimeout,
		"ReadTimeout":       server.ReadTimeout,
		"WriteTimeout":      server.WriteTimeout,
		"IdleTimeout":       server.IdleTimeout,
	} {
		if timeout <= 0 {
			t.Errorf("%s = %s; want a non-zero timeout", name, timeout)
		}
	}
}

func TestValidatePrivateKeyFileRequiresRegular0600File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-key.pem")
	if err := os.WriteFile(path, []byte("not a real key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateKeyFile(path); err != nil {
		t.Fatalf("valid private file rejected: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateKeyFile(path); err == nil {
		t.Fatal("group-readable private key was accepted")
	}
}

func TestSessionCookieUsesHostOnlySecureAttributes(t *testing.T) {
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	setSessionCookie(context, "test-session-token", 300)

	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookie count = %d; want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookieName || cookie.Value != "test-session-token" ||
		cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != 300 ||
		!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie attributes = %#v", cookie)
	}
}

func TestDecodeStrictJSONRejectsUnknownAndTrailingFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "valid object", body: `{"code":"123456"}`},
		{name: "unknown field", body: `{"code":"123456","token":"secret"}`, want: true},
		{name: "trailing JSON", body: `{"code":"123456"} {}`, want: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			context, _ := gin.CreateTestContext(httptest.NewRecorder())
			context.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testCase.body))
			var request struct {
				Code string `json:"code"`
			}
			err := decodeStrictJSON(context, &request)
			if (err != nil) != testCase.want {
				t.Fatalf("decodeStrictJSON() error = %v; want error %v", err, testCase.want)
			}
		})
	}
}

func TestResponsesIncludeSecurityHeaders(t *testing.T) {
	server, err := New()
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	for name, want := range map[string]string{
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "strict-origin-when-cross-origin",
		"Cross-Origin-Opener-Policy": "same-origin",
		"Cache-Control":              "no-store",
		"Content-Security-Policy":    contentSecurityPolicy,
	} {
		if got := response.Header().Get(name); got != want {
			t.Errorf("%s = %q; want %q", name, got, want)
		}
	}
	for _, name := range []string{"X-Powered-By", "Server", "Strict-Transport-Security"} {
		if got := response.Header().Get(name); got != "" {
			t.Errorf("%s = %q; want absent", name, got)
		}
	}
}

func TestOversizedRequestIsRejectedBeforeHandler(t *testing.T) {
	router, err := newRouter(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	handlerCalled := false
	router.POST("/test", func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusNoContent)
	})

	body := strings.Repeat("x", maxRequestBodyBytes+1)
	request := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d; want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
	if handlerCalled {
		t.Fatal("request handler ran for an oversized body")
	}
}

func TestMutatingRequestRequiresCSRFHeaderAndJSON(t *testing.T) {
	router, err := newRouter(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	router.POST("/mutate", requireCSRF(), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	for _, testCase := range []struct {
		name        string
		contentType string
		csrf        string
		wantStatus  int
	}{
		{name: "missing header", contentType: "application/json", wantStatus: http.StatusForbidden},
		{name: "wrong content type", contentType: "text/plain", csrf: "1", wantStatus: http.StatusForbidden},
		{name: "accepted", contentType: "application/json", csrf: "1", wantStatus: http.StatusNoContent},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/mutate", strings.NewReader("{}"))
			request.Header.Set("Content-Type", testCase.contentType)
			if testCase.csrf != "" {
				request.Header.Set("X-GMB-CSRF", testCase.csrf)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d; want %d", response.Code, testCase.wantStatus)
			}
		})
	}
}

func TestStoriesRequireAnAuthenticatedSession(t *testing.T) {
	service, err := identity.NewService(&unauthenticatedIdentityStore{}, make([]byte, 32), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRouter(service, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newHTTPServer(router)
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://localhost:8443/api/stories", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestAdminEndpointsRequireAnAuthenticatedSession(t *testing.T) {
	service, err := identity.NewService(&unauthenticatedIdentityStore{}, make([]byte, 32), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRouter(service, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}})
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/admin/accounts", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestPasswordOnlyAdminLoginReturnsAuthenticatedSession(t *testing.T) {
	passwordHash, err := identity.HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	store := &passwordOnlyIdentityStore{account: identity.Account{
		ID:           1,
		Email:        "admin@example.test",
		Role:         "admin",
		PasswordHash: passwordHash,
		Enabled:      true,
		TOTPRequired: false,
	}}
	service, err := identity.NewService(store, make([]byte, 32), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRouter(service, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://localhost:8443/api/auth/login",
		strings.NewReader(`{"email":"admin@example.test","password":"a sufficiently long password"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GMB-CSRF", "1")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	var user identity.AuthenticatedUser
	if err := json.NewDecoder(response.Body).Decode(&user); err != nil {
		t.Fatal(err)
	}
	if user.Email != "admin@example.test" || user.Role != "admin" {
		t.Fatalf("login response user = %#v", user)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != 8*60*60 {
		t.Fatalf("password-only session cookie = %#v", cookies)
	}
}

func TestCrossOriginMutationIsRejected(t *testing.T) {
	router, err := newRouter(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	router.POST("/mutate", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	server, err := newHTTPServer(router)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://localhost:8443/mutate", strings.NewReader("{}"))
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want %d", response.Code, http.StatusForbidden)
	}
}

type unauthenticatedIdentityStore struct{}

type passwordOnlyIdentityStore struct {
	unauthenticatedIdentityStore
	account identity.Account
}

func (s *passwordOnlyIdentityStore) AccountByEmail(_ context.Context, email string) (identity.Account, error) {
	if email != s.account.Email {
		return identity.Account{}, identity.ErrNotFound
	}
	return s.account, nil
}
func (*passwordOnlyIdentityStore) CreateSession(context.Context, []byte, []byte, int64, time.Time) error {
	return nil
}

func (*unauthenticatedIdentityStore) CreateAdmin(context.Context, string, string) (int64, error) {
	return 0, errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) ListAccounts(context.Context) ([]identity.ManagedAccount, error) {
	return nil, errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) CreateAccount(context.Context, int64, string, string, string) (identity.ManagedAccount, error) {
	return identity.ManagedAccount{}, errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) UpdateAccount(context.Context, int64, int64, *string, *bool) error {
	return errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) DeleteAccount(context.Context, int64, int64) error {
	return errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) ListAdminAudit(context.Context) ([]identity.AdminAuditRecord, error) {
	return nil, errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) AccountByEmail(context.Context, string) (identity.Account, error) {
	return identity.Account{}, identity.ErrNotFound
}
func (*unauthenticatedIdentityStore) RecordFailedLogin(context.Context, int64, time.Time) (bool, error) {
	return false, errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) CreatePartialSession(context.Context, []byte, []byte, int64, time.Time, time.Time) error {
	return errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) CreateSession(context.Context, []byte, []byte, int64, time.Time) error {
	return errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) LoadSession(context.Context, []byte, time.Time) (identity.Session, error) {
	return identity.Session{}, identity.ErrSession
}
func (*unauthenticatedIdentityStore) TouchSession(context.Context, []byte, time.Time) error {
	return errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) BeginTOTPSetup(context.Context, []byte, int64, []byte, []byte, time.Time) error {
	return errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) CompleteTOTP(context.Context, []byte, []byte, int64, time.Time, bool) (identity.Account, error) {
	return identity.Account{}, errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) DeleteSession(context.Context, []byte) error {
	return errors.New("unexpected call")
}
func (*unauthenticatedIdentityStore) ListStories(context.Context, time.Time) ([]identity.Story, error) {
	return nil, errors.New("unexpected call")
}
