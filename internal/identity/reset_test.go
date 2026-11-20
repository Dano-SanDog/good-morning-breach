package identity

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeResetStore struct {
	tokens   map[string]time.Time
	created  []time.Time
	password string
}

func (f *fakeResetStore) CreateResetToken(_ context.Context, email string, hash []byte, now, expires time.Time, limit int, window time.Duration) (string, bool, error) {
	if email != "user@example.test" {
		return "", false, nil
	}
	recent := 0
	for _, created := range f.created {
		if created.After(now.Add(-window)) {
			recent++
		}
	}
	if recent >= limit {
		return "", false, nil
	}
	f.created = append(f.created, now)
	f.tokens[string(hash)] = expires
	return email, true, nil
}

func (f *fakeResetStore) ConsumeResetToken(_ context.Context, hash []byte, passwordHash string, now time.Time) (int64, error) {
	expires, ok := f.tokens[string(hash)]
	if !ok || !expires.After(now) {
		return 0, ErrResetToken
	}
	f.tokens = map[string]time.Time{}
	f.password = passwordHash
	return 1, nil
}

type fakeMailer struct {
	mu   sync.Mutex
	sent []string
}

func (m *fakeMailer) SendText(_ context.Context, to, _, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, to+"\n"+text)
	return nil
}

type emptyRange struct{}

func (emptyRange) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

func newResetService(t *testing.T) (*Service, *fakeResetStore, *fakeMailer, *time.Time) {
	t.Helper()
	service, err := NewService(&memoryIdentityStore{}, &http.Client{Transport: emptyRange{}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	service.now = func() time.Time { return now }
	store := &fakeResetStore{tokens: map[string]time.Time{}}
	mailer := &fakeMailer{}
	service.EnablePasswordReset(store, mailer, "https://localhost:8443")
	service.reset.async = func(f func()) { f() }
	return service, store, mailer, &now
}

func tokenFrom(t *testing.T, message string) string {
	t.Helper()
	_, token, ok := strings.Cut(message, "/#reset=")
	if !ok {
		t.Fatal("no reset link in message")
	}
	token, _, _ = strings.Cut(token, "\n")
	return token
}

func TestPasswordResetSingleUseAndExpiry(t *testing.T) {
	service, store, mailer, now := newResetService(t)
	ctx := context.Background()
	if err := service.RequestPasswordReset(ctx, " USER@example.test "); err != nil {
		t.Fatal(err)
	}
	if len(mailer.sent) != 1 {
		t.Fatalf("sent %d emails", len(mailer.sent))
	}
	token := tokenFrom(t, mailer.sent[0])
	if _, ok := store.tokens[token]; ok {
		t.Fatal("raw token stored")
	}
	if err := service.ResetPassword(ctx, token, "short"); !errors.Is(err, ErrPasswordLength) {
		t.Fatalf("short password error = %v", err)
	}
	if err := service.ResetPassword(ctx, token, "a brand new long password"); err != nil {
		t.Fatal(err)
	}
	if store.password == "" || strings.Contains(store.password, "brand") {
		t.Fatal("password not hashed")
	}
	if err := service.ResetPassword(ctx, token, "another long password!"); !errors.Is(err, ErrResetToken) {
		t.Fatalf("reuse error = %v", err)
	}

	if err := service.RequestPasswordReset(ctx, "user@example.test"); err != nil {
		t.Fatal(err)
	}
	late := tokenFrom(t, mailer.sent[1])
	*now = now.Add(31 * time.Minute)
	if err := service.ResetPassword(ctx, late, "a brand new long password"); !errors.Is(err, ErrResetToken) {
		t.Fatalf("expired error = %v", err)
	}
}

func TestPasswordResetRequestIsGenericAndRateLimited(t *testing.T) {
	service, _, mailer, _ := newResetService(t)
	ctx := context.Background()
	if err := service.RequestPasswordReset(ctx, "nobody@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := service.RequestPasswordReset(ctx, "not an address"); err != nil {
		t.Fatal(err)
	}
	if len(mailer.sent) != 0 {
		t.Fatal("email sent for unknown address")
	}
	for i := 0; i < 4; i++ {
		if err := service.RequestPasswordReset(ctx, "user@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	if len(mailer.sent) != 3 {
		t.Fatalf("sent %d emails, want 3", len(mailer.sent))
	}
}
