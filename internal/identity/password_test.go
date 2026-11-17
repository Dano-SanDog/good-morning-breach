package identity

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPasswordHashUsesIndependentArgon2idSalts(t *testing.T) {
	first, err := HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash parameters are not encoded: %q", first)
	}
	if first == second {
		t.Fatal("identical passwords unexpectedly produced identical hashes")
	}
	if !VerifyPassword(first, "a sufficiently long password") {
		t.Fatal("correct password did not verify")
	}
	if VerifyPassword(first, "a different password") {
		t.Fatal("incorrect password verified")
	}
}

func TestPasswordLengthCountsUnicodeCodePoints(t *testing.T) {
	if err := ValidateNewPassword(context.Background(), http.DefaultClient, strings.Repeat("x", 11)); !errors.Is(err, ErrPasswordLength) {
		t.Fatalf("11-character password error = %v", err)
	}
	if !validPasswordLength(strings.Repeat("é", 64)) {
		t.Fatal("64-code-point password was rejected")
	}
}

func TestHIBPRangeCheckUsesKAnonymityAndIgnoresPaddedEntries(t *testing.T) {
	password := "correct horse battery staple"
	digest := sha1.Sum([]byte(password))
	encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
	requestObserved := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestObserved = true
		if r.URL.Path != "/range/"+encoded[:5] {
			t.Errorf("range path = %q", r.URL.Path)
		}
		if r.Header.Get("Add-Padding") != "true" {
			t.Errorf("Add-Padding = %q", r.Header.Get("Add-Padding"))
		}
		_, _ = w.Write([]byte(encoded[5:] + ":0\n" + strings.Repeat("A", 35) + ":0\n"))
	}))
	defer server.Close()

	if err := checkHIBPAt(context.Background(), server.Client(), password, server.URL+"/range/"); err != nil {
		t.Fatalf("zero-count padded response was rejected: %v", err)
	}
	if !requestObserved {
		t.Fatal("HIBP range endpoint was not called")
	}
}

func TestHIBPRejectsBreachedPasswordAndFailsClosed(t *testing.T) {
	password := "correct horse battery staple"
	digest := sha1.Sum([]byte(password))
	encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
	breached := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(encoded[5:] + ":1\n"))
	}))
	defer breached.Close()
	if err := checkHIBPAt(context.Background(), breached.Client(), password, breached.URL+"/"); !errors.Is(err, ErrPasswordBreached) {
		t.Fatalf("breached password error = %v", err)
	}

	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer unavailable.Close()
	if err := checkHIBPAt(context.Background(), unavailable.Client(), password, unavailable.URL+"/"); err == nil {
		t.Fatal("unavailable HIBP response did not fail closed")
	}
}
