package httpserver

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	server, err := New()
	if err != nil {
		t.Fatal(err)
	}

	router, ok := server.Handler.(*gin.Engine)
	if !ok {
		t.Fatal("server handler is not a Gin engine")
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
