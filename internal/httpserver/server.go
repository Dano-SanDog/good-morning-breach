package httpserver

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
	"github.com/gin-gonic/gin"
)

const maxRequestBodyBytes = 64 << 10

const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"

func New() (*http.Server, error) {
	router, err := newRouter(nil, nil)
	if err != nil {
		return nil, err
	}
	return newHTTPServer(router)
}

func NewApplication(service *identity.Service, assets fs.FS) (*http.Server, error) {
	if service == nil {
		return nil, errors.New("identity service is required")
	}
	if assets == nil {
		return nil, errors.New("embedded client assets are required")
	}
	if _, err := fs.Stat(assets, "index.html"); err != nil {
		return nil, fmt.Errorf("client bundle is unavailable; run npm run build: %w", err)
	}
	router, err := newRouter(service, assets)
	if err != nil {
		return nil, err
	}
	return newHTTPServer(router)
}

func ValidatePrivateKeyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect TLS private key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return errors.New("TLS private key must be a regular 0600 file")
	}
	return nil
}

func newHTTPServer(handler http.Handler) (*http.Server, error) {
	protection := http.NewCrossOriginProtection()
	protectedHandler := protection.Handler(handler)
	return &http.Server{
		Addr:              "127.0.0.1:8443",
		Handler:           protectedHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}, nil
}

func newRouter(service *identity.Service, assets fs.FS) (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(recoveryMiddleware(), correlationMiddleware(), securityHeaders(), limitRequestBody())

	if err := router.SetTrustedProxies(nil); err != nil {
		return nil, fmt.Errorf("disable trusted proxies: %w", err)
	}
	if service != nil {
		registerRoutes(router, service, assets)
	}
	router.NoRoute(func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Not found."})
	})
	return router, nil
}

func recoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recovered := recover(); recovered != nil {
				requestID := requestCorrelationID(c)
				slog.Error(
					"request handler panic",
					"correlation_id", requestID,
					"panic_type", fmt.Sprintf("%T", recovered),
					"stack", string(debug.Stack()),
				)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error":         "An unexpected error occurred.",
					"correlationId": requestID,
				})
			}
		}()
		c.Next()
	}
}

func correlationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := rand.Text()
		c.Set("correlation_id", id)
		c.Header("X-Correlation-ID", id)
		c.Next()
	}
}

func requestCorrelationID(c *gin.Context) string {
	if id, exists := c.Get("correlation_id"); exists {
		if value, ok := id.(string); ok {
			return value
		}
	}
	return "unavailable"
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.Writer.Header()
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		header.Set("Cache-Control", "no-store")
		header.Set("Content-Security-Policy", contentSecurityPolicy)
		header.Del("X-Powered-By")
		header.Del("Server")
		c.Next()
	}
}

func limitRequestBody() gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxRequestBodyBytes))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Request body is too large."})
				return
			}
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
			return
		}

		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		c.Next()
	}
}
