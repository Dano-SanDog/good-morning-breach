package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/applog"
	"github.com/Dano-SanDog/good-morning-breach/internal/egress"
	"github.com/Dano-SanDog/good-morning-breach/internal/httpserver"
	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
	"github.com/Dano-SanDog/good-morning-breach/internal/secrets"
	"github.com/Dano-SanDog/good-morning-breach/internal/store/postgres"
)

const defaultDatabaseURL = "host=127.0.0.1 dbname=good_morning_breach user=gb_app sslmode=disable"

func main() {
	if err := applog.Configure(); err != nil {
		fmt.Fprintf(os.Stderr, "configure application logs: %v\n", err)
		os.Exit(1)
	}
	certFile := os.Getenv("GB_TLS_CERT_FILE")
	keyFile := os.Getenv("GB_TLS_KEY_FILE")
	if certFile == "" || keyFile == "" {
		slog.Error("GB_TLS_CERT_FILE and GB_TLS_KEY_FILE are required")
		os.Exit(1)
	}
	if err := httpserver.ValidatePrivateKeyFile(keyFile); err != nil {
		slog.Error("TLS private key permissions are invalid", "error", err)
		os.Exit(1)
	}

	startupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	databaseURL := os.Getenv("GB_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = defaultDatabaseURL
	}
	pool, err := postgres.OpenLocalPool(startupCtx, databaseURL)
	if err != nil {
		slog.Error("connect to local database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	dataKey, err := secrets.LoadDataKey()
	if err != nil {
		slog.Error("load application data key", "error", err)
		os.Exit(1)
	}
	identityStore := postgres.NewIdentityStore(pool)
	identityService, err := identity.NewService(identityStore, dataKey, egress.NewHTTPClient())
	if err != nil {
		slog.Error("configure identity service", "error", err)
		os.Exit(1)
	}
	assets, err := httpserver.EmbeddedAssets()
	if err != nil {
		slog.Error("load client assets; run npm run build first", "error", err)
		os.Exit(1)
	}
	server, err := httpserver.NewApplication(identityService, assets)
	if err != nil {
		slog.Error("configure HTTPS server", "error", err)
		os.Exit(1)
	}

	slog.Info("starting local HTTPS server", "address", server.Addr)
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("HTTPS server stopped", "error", err)
		os.Exit(1)
	}
}
