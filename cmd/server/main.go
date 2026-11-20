package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/alerting"
	"github.com/Dano-SanDog/good-morning-breach/internal/analyzer"
	"github.com/Dano-SanDog/good-morning-breach/internal/applog"
	"github.com/Dano-SanDog/good-morning-breach/internal/egress"
	"github.com/Dano-SanDog/good-morning-breach/internal/httpserver"
	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
	"github.com/Dano-SanDog/good-morning-breach/internal/ingest"
	"github.com/Dano-SanDog/good-morning-breach/internal/secrets"
	"github.com/Dano-SanDog/good-morning-breach/internal/store/postgres"
)

const (
	defaultDatabaseURL      = "host=127.0.0.1 dbname=good_morning_breach user=gb_app sslmode=disable"
	collectionCheckInterval = time.Hour
	alertCheckInterval      = time.Minute
	serverShutdownTimeout   = 10 * time.Second
)

func main() {
	if err := applog.Configure(); err != nil {
		fmt.Fprintf(os.Stderr, "configure application logs: %v\n", err)
		os.Exit(1)
	}
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	certFile := os.Getenv("GB_TLS_CERT_FILE")
	keyFile := os.Getenv("GB_TLS_KEY_FILE")
	if certFile == "" || keyFile == "" {
		return errors.New("GB_TLS_CERT_FILE and GB_TLS_KEY_FILE are required")
	}
	if err := httpserver.ValidatePrivateKeyFile(keyFile); err != nil {
		return fmt.Errorf("TLS private key permissions are invalid: %w", err)
	}

	startupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	databaseURL := os.Getenv("GB_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = defaultDatabaseURL
	}
	pool, err := postgres.OpenLocalPool(startupCtx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to local database: %w", err)
	}
	defer pool.Close()

	attackIndex, err := analyzer.NewAttackIndex()
	if err != nil {
		return fmt.Errorf("load pinned MITRE ATT&CK bundle: %w", err)
	}
	storyStore, err := postgres.NewStore(pool, attackIndex)
	if err != nil {
		return fmt.Errorf("configure story store: %w", err)
	}
	analysisCtx, analysisCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	analyzedStories, err := storyStore.ReanalyzeStories(analysisCtx)
	analysisCancel()
	if err != nil {
		return fmt.Errorf("backfill story analysis: %w", err)
	}
	if analyzedStories > 0 {
		slog.Info("backfilled story analysis", "count", analyzedStories)
	}

	dataKey, err := secrets.LoadDataKey()
	if err != nil {
		return fmt.Errorf("load application data key: %w", err)
	}
	identityStore := postgres.NewIdentityStore(pool)
	identityService, err := identity.NewService(identityStore, dataKey, egress.NewHTTPClient())
	if err != nil {
		return fmt.Errorf("configure identity service: %w", err)
	}
	smtpConfig, smtpConfigured, err := alerting.LoadSMTPConfig()
	if err != nil {
		return fmt.Errorf("configure SMTP: %w", err)
	}
	var sender *alerting.SMTPSender
	if smtpConfigured {
		sender, err = alerting.NewSMTPSender(smtpConfig)
		if err != nil {
			return fmt.Errorf("configure SMTP: %w", err)
		}
		identityService.EnablePasswordReset(identityStore, sender, "https://localhost:8443")
	}
	assets, err := httpserver.EmbeddedAssets()
	if err != nil {
		return fmt.Errorf("load client assets; run npm run build first: %w", err)
	}
	server, err := httpserver.NewApplication(identityService, assets)
	if err != nil {
		return fmt.Errorf("configure HTTPS server: %w", err)
	}

	collector, err := ingest.NewCollector(egress.NewHTTPClient(), storyStore)
	if err != nil {
		return fmt.Errorf("configure RSS collection: %w", err)
	}

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	collectionDone := make(chan struct{})
	go func() {
		defer close(collectionDone)
		if err := ingest.RunPeriodically(runCtx, collector, collectionCheckInterval); err != nil {
			slog.Error("collection scheduler stopped", "event", "collection_scheduler", "outcome", "failure", "error", err)
		}
	}()

	alertsDone := make(chan struct{})
	if sender != nil {
		alertService, err := alerting.NewService(postgres.NewAlertStore(pool), sender)
		if err != nil {
			return fmt.Errorf("configure alert delivery: %w", err)
		}
		go func() {
			defer close(alertsDone)
			if err := alerting.RunPeriodically(runCtx, alertService, alertCheckInterval); err != nil {
				slog.Error("alert scheduler stopped", "event", "alert_scheduler", "outcome", "failure", "error", err)
			}
		}()
		slog.Info("starting alert scheduler", "event", "alert_scheduler", "outcome", "started")
	} else {
		close(alertsDone)
		slog.Warn("GB_SMTP_HOST is not set; morning alerts are disabled", "event", "alert_scheduler", "outcome", "disabled")
	}

	slog.Info(
		"starting collection scheduler",
		"event", "collection_scheduler",
		"outcome", "started",
		"check_interval", collectionCheckInterval.String(),
	)
	slog.Info("starting local HTTPS server", "address", server.Addr)
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServeTLS(certFile, keyFile)
	}()

	select {
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			stop()
			<-collectionDone
			<-alertsDone
			return fmt.Errorf("HTTPS server stopped: %w", err)
		}
		stop()
	case <-runCtx.Done():
		slog.Info("shutdown requested", "event", "server_shutdown", "outcome", "started")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
	defer shutdownCancel()
	shutdownErr := server.Shutdown(shutdownCtx)
	stop()
	<-collectionDone
	<-alertsDone
	if shutdownErr != nil {
		return fmt.Errorf("shut down HTTPS server: %w", shutdownErr)
	}
	return nil
}
