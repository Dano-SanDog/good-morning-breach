package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/analyzer"
	"github.com/Dano-SanDog/good-morning-breach/internal/applog"
	"github.com/Dano-SanDog/good-morning-breach/internal/egress"
	"github.com/Dano-SanDog/good-morning-breach/internal/ingest"
	"github.com/Dano-SanDog/good-morning-breach/internal/store/postgres"
)

const defaultDatabaseURL = "host=127.0.0.1 dbname=good_morning_breach user=gb_app sslmode=disable"

func main() {
	if err := applog.Configure(); err != nil {
		fmt.Fprintf(os.Stderr, "configure application logs: %v\n", err)
		os.Exit(1)
	}
	if err := run(); err != nil {
		slog.Error("collection command failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	databaseURL := os.Getenv("GB_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = defaultDatabaseURL
	}
	pool, err := postgres.OpenLocalPool(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	attackIndex, err := analyzer.NewAttackIndex()
	if err != nil {
		return fmt.Errorf("load pinned MITRE ATT&CK bundle: %w", err)
	}
	store, err := postgres.NewStore(pool, attackIndex)
	if err != nil {
		return fmt.Errorf("configure story store: %w", err)
	}
	if _, err := store.ReanalyzeStories(ctx); err != nil {
		return fmt.Errorf("backfill story analysis: %w", err)
	}
	collector, err := ingest.NewCollector(egress.NewHTTPClient(), store)
	if err != nil {
		return err
	}
	results, runErr := collector.Run(ctx)
	ingest.LogResults(results)
	if runErr != nil {
		return runErr
	}
	return nil
}
