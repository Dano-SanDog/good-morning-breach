package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/egress"
	"github.com/Dano-SanDog/good-morning-breach/internal/ingest"
	"github.com/Dano-SanDog/good-morning-breach/internal/store/postgres"
)

const defaultDatabaseURL = "host=127.0.0.1 dbname=good_morning_breach user=gb_app sslmode=disable"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
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

	store := postgres.NewStore(pool)
	collector, err := ingest.NewCollector(egress.NewHTTPClient(), store)
	if err != nil {
		return err
	}
	results, runErr := collector.Run(ctx)
	for _, result := range results {
		if result.Failure != "" {
			slog.Error("source collection failed", "source_id", result.SourceID, "cause", result.Failure)
		} else if result.Skipped {
			slog.Info("source collection skipped", "source_id", result.SourceID, "reason", "poll interval has not elapsed")
		} else {
			slog.Info("source collection succeeded",
				"source_id", result.SourceID,
				"items_received", result.ItemsReceived,
				"items_saved", result.ItemsSaved,
				"items_skipped", result.ItemsSkipped,
			)
		}
	}
	if runErr != nil {
		return runErr
	}
	return nil
}
