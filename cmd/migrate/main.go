package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/applog"
	"github.com/Dano-SanDog/good-morning-breach/internal/store/postgres"
)

const defaultDatabaseURL = "host=127.0.0.1 dbname=good_morning_breach sslmode=disable"

func main() {
	if err := applog.Configure(); err != nil {
		fmt.Fprintf(os.Stderr, "configure application logs: %v\n", err)
		os.Exit(1)
	}
	if err := run(); err != nil {
		slog.Error("database migration failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	databaseURL := os.Getenv("GB_MIGRATION_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = defaultDatabaseURL
	}
	pool, err := postgres.OpenLocalPool(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	return postgres.Migrate(ctx, pool)
}
