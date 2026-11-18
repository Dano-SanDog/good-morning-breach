package ingest

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

type Runner interface {
	Run(context.Context) ([]Result, error)
}

func RunPeriodically(ctx context.Context, runner Runner, interval time.Duration) error {
	if runner == nil {
		return errors.New("collection runner is required")
	}
	if interval <= 0 {
		return errors.New("collection interval must be positive")
	}

	for {
		if ctx.Err() != nil {
			return nil
		}
		results, err := runner.Run(ctx)
		if ctx.Err() != nil {
			return nil
		}
		LogResults(results)
		if err != nil {
			slog.Error(
				"scheduled collection run failed",
				"event", "collection_run",
				"outcome", "failure",
				"error", err,
			)
		} else if err == nil {
			slog.Info(
				"scheduled collection run completed",
				"event", "collection_run",
				"outcome", "success",
			)
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func LogResults(results []Result) {
	for _, result := range results {
		switch {
		case result.Failure != "":
			slog.Error("source collection failed",
				"event", "collection_source",
				"source_id", result.SourceID,
				"outcome", "failure",
				"reason", result.Failure,
			)
		case result.Skipped:
			slog.Info("source collection skipped",
				"event", "collection_source",
				"source_id", result.SourceID,
				"outcome", "skipped",
				"reason", "poll interval has not elapsed",
			)
		default:
			slog.Info("source collection succeeded",
				"event", "collection_source",
				"source_id", result.SourceID,
				"outcome", "success",
				"items_received", result.ItemsReceived,
				"items_saved", result.ItemsSaved,
				"items_skipped", result.ItemsSkipped,
			)
		}
	}
}
