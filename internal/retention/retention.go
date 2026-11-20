// Package retention deletes expired stories (FR-10.1) and alert delivery
// records (FR-10.2) in bounded batches.
package retention

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

const (
	StoryRetention    = 365 * 24 * time.Hour
	DeliveryRetention = 90 * 24 * time.Hour
	BatchSize         = 500
	MaxBatches        = 200
	CheckInterval     = 6 * time.Hour
)

// Store deletes at most limit rows created before cutoff and returns the count.
type Store interface {
	DeleteStoriesBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	DeleteDeliveriesBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error)
}

type Service struct {
	store Store
	now   func() time.Time
}

type Result struct {
	Stories    int64
	Deliveries int64
}

func NewService(store Store) (*Service, error) {
	if store == nil {
		return nil, errors.New("retention store is required")
	}
	return &Service{store: store, now: time.Now}, nil
}

// Run deletes expired rows. Each table is capped at MaxBatches batches per run;
// the next run continues any backlog.
func (s *Service) Run(ctx context.Context) (Result, error) {
	now := s.now()
	var result Result
	var errs []error
	var err error
	if result.Stories, err = drain(ctx, now.Add(-StoryRetention), s.store.DeleteStoriesBefore); err != nil {
		errs = append(errs, fmt.Errorf("delete expired stories: %w", err))
	}
	if result.Deliveries, err = drain(ctx, now.Add(-DeliveryRetention), s.store.DeleteDeliveriesBefore); err != nil {
		errs = append(errs, fmt.Errorf("delete expired delivery records: %w", err))
	}
	return result, errors.Join(errs...)
}

func drain(ctx context.Context, cutoff time.Time, del func(context.Context, time.Time, int) (int64, error)) (int64, error) {
	var total int64
	for i := 0; i < MaxBatches; i++ {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := del(ctx, cutoff, BatchSize)
		total += n
		if err != nil {
			return total, err
		}
		if n < BatchSize {
			break
		}
	}
	return total, nil
}

// RunPeriodically runs retention immediately and then every interval until ctx ends.
func RunPeriodically(ctx context.Context, s *Service, interval time.Duration) error {
	if s == nil {
		return errors.New("retention service is required")
	}
	if interval <= 0 {
		return errors.New("retention interval must be positive")
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		result, err := s.Run(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			slog.Error("retention run failed", "event", "retention_run", "outcome", "failure", "error", err)
		} else {
			slog.Info("retention run completed", "event", "retention_run", "outcome", "success",
				"stories_deleted", result.Stories, "deliveries_deleted", result.Deliveries)
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
