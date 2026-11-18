package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/analyzer"
	"github.com/Dano-SanDog/good-morning-breach/internal/ingest"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) ListEnabledSources(ctx context.Context) ([]ingest.Source, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()

	rows, err := s.pool.Query(queryCtx, `SELECT
		id, name, address, license_name, license_url, permitted_use,
		attribution, content_policy, poll_interval_seconds, last_success_at
		FROM data_sources
		WHERE enabled
		ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query enabled sources: %w", err)
	}
	defer rows.Close()

	var sources []ingest.Source
	for rows.Next() {
		var source ingest.Source
		var pollIntervalSeconds int64
		var lastSuccessAt *time.Time
		if err := rows.Scan(
			&source.ID,
			&source.Name,
			&source.Address,
			&source.LicenseName,
			&source.LicenseURL,
			&source.PermittedUse,
			&source.Attribution,
			&source.ContentPolicy,
			&pollIntervalSeconds,
			&lastSuccessAt,
		); err != nil {
			return nil, fmt.Errorf("scan enabled source: %w", err)
		}
		source.PollInterval = time.Duration(pollIntervalSeconds) * time.Second
		source.LastSuccessAt = lastSuccessAt
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read enabled sources: %w", err)
	}
	return sources, nil
}

func (s *Store) CompleteCollection(ctx context.Context, source ingest.Source, run ingest.Run, items []ingest.Item) (int, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()

	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return 0, fmt.Errorf("begin collection transaction: %w", err)
	}
	defer func() {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer rollbackCancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	for _, item := range items {
		analysis := analyzer.Analyze(item.Title)
		var storyID int64
		err := tx.QueryRow(queryCtx, `INSERT INTO stories (
				canonical_url, title, published_at, risk, sentiment
			) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (canonical_url) DO UPDATE SET
				title = EXCLUDED.title,
				published_at = COALESCE(EXCLUDED.published_at, stories.published_at),
				risk = EXCLUDED.risk,
				sentiment = EXCLUDED.sentiment,
				updated_at = clock_timestamp()
			RETURNING id`,
			item.CanonicalURL, item.Title, item.PublishedAt, analysis.Risk, analysis.Sentiment,
		).Scan(&storyID)
		if err != nil {
			return 0, fmt.Errorf("upsert story: %w", err)
		}
		if _, err := tx.Exec(queryCtx, `DELETE FROM story_categories WHERE story_id = $1`, storyID); err != nil {
			return 0, fmt.Errorf("replace story categories: %w", err)
		}
		assignedCategories := int64(0)
		for _, categoryID := range analysis.Categories {
			tag, err := tx.Exec(queryCtx, `INSERT INTO story_categories (story_id, category_id)
				SELECT $1, id FROM categories WHERE id = $2 AND enabled
				ON CONFLICT DO NOTHING`, storyID, categoryID)
			if err != nil {
				return 0, fmt.Errorf("assign story category: %w", err)
			}
			assignedCategories += tag.RowsAffected()
		}
		if assignedCategories == 0 {
			tag, err := tx.Exec(queryCtx, `INSERT INTO story_categories (story_id, category_id)
				SELECT $1, id FROM categories WHERE id = 'other' AND enabled
				ON CONFLICT DO NOTHING`, storyID)
			if err != nil {
				return 0, fmt.Errorf("assign fallback story category: %w", err)
			}
			if tag.RowsAffected() == 0 {
				return 0, errors.New("no enabled fallback category is available")
			}
		}
		if _, err := tx.Exec(queryCtx, `INSERT INTO story_sources (story_id, source_id)
			VALUES ($1, $2)
			ON CONFLICT (story_id, source_id) DO NOTHING`,
			storyID, source.ID,
		); err != nil {
			return 0, fmt.Errorf("associate story source: %w", err)
		}
	}

	itemsSaved := len(items)
	if _, err := tx.Exec(queryCtx, `INSERT INTO collection_runs (
		source_id, started_at, finished_at, outcome, items_received,
		items_saved, items_skipped, failure_cause
	) VALUES ($1, $2, $3, 'success', $4, $5, $6, NULL)`,
		source.ID, run.StartedAt, run.FinishedAt,
		run.ItemsReceived, itemsSaved, run.ItemsSkipped,
	); err != nil {
		return 0, fmt.Errorf("record successful collection: %w", err)
	}
	if _, err := tx.Exec(queryCtx, `UPDATE data_sources
		SET last_success_at = $2, updated_at = clock_timestamp()
		WHERE id = $1`,
		source.ID, run.FinishedAt,
	); err != nil {
		return 0, fmt.Errorf("update source status: %w", err)
	}
	if err := tx.Commit(queryCtx); err != nil {
		return 0, fmt.Errorf("commit collection transaction: %w", err)
	}
	return itemsSaved, nil
}

func (s *Store) RecordFailure(ctx context.Context, source ingest.Source, run ingest.Run, cause string) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()

	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return fmt.Errorf("begin failure transaction: %w", err)
	}
	defer func() {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer rollbackCancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	if _, err := tx.Exec(queryCtx, `INSERT INTO collection_runs (
		source_id, started_at, finished_at, outcome, items_received,
		items_saved, items_skipped, failure_cause
	) VALUES ($1, $2, $3, 'failure', $4, 0, $5, $6)`,
		source.ID, run.StartedAt, run.FinishedAt,
		run.ItemsReceived, run.ItemsSkipped, cause,
	); err != nil {
		return fmt.Errorf("record failed collection: %w", err)
	}
	tag, err := tx.Exec(queryCtx, `UPDATE data_sources SET
		last_failure_at = $2,
		last_failure_cause = $3,
		updated_at = clock_timestamp()
		WHERE id = $1`,
		source.ID, run.FinishedAt, cause,
	)
	if err != nil {
		return fmt.Errorf("update failed source status: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("source %q no longer exists", source.ID)
	}
	if err := tx.Commit(queryCtx); err != nil {
		return fmt.Errorf("commit failure transaction: %w", err)
	}
	return nil
}

var _ ingest.Store = (*Store)(nil)
