package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/analyzer"
	"github.com/Dano-SanDog/good-morning-breach/internal/ingest"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	currentAnalysisVersion       = 1
	analysisBatchSize            = 100
	collectionLockID       int64 = 0x47424d434f4c4c
)

type Store struct {
	pool        *pgxpool.Pool
	attackIndex *analyzer.AttackIndex
}

func NewStore(pool *pgxpool.Pool, attackIndex *analyzer.AttackIndex) (*Store, error) {
	if attackIndex == nil {
		return nil, errors.New("ATT&CK index is required")
	}
	return &Store{pool: pool, attackIndex: attackIndex}, nil
}

func (s *Store) ReanalyzeStories(ctx context.Context) (int, error) {
	total := 0
	for {
		updated, err := s.reanalyzeStoryBatch(ctx)
		if err != nil {
			return total, err
		}
		total += updated
		if updated == 0 {
			return total, nil
		}
	}
}

func (s *Store) reanalyzeStoryBatch(ctx context.Context) (int, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()

	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return 0, fmt.Errorf("begin story analysis batch: %w", err)
	}
	defer rollback(tx)

	rows, err := tx.Query(queryCtx, `SELECT id, title FROM stories
		WHERE analysis_version < $1
		ORDER BY id
		LIMIT $2`, currentAnalysisVersion, analysisBatchSize)
	if err != nil {
		return 0, fmt.Errorf("query stories requiring analysis: %w", err)
	}
	type storyHeadline struct {
		id    int64
		title string
	}
	var stories []storyHeadline
	for rows.Next() {
		var story storyHeadline
		if err := rows.Scan(&story.id, &story.title); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan story requiring analysis: %w", err)
		}
		stories = append(stories, story)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("read stories requiring analysis: %w", err)
	}
	rows.Close()

	for _, story := range stories {
		if err := s.saveStoryAnalysis(queryCtx, tx, story.id, story.title); err != nil {
			return 0, fmt.Errorf("analyze story %d: %w", story.id, err)
		}
	}
	if err := tx.Commit(queryCtx); err != nil {
		return 0, fmt.Errorf("commit story analysis batch: %w", err)
	}
	return len(stories), nil
}

func (s *Store) ListEnabledSources(ctx context.Context) ([]ingest.Source, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()

	rows, err := s.pool.Query(queryCtx, `SELECT
		id, name, address, license_name, license_url, permitted_use,
		attribution, content_policy, poll_interval_seconds, last_success_at, format
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
			&source.Format,
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

func (s *Store) AcquireCollectionLock(ctx context.Context) (func(context.Context) error, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire database connection for collection lock: %w", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, collectionLockID); err != nil {
		closeErr := closeLockedConnection(conn)
		return nil, errors.Join(fmt.Errorf("acquire PostgreSQL collection lock: %w", err), closeErr)
	}

	var once sync.Once
	var releaseErr error
	return func(releaseCtx context.Context) error {
		once.Do(func() {
			var released bool
			if err := conn.QueryRow(releaseCtx,
				`SELECT pg_advisory_unlock($1)`, collectionLockID,
			).Scan(&released); err != nil {
				releaseErr = errors.Join(
					fmt.Errorf("unlock PostgreSQL collection lock: %w", err),
					closeLockedConnection(conn),
				)
				return
			}
			if !released {
				releaseErr = errors.Join(
					errors.New("PostgreSQL collection lock was not held"),
					closeLockedConnection(conn),
				)
				return
			}
			conn.Release()
		})
		return releaseErr
	}, nil
}

func closeLockedConnection(conn *pgxpool.Conn) error {
	rawConn := conn.Hijack()
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return rawConn.Close(closeCtx)
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
		var storyID int64
		err := tx.QueryRow(queryCtx, `INSERT INTO stories (canonical_url, title, published_at)
			VALUES ($1, $2, $3)
			ON CONFLICT (canonical_url) DO UPDATE SET
				title = EXCLUDED.title,
				published_at = COALESCE(EXCLUDED.published_at, stories.published_at),
				updated_at = clock_timestamp()
			RETURNING id`,
			item.CanonicalURL, item.Title, item.PublishedAt,
		).Scan(&storyID)
		if err != nil {
			return 0, fmt.Errorf("upsert story: %w", err)
		}
		if err := s.saveStoryAnalysis(queryCtx, tx, storyID, item.Title); err != nil {
			return 0, fmt.Errorf("analyze collected story: %w", err)
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

func (s *Store) saveStoryAnalysis(ctx context.Context, tx pgx.Tx, storyID int64, title string) error {
	analysis := analyzer.Analyze(title)
	analysis.AttackTechniques = s.attackIndex.Match(title)

	if _, err := tx.Exec(ctx, `DELETE FROM story_categories WHERE story_id = $1`, storyID); err != nil {
		return fmt.Errorf("replace story categories: %w", err)
	}
	assignedCategories := int64(0)
	for _, categoryID := range analysis.Categories {
		tag, err := tx.Exec(ctx, `INSERT INTO story_categories (story_id, category_id)
			SELECT $1, id FROM categories WHERE id = $2 AND enabled
			ON CONFLICT DO NOTHING`, storyID, categoryID)
		if err != nil {
			return fmt.Errorf("assign story category: %w", err)
		}
		assignedCategories += tag.RowsAffected()
	}
	if assignedCategories == 0 {
		tag, err := tx.Exec(ctx, `INSERT INTO story_categories (story_id, category_id)
			SELECT $1, id FROM categories WHERE id = 'other' AND enabled
			ON CONFLICT DO NOTHING`, storyID)
		if err != nil {
			return fmt.Errorf("assign fallback story category: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return errors.New("no enabled fallback category is available")
		}
	}

	if _, err := tx.Exec(ctx, `DELETE FROM story_techniques WHERE story_id = $1`, storyID); err != nil {
		return fmt.Errorf("replace story ATT&CK techniques: %w", err)
	}
	for _, technique := range analysis.AttackTechniques {
		if _, err := tx.Exec(ctx, `INSERT INTO attack_techniques (
			technique_id, name, tactics
		) VALUES ($1, $2, $3)
		ON CONFLICT (technique_id) DO UPDATE SET
			name = EXCLUDED.name,
			tactics = EXCLUDED.tactics,
			updated_at = clock_timestamp()`,
			technique.ID, technique.Name, technique.Tactics,
		); err != nil {
			return fmt.Errorf("save ATT&CK technique: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO story_techniques (story_id, technique_id)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING`, storyID, technique.ID); err != nil {
			return fmt.Errorf("associate story ATT&CK technique: %w", err)
		}
	}

	tag, err := tx.Exec(ctx, `UPDATE stories SET
		risk = $2, sentiment = $3, analysis_version = $4, updated_at = clock_timestamp()
		WHERE id = $1`, storyID, analysis.Risk, analysis.Sentiment, currentAnalysisVersion)
	if err != nil {
		return fmt.Errorf("update story analysis: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("story %d no longer exists", storyID)
	}
	return nil
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
