package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/retention"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RetentionStore deletes expired stories and delivery records in batches.
// Story children (sources, categories, techniques, CVEs) cascade.
type RetentionStore struct {
	pool *pgxpool.Pool
}

func NewRetentionStore(pool *pgxpool.Pool) *RetentionStore {
	return &RetentionStore{pool: pool}
}

func (s *RetentionStore) DeleteStoriesBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	tag, err := s.pool.Exec(queryCtx, `DELETE FROM stories WHERE id IN (
		SELECT id FROM stories WHERE created_at < $1 ORDER BY created_at LIMIT $2)`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired stories: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (s *RetentionStore) DeleteDeliveriesBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	tag, err := s.pool.Exec(queryCtx, `DELETE FROM alert_deliveries WHERE id IN (
		SELECT id FROM alert_deliveries WHERE attempted_at < $1 ORDER BY attempted_at LIMIT $2)`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired alert deliveries: %w", err)
	}
	logTag, err := s.pool.Exec(queryCtx, `DELETE FROM outbound_message_log WHERE id IN (
		SELECT id FROM outbound_message_log WHERE sent_at < $1 ORDER BY sent_at LIMIT $2)`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired outbound message log: %w", err)
	}
	return tag.RowsAffected() + logTag.RowsAffected(), nil
}

var _ retention.Store = (*RetentionStore)(nil)
