package postgres

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_ingestion.sql
var ingestionMigration string

const migrationVersion = 1
const migrationLockID int64 = 0x47424d

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	migrationCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	_, err := pool.Exec(migrationCtx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
	)`)
	if err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}

	tx, err := pool.Begin(migrationCtx)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer func() {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer rollbackCancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	if _, err := tx.Exec(migrationCtx, `SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	var applied bool
	if err := tx.QueryRow(migrationCtx,
		`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`,
		migrationVersion,
	).Scan(&applied); err != nil {
		return fmt.Errorf("check migration version: %w", err)
	}
	if !applied {
		for _, statement := range strings.Split(ingestionMigration, ";") {
			statement = strings.TrimSpace(statement)
			if statement == "" {
				continue
			}
			if _, err := tx.Exec(migrationCtx, statement); err != nil {
				return fmt.Errorf("apply ingestion migration: %w", err)
			}
		}
		if _, err := tx.Exec(migrationCtx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`,
			migrationVersion,
		); err != nil {
			return fmt.Errorf("record migration version: %w", err)
		}
	}
	if err := tx.Commit(migrationCtx); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}
