package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/Dano-SanDog/good-morning-breach/internal/catalog"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CatalogStore persists administrator edits to categories and data sources.
type CatalogStore struct {
	pool *pgxpool.Pool
}

func NewCatalogStore(pool *pgxpool.Pool) *CatalogStore {
	return &CatalogStore{pool: pool}
}

const sourceColumns = `id, name, address, format, license_name, license_url, permitted_use,
	attribution, content_policy, rights_class, poll_interval_seconds, enabled, require_complete_title,
	(SELECT count(*) FROM story_sources ss WHERE ss.source_id = data_sources.id), updated_at`

func scanSource(row pgx.Row) (catalog.Source, error) {
	var s catalog.Source
	err := row.Scan(&s.ID, &s.Name, &s.Address, &s.Format, &s.LicenseName, &s.LicenseURL,
		&s.PermittedUse, &s.Attribution, &s.ContentPolicy, &s.RightsClass, &s.PollIntervalSeconds, &s.Enabled,
		&s.RequireCompleteTitle, &s.StoryCount, &s.UpdatedAt)
	return s, err
}

func scanCategory(row pgx.Row) (catalog.Category, error) {
	var c catalog.Category
	err := row.Scan(&c.ID, &c.Name, &c.Enabled, &c.StoryCount, &c.UpdatedAt)
	return c, err
}

const categoryColumns = `id, name, enabled,
	(SELECT count(*) FROM story_categories sc WHERE sc.category_id = categories.id), updated_at`

func (s *CatalogStore) ListCategories(ctx context.Context) ([]catalog.Category, error) {
	ctx, cancel := databaseContext(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT `+categoryColumns+` FROM categories ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list categories: %w", err)
	}
	defer rows.Close()
	out := []catalog.Category{}
	for rows.Next() {
		c, err := scanCategory(rows)
		if err != nil {
			return nil, fmt.Errorf("scan category: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *CatalogStore) GetCategory(ctx context.Context, id string) (catalog.Category, error) {
	ctx, cancel := databaseContext(ctx)
	defer cancel()
	c, err := scanCategory(s.pool.QueryRow(ctx, `SELECT `+categoryColumns+` FROM categories WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return c, catalog.ErrNotFound
	}
	return c, err
}

func (s *CatalogStore) CreateCategory(ctx context.Context, actorID int64, id, name string) (catalog.Category, error) {
	ctx, cancel := databaseContext(ctx)
	defer cancel()
	var out catalog.Category
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		c, err := scanCategory(tx.QueryRow(ctx, `INSERT INTO categories (id, name, enabled)
			VALUES ($1, $2, true)
			RETURNING id, name, enabled, 0::bigint, updated_at`, id, name))
		if err != nil {
			return err
		}
		out = c
		return insertCatalogAudit(ctx, tx, actorID, "category_created", "category", id,
			map[string]any{"name": name})
	})
	return out, mapCatalogError(err)
}

func (s *CatalogStore) UpdateCategory(ctx context.Context, actorID int64, id, name string, enabled bool) error {
	ctx, cancel := databaseContext(ctx)
	defer cancel()
	return mapCatalogError(s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE categories SET name = $2, enabled = $3, updated_at = now()
			WHERE id = $1`, id, name, enabled)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return catalog.ErrNotFound
		}
		return insertCatalogAudit(ctx, tx, actorID, "category_updated", "category", id,
			map[string]any{"name": name, "enabled": enabled})
	}))
}

func (s *CatalogStore) DeleteCategory(ctx context.Context, actorID int64, id string) error {
	ctx, cancel := databaseContext(ctx)
	defer cancel()
	return mapCatalogError(s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM categories WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return catalog.ErrNotFound
		}
		return insertCatalogAudit(ctx, tx, actorID, "category_deleted", "category", id, map[string]any{})
	}))
}

func (s *CatalogStore) ListSources(ctx context.Context) ([]catalog.Source, error) {
	ctx, cancel := databaseContext(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT `+sourceColumns+` FROM data_sources ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list sources: %w", err)
	}
	defer rows.Close()
	out := []catalog.Source{}
	for rows.Next() {
		src, err := scanSource(rows)
		if err != nil {
			return nil, fmt.Errorf("scan source: %w", err)
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

func (s *CatalogStore) GetSource(ctx context.Context, id string) (catalog.Source, error) {
	ctx, cancel := databaseContext(ctx)
	defer cancel()
	src, err := scanSource(s.pool.QueryRow(ctx, `SELECT `+sourceColumns+` FROM data_sources WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return src, catalog.ErrNotFound
	}
	return src, err
}

func (s *CatalogStore) CreateSource(ctx context.Context, actorID int64, src catalog.Source) (catalog.Source, error) {
	ctx, cancel := databaseContext(ctx)
	defer cancel()
	var out catalog.Source
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		created, err := scanSource(tx.QueryRow(ctx, `INSERT INTO data_sources (
				id, name, address, format, license_name, license_url, permitted_use, attribution,
				content_policy, rights_class, poll_interval_seconds, enabled, require_complete_title)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			RETURNING id, name, address, format, license_name, license_url, permitted_use,
				attribution, content_policy, rights_class, poll_interval_seconds, enabled,
				require_complete_title, 0::bigint, updated_at`,
			src.ID, src.Name, src.Address, src.Format, src.LicenseName, src.LicenseURL,
			src.PermittedUse, src.Attribution, src.ContentPolicy, src.RightsClass, src.PollIntervalSeconds,
			src.Enabled, src.RequireCompleteTitle))
		if err != nil {
			return err
		}
		out = created
		return insertCatalogAudit(ctx, tx, actorID, "source_created", "source", src.ID, sourceAuditDetails(src))
	})
	return out, mapCatalogError(err)
}

func (s *CatalogStore) UpdateSource(ctx context.Context, actorID int64, src catalog.Source) error {
	ctx, cancel := databaseContext(ctx)
	defer cancel()
	return mapCatalogError(s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE data_sources SET
				name = $2, address = $3, format = $4, license_name = $5, license_url = $6,
				permitted_use = $7, attribution = $8, content_policy = $9,
				rights_class = $10, poll_interval_seconds = $11, enabled = $12, require_complete_title = $13,
				updated_at = now()
			WHERE id = $1`,
			src.ID, src.Name, src.Address, src.Format, src.LicenseName, src.LicenseURL,
			src.PermittedUse, src.Attribution, src.ContentPolicy, src.RightsClass, src.PollIntervalSeconds,
			src.Enabled, src.RequireCompleteTitle)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return catalog.ErrNotFound
		}
		return insertCatalogAudit(ctx, tx, actorID, "source_updated", "source", src.ID, sourceAuditDetails(src))
	}))
}

func (s *CatalogStore) DeleteSource(ctx context.Context, actorID int64, id string) error {
	ctx, cancel := databaseContext(ctx)
	defer cancel()
	return mapCatalogError(s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM data_sources WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return catalog.ErrNotFound
		}
		return insertCatalogAudit(ctx, tx, actorID, "source_deleted", "source", id, map[string]any{})
	}))
}

func (s *CatalogStore) ListReviewStories(ctx context.Context) ([]catalog.ReviewStory, error) {
	ctx, cancel := databaseContext(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT stories.id, stories.title, stories.canonical_url, stories.excerpt,
			array_agg(DISTINCT data_sources.name ORDER BY data_sources.name),
			COALESCE(stories.published_at, stories.created_at), stories.excerpt_approved_at
		FROM stories
		JOIN story_sources ON story_sources.story_id = stories.id
		JOIN data_sources ON data_sources.id = story_sources.source_id
		WHERE stories.excerpt IS NOT NULL AND stories.excerpt <> ''
		AND EXISTS (SELECT 1 FROM story_sources ss JOIN data_sources ds ON ds.id = ss.source_id
			WHERE ss.story_id = stories.id AND ds.rights_class = 'conditional')
		GROUP BY stories.id
		ORDER BY (stories.excerpt_approved_at IS NOT NULL), COALESCE(stories.published_at, stories.created_at) DESC, stories.id DESC
		LIMIT 100`)
	if err != nil {
		return nil, fmt.Errorf("query stories for review: %w", err)
	}
	defer rows.Close()
	out := []catalog.ReviewStory{}
	for rows.Next() {
		// Admin-only pre-gate view: the excerpt is shown so it can be approved.
		var item catalog.ReviewStory
		if err := rows.Scan(&item.ID, &item.Title, &item.URL, &item.Candidate, &item.Sources, &item.PublishedAt, &item.ApprovedAt); err != nil {
			return nil, fmt.Errorf("scan story for review: %w", err)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *CatalogStore) SetExcerptApproval(ctx context.Context, actorID, storyID int64, approved bool) error {
	ctx, cancel := databaseContext(ctx)
	defer cancel()
	return mapCatalogError(s.inTx(ctx, func(tx pgx.Tx) error {
		action := "story_excerpt_revoked"
		query := `UPDATE stories SET excerpt_approved_at = NULL, excerpt_approved_by = NULL WHERE id = $1`
		args := []any{storyID}
		if approved {
			action = "story_excerpt_approved"
			query = `UPDATE stories SET excerpt_approved_at = now(), excerpt_approved_by = $2 WHERE id = $1`
			args = append(args, actorID)
		}
		// Only a story with a stored excerpt from a conditional source can be reviewed.
		tag, err := tx.Exec(ctx, query+` AND excerpt IS NOT NULL AND excerpt <> ''
			AND EXISTS (SELECT 1 FROM story_sources ss JOIN data_sources ds ON ds.id = ss.source_id
				WHERE ss.story_id = stories.id AND ds.rights_class = 'conditional')`, args...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return catalog.ErrNotFound
		}
		return insertCatalogAudit(ctx, tx, actorID, action, "story", strconv.FormatInt(storyID, 10), map[string]any{})
	}))
}

func (s *CatalogStore) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin catalog transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit catalog transaction: %w", err)
	}
	return nil
}

func sourceAuditDetails(src catalog.Source) map[string]any {
	return map[string]any{
		"name": src.Name, "address": src.Address, "format": src.Format,
		"enabled": src.Enabled, "contentPolicy": src.ContentPolicy, "rightsClass": src.RightsClass,
		"pollIntervalSeconds": src.PollIntervalSeconds, "requireCompleteTitle": src.RequireCompleteTitle,
	}
}

func insertCatalogAudit(ctx context.Context, tx pgx.Tx, actorID int64, action, kind, targetID string, details map[string]any) error {
	raw, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode audit details: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO admin_audit_log (
			actor_account_id, target_account_id, target_kind, target_id, action, details
		) VALUES ($1, NULL, $2, $3, $4, $5)`, actorID, kind, targetID, action, raw); err != nil {
		return fmt.Errorf("record administrator action: %w", err)
	}
	return nil
}

func mapCatalogError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return catalog.ErrConflict
		case "23503":
			return catalog.ErrInUse
		}
	}
	return err
}
