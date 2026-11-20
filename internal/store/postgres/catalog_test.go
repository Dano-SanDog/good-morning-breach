package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/Dano-SanDog/good-morning-breach/internal/catalog"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires a scratch database that already has every migration applied.
func TestCatalogStoreWithMigratedPostgres(t *testing.T) {
	connection := os.Getenv("GB_TEST_MIGRATED_DATABASE_URL")
	if connection == "" {
		t.Skip("set GB_TEST_MIGRATED_DATABASE_URL to a scratch migrated database")
	}
	config, err := pgxpool.ParseConfig(connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLocalHost(config.ConnConfig.Host); err != nil || config.ConnConfig.Password != "" {
		t.Fatal("test database must be local and must not contain a password")
	}
	ctx := context.Background()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var actor int64
	if err := pool.QueryRow(ctx, `INSERT INTO accounts (email, password_hash, role)
		VALUES ('catalog-test@example.test', 'x', 'admin') RETURNING id`).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM story_categories WHERE category_id = 'catalog-test'`)
		_, _ = pool.Exec(ctx, `DELETE FROM categories WHERE id LIKE 'catalog-test%'`)
		_, _ = pool.Exec(ctx, `DELETE FROM data_sources WHERE id = 'catalog-test-source'`)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_audit_log WHERE actor_account_id = $1`, actor)
		_, _ = pool.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, actor)
	})
	store := NewCatalogStore(pool)

	if _, err := store.CreateCategory(ctx, actor, "catalog-test", "Catalog Test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateCategory(ctx, actor, "catalog-test-2", "catalog test"); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("case-insensitive duplicate err = %v", err)
	}
	if err := store.UpdateCategory(ctx, actor, "catalog-test", "Catalog Renamed", false); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetCategory(ctx, "catalog-test")
	if err != nil || got.Name != "Catalog Renamed" || got.Enabled {
		t.Fatalf("category = %+v, %v", got, err)
	}
	if err := store.DeleteCategory(ctx, actor, "catalog-test"); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteCategory(ctx, actor, "catalog-test"); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("second delete err = %v", err)
	}

	source := catalog.Source{
		ID: "catalog-test-source", Name: "Catalog Test Source", Address: "https://example.com/feed.xml",
		Format: "rss", LicenseName: "CC BY", LicenseURL: "https://example.com/l", PermittedUse: "headline",
		Attribution: "Example", ContentPolicy: "headline_link", PollIntervalSeconds: 3600, Enabled: true,
	}
	if _, err := store.CreateSource(ctx, actor, source); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSource(ctx, actor, source); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("duplicate source err = %v", err)
	}
	source.RequireCompleteTitle = true
	source.Enabled = false
	if err := store.UpdateSource(ctx, actor, source); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetSource(ctx, source.ID)
	if err != nil || !stored.RequireCompleteTitle || stored.Enabled {
		t.Fatalf("source = %+v, %v", stored, err)
	}
	if err := store.DeleteSource(ctx, actor, source.ID); err != nil {
		t.Fatal(err)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log
		WHERE actor_account_id = $1 AND target_account_id IS NULL AND target_kind IN ('category','source')`, actor).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 6 {
		t.Fatalf("audit rows = %d; want 6", audits)
	}
}
