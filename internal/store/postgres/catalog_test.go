package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/catalog"
	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
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
		Attribution: "Example", ContentPolicy: "headline_link", RightsClass: "licensed", PollIntervalSeconds: 3600, Enabled: true,
	}
	if _, err := store.CreateSource(ctx, actor, source); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSource(ctx, actor, source); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("duplicate source err = %v", err)
	}
	source.RequireCompleteTitle = true
	source.Enabled = false
	source.RightsClass = "all_rights_reserved"
	if err := store.UpdateSource(ctx, actor, source); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetSource(ctx, source.ID)
	if err != nil || !stored.RequireCompleteTitle || stored.Enabled || stored.RightsClass != "all_rights_reserved" {
		t.Fatalf("source = %+v, %v", stored, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE data_sources SET content_policy = 'full_text' WHERE id = $1`, source.ID); err == nil {
		t.Fatal("database accepted an all-rights-reserved source with a full_text policy")
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

// Requires a scratch database that already has every migration applied.
func TestExcerptReviewWithMigratedPostgres(t *testing.T) {
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
	var actor, storyID, plainID int64
	if err := pool.QueryRow(ctx, `INSERT INTO accounts (email, password_hash, role)
		VALUES ('review-test@example.test', 'x', 'admin') RETURNING id`).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM stories WHERE canonical_url LIKE 'https://review-test.example/%'`)
		_, _ = pool.Exec(ctx, `DELETE FROM data_sources WHERE id IN ('review-test-cond', 'review-test-plain')`)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_audit_log WHERE actor_account_id = $1`, actor)
		_, _ = pool.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, actor)
	})
	store := NewCatalogStore(pool)
	for id, rights := range map[string]string{"review-test-cond": "conditional", "review-test-plain": "licensed"} {
		src := catalog.Source{
			ID: id, Name: id, Address: "https://review-test.example/feed.xml", Format: "rss",
			LicenseName: "L", LicenseURL: "https://review-test.example/l", PermittedUse: "p", Attribution: "a",
			ContentPolicy: "verbatim_excerpt", RightsClass: rights, PollIntervalSeconds: 3600,
		}
		if _, err := store.CreateSource(ctx, actor, src); err != nil {
			t.Fatal(err)
		}
	}
	add := func(url, source string) int64 {
		var id int64
		if err := pool.QueryRow(ctx, `INSERT INTO stories (canonical_url, title, excerpt) VALUES ($1, 'T', 'Excerpt') RETURNING id`, url).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO story_sources (story_id, source_id) VALUES ($1, $2)`, id, source); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO story_categories (story_id, category_id) VALUES ($1, 'other')`, id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	storyID = add("https://review-test.example/a", "review-test-cond")
	plainID = add("https://review-test.example/b", "review-test-plain")

	if err := store.SetExcerptApproval(ctx, actor, plainID, true); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("approving a licensed story err = %v", err)
	}
	stories, err := store.ListReviewStories(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range stories {
		if s.ID == plainID {
			t.Fatal("licensed story listed for review")
		}
		if s.ID == storyID && s.ApprovedAt == nil {
			found = true
		}
	}
	if !found {
		t.Fatal("conditional story not pending")
	}
	identityStore := NewIdentityStore(pool)
	excerptOf := func() string {
		list, err := identityStore.ListStories(ctx, identity.StoryFilter{After: time.Now().Add(-time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range list {
			if s.ID == storyID {
				return s.Excerpt
			}
		}
		return "missing"
	}
	if got := excerptOf(); got != "" {
		t.Fatalf("unapproved excerpt shown: %q", got)
	}
	if err := store.SetExcerptApproval(ctx, actor, storyID, true); err != nil {
		t.Fatal(err)
	}
	if got := excerptOf(); got != "Excerpt" {
		t.Fatalf("approved excerpt = %q", got)
	}
	if err := store.SetExcerptApproval(ctx, actor, storyID, false); err != nil {
		t.Fatal(err)
	}
	if got := excerptOf(); got != "" {
		t.Fatalf("revoked excerpt shown: %q", got)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log WHERE actor_account_id = $1 AND target_kind = 'story'`, actor).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("story audit rows = %d, %v", audits, err)
	}
}
