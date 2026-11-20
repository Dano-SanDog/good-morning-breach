package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/analyzer"
	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires a scratch database that already has every migration applied.
func TestSemanticAnalysisWithMigratedPostgres(t *testing.T) {
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
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM stories WHERE canonical_url LIKE 'https://semantic-test.example/%'`)
		_, _ = pool.Exec(ctx, `DELETE FROM data_sources WHERE id = 'semantic-test-kev'`)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO data_sources (id, name, address, license_name, license_url,
		permitted_use, attribution, content_policy, poll_interval_seconds, enabled, format)
		VALUES ('semantic-test-kev', 'Semantic Test KEV', 'https://semantic-test.example/feed', 'l',
		'https://semantic-test.example/l', 'p', 'n', 'headline_link', 3600, false, 'cisa_kev_json')`); err != nil {
		t.Fatal(err)
	}
	titles := []string{
		"Acme Gateway Command Injection CVE-2026-7001",
		"Researchers detail cve-2026-7001 exploit chain",
		"Phishing kits deliver ransomware to clinics",
	}
	for i, title := range titles {
		var id int64
		if err := pool.QueryRow(ctx, `INSERT INTO stories (canonical_url, title, published_at)
			VALUES ($1, $2, now()) RETURNING id`,
			"https://semantic-test.example/"+string(rune('a'+i)), title).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO story_sources (story_id, source_id)
			VALUES ($1, 'semantic-test-kev')`, id); err != nil {
			t.Fatal(err)
		}
	}
	index, err := analyzer.NewAttackIndex()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(pool, index)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReanalyzeStories(ctx); err != nil {
		t.Fatal(err)
	}

	stories, err := NewIdentityStore(pool).ListStories(ctx, identity.StoryFilter{
		After: time.Now().Add(-time.Hour), Search: "cve-2026-7001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(stories) == 0 {
		t.Fatal("no stories returned")
	}
	for _, story := range stories {
		if len(story.CVEs) != 1 || story.CVEs[0] != "CVE-2026-7001" || len(story.Related) != 1 {
			t.Errorf("story %q: CVEs %v related %+v", story.Title, story.CVEs, story.Related)
		}
		if story.Risk != "High" {
			t.Errorf("story %q risk = %s; want High from the KEV floor", story.Title, story.Risk)
		}
	}
	var engine string
	var version int
	if err := pool.QueryRow(ctx, `SELECT analysis_engine, analysis_version FROM stories
		WHERE canonical_url = 'https://semantic-test.example/c'`).Scan(&engine, &version); err != nil ||
		engine != "semantic" || version != currentAnalysisVersion {
		t.Fatalf("engine %q version %d error %v", engine, version, err)
	}
	var techniques int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM story_techniques JOIN stories ON stories.id = story_id
		WHERE canonical_url = 'https://semantic-test.example/c'`).Scan(&techniques); err != nil || techniques < 2 {
		t.Fatalf("techniques = %d, error %v", techniques, err)
	}
}
