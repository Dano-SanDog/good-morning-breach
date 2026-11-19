package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestValidateLocalHost(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "::1", "/tmp"} {
		if err := validateLocalHost(host); err != nil {
			t.Errorf("validateLocalHost(%q): %v", host, err)
		}
	}
	for _, host := range []string{"db.example.com", "192.168.1.10"} {
		if err := validateLocalHost(host); err == nil {
			t.Errorf("validateLocalHost(%q) unexpectedly succeeded", host)
		}
	}
}

func TestDashboardQueriesWithPostgres(t *testing.T) {
	connection := os.Getenv("GB_TEST_DATABASE_URL")
	if connection == "" {
		t.Skip("set GB_TEST_DATABASE_URL to run PostgreSQL integration test")
	}
	config, err := pgxpool.ParseConfig(connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLocalHost(config.ConnConfig.Host); err != nil || config.ConnConfig.Password != "" {
		t.Fatal("test database must be local and must not contain a password")
	}
	config.MaxConns = 1
	ctx := context.Background()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	setup := []string{
		`CREATE TEMP TABLE stories (id bigint PRIMARY KEY, title text, canonical_url text, published_at timestamptz, created_at timestamptz, risk text, sentiment text)`,
		`CREATE TEMP TABLE data_sources (id text PRIMARY KEY, name text, attribution text, enabled boolean, last_success_at timestamptz, last_failure_at timestamptz, last_failure_cause text)`,
		`CREATE TEMP TABLE story_sources (story_id bigint, source_id text)`,
		`CREATE TEMP TABLE categories (id text PRIMARY KEY, name text)`,
		`CREATE TEMP TABLE story_categories (story_id bigint, category_id text)`,
		`CREATE TEMP TABLE attack_techniques (technique_id text, name text, tactics text[])`,
		`CREATE TEMP TABLE story_techniques (story_id bigint, technique_id text)`,
		`CREATE TEMP TABLE collection_runs (source_id text, outcome text, finished_at timestamptz)`,
		`INSERT INTO data_sources VALUES
				  ('a', 'Feed A', 'A notice', true, now() - interval '30 hours', now() - interval '1 hour', 'failed'),
				  ('b', 'Feed B', 'B notice', true, now() - interval '1 hour', now() - interval '25 hours', 'old failure')`,
		`INSERT INTO collection_runs VALUES
				  ('a', 'failure', now() - interval '40 hours'), ('a', 'success', now() - interval '30 hours'),
				  ('a', 'failure', now() - interval '26 hours'), ('a', 'failure', now() - interval '1 hour'),
				  ('b', 'failure', now() - interval '25 hours'), ('b', 'success', now() - interval '1 hour')`,
		`INSERT INTO stories SELECT n, CASE WHEN n = 1 THEN 'Critical alpha patch' ELSE 'Other news' END,
				  'https://example.test/' || n, now() - interval '1 hour', now(), 'High', 'Neutral' FROM generate_series(1,105) n`,
		`INSERT INTO story_sources SELECT n, 'a' FROM generate_series(1,105) n`,
		`INSERT INTO story_sources VALUES (1, 'b')`,
		`INSERT INTO categories VALUES ('one', 'Vulnerability'), ('two', 'Other')`,
		`INSERT INTO story_categories SELECT n, 'one' FROM generate_series(1,105) n`,
		`INSERT INTO story_categories VALUES (1, 'two')`,
		`INSERT INTO attack_techniques VALUES ('T1190', 'Exploit Public-Facing Application', ARRAY['Initial Access'])`,
		`INSERT INTO story_techniques VALUES (1, 'T1190')`,
	}
	for _, statement := range setup {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	store := NewIdentityStore(pool)
	if _, err := pool.Exec(ctx, `CREATE TEMP TABLE accounts (id bigint PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	migration := strings.Replace(alertSettingsMigration, "CREATE TABLE alert_settings", "CREATE TEMP TABLE alert_settings", 1)
	for _, statement := range strings.Split(migration, ";") {
		if strings.TrimSpace(statement) != "" {
			if _, err := pool.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO accounts VALUES (1), (2)`); err != nil {
		t.Fatal(err)
	}
	defaults, err := store.GetAlertSettings(ctx, 1)
	if err != nil || !defaults.Enabled || defaults.Time != "07:00" || defaults.TimeZone != "" ||
		len(defaults.Days) != 7 || defaults.MinimumRisk != "Medium" {
		t.Fatalf("default alert settings = %+v, error %v", defaults, err)
	}
	settings := identity.AlertSettings{Enabled: true, Time: "08:30", TimeZone: "America/Los_Angeles",
		Days: []int16{1, 3, 5}, MinimumRisk: "High"}
	if err := store.SaveAlertSettings(ctx, 1, settings); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAlertSettings(ctx, 2, identity.AlertSettings{Enabled: false, Time: "07:00",
		TimeZone: "UTC", Days: []int16{0}, MinimumRisk: "Low"}); err != nil {
		t.Fatal(err)
	}
	settings.Time = "09:15"
	if err := store.SaveAlertSettings(ctx, 1, settings); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetAlertSettings(ctx, 1)
	if err != nil || stored.Time != "09:15" || stored.TimeZone != settings.TimeZone || len(stored.Days) != 3 {
		t.Fatalf("saved alert settings = %+v, error %v", stored, err)
	}
	second, err := store.GetAlertSettings(ctx, 2)
	if err != nil || second.Enabled || second.TimeZone != "UTC" {
		t.Fatalf("second account settings = %+v, error %v", second, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM accounts WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM alert_settings WHERE account_id = 1`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("deleted account settings remaining = %d, error %v", remaining, err)
	}
	statuses, err := store.ListSourceStatuses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 2 || statuses[0].FailingSince == nil || statuses[1].FailingSince != nil {
		t.Fatalf("unexpected failure streaks: %+v", statuses)
	}
	if age := time.Since(*statuses[0].FailingSince); age < 25*time.Hour || age > 27*time.Hour {
		t.Fatalf("failure streak age = %v; want 26 hours", age)
	}
	filter := identity.StoryFilter{After: time.Now().Add(-24 * time.Hour)}
	stories, err := store.ListStories(ctx, filter)
	if err != nil || len(stories) != 101 {
		t.Fatalf("first page: got %d stories, error %v", len(stories), err)
	}
	filter.Offset = 100
	stories, err = store.ListStories(ctx, filter)
	if err != nil || len(stories) != 5 {
		t.Fatalf("second page: got %d stories, error %v", len(stories), err)
	}
	filter = identity.StoryFilter{After: time.Now().Add(-24 * time.Hour), Search: "alpha patch",
		Risk: "High", Category: "other", Source: "feed b", Attack: "initial access"}
	stories, err = store.ListStories(ctx, filter)
	if err != nil || len(stories) != 1 || stories[0].ID != 1 || len(stories[0].Sources) != 2 || len(stories[0].Categories) != 2 {
		t.Fatalf("combined filters: stories = %+v, error %v", stories, err)
	}
	filter.Search = "' OR 1=1 -- &|!:*"
	stories, err = store.ListStories(ctx, filter)
	if err != nil || len(stories) != 0 {
		t.Fatalf("special search: got %d stories, error %v", len(stories), err)
	}
}
