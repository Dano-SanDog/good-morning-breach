package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires a scratch database that already has every migration applied.
func TestRetentionAndTOTPResetWithMigratedPostgres(t *testing.T) {
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

	var admin, target int64
	if err := pool.QueryRow(ctx, `INSERT INTO accounts (email, password_hash, role)
		VALUES ('retention-admin@example.test', 'x', 'admin') RETURNING id`).Scan(&admin); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO accounts (email, password_hash, role, last_totp_step)
		VALUES ('retention-target@example.test', 'x', 'user', 7) RETURNING id`).Scan(&target); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM stories WHERE canonical_url LIKE 'https://retention.example.test/%'`)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_audit_log WHERE actor_account_id = $1`, admin)
		_, _ = pool.Exec(ctx, `DELETE FROM accounts WHERE id IN ($1, $2)`, admin, target)
	})

	now := time.Now()
	for name, age := range map[string]time.Duration{"old1": 400 * 24 * time.Hour, "old2": 366 * 24 * time.Hour, "new": 24 * time.Hour} {
		if _, err := pool.Exec(ctx, `INSERT INTO stories (canonical_url, title, published_at, created_at)
			VALUES ($1, $2, $3, $3)`, "https://retention.example.test/"+name, name, now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO alert_deliveries (account_id, channel, slot_at, attempted_at, outcome, story_count)
		VALUES ($1, 'email', $2, $2, 'success', 1), ($1, 'email', $3, $3, 'success', 1)`,
		admin, now.Add(-100*24*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	retention := NewRetentionStore(pool)
	deleted, err := retention.DeleteStoriesBefore(ctx, now.Add(-365*24*time.Hour), 1)
	if err != nil || deleted != 1 {
		t.Fatalf("first batch deleted %d, err %v; want 1", deleted, err)
	}
	deleted, err = retention.DeleteStoriesBefore(ctx, now.Add(-365*24*time.Hour), 10)
	if err != nil || deleted != 1 {
		t.Fatalf("second batch deleted %d, err %v; want 1", deleted, err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM stories WHERE canonical_url LIKE 'https://retention.example.test/%'`).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("remaining stories = %d, err %v; want 1", remaining, err)
	}
	deleted, err = retention.DeleteDeliveriesBefore(ctx, now.Add(-90*24*time.Hour), 10)
	if err != nil || deleted != 1 {
		t.Fatalf("deliveries deleted %d, err %v; want 1", deleted, err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO auth_sessions (token_hash, account_id, created_at, last_seen_at, expires_at)
		VALUES (decode(repeat('ab', 32), 'hex'), $1, now(), now(), now() + interval '1 hour')`, target); err != nil {
		t.Fatal(err)
	}
	if err := NewIdentityStore(pool).ResetAccountTOTP(ctx, admin, target); err != nil {
		t.Fatal(err)
	}
	var enrolled bool
	var step int64
	var sessions, audits int
	if err := pool.QueryRow(ctx, `SELECT totp_enrolled_at IS NOT NULL, last_totp_step,
		(SELECT count(*) FROM auth_sessions WHERE account_id = $2),
		(SELECT count(*) FROM admin_audit_log WHERE actor_account_id = $1 AND action = 'account_totp_reset')
		FROM accounts WHERE id = $2`, admin, target).Scan(&enrolled, &step, &sessions, &audits); err != nil {
		t.Fatal(err)
	}
	if enrolled || step != -1 || sessions != 0 || audits != 1 {
		t.Fatalf("after reset: enrolled=%v step=%d sessions=%d audits=%d", enrolled, step, sessions, audits)
	}
	if err := NewIdentityStore(pool).ResetAccountTOTP(ctx, admin, -5); err == nil {
		t.Fatal("reset of missing account succeeded")
	}
}
