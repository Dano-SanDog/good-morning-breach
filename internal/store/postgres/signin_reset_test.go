package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires a scratch database that already has every migration applied.
func TestCreateSessionClearsFailedLoginState(t *testing.T) {
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

	var id int64
	if err := pool.QueryRow(ctx, `INSERT INTO accounts (email, password_hash, role)
		VALUES ('signin-reset@example.test', 'x', 'user') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, id)
	})

	store := NewIdentityStore(pool)
	now := time.Now()
	for range 3 {
		if _, err := store.RecordFailedLogin(ctx, id, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.CreateSession(ctx, nil, make([]byte, 32), id, now); err != nil {
		t.Fatal(err)
	}
	var count int
	var started, locked *time.Time
	if err := pool.QueryRow(ctx, `SELECT failed_login_count, failure_window_started_at, locked_until
		FROM accounts WHERE id = $1`, id).Scan(&count, &started, &locked); err != nil {
		t.Fatal(err)
	}
	if count != 0 || started != nil || locked != nil {
		t.Fatalf("lockout state after sign-in = %d, %v, %v; want cleared", count, started, locked)
	}
	// Four more failures must not lock, proving the earlier three were cleared.
	for range 4 {
		if locked, err := store.RecordFailedLogin(ctx, id, now); err != nil || locked {
			t.Fatalf("RecordFailedLogin() = %v, %v; want not locked", locked, err)
		}
	}
}
