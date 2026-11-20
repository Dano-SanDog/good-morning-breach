package postgres

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/alerting"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires a scratch database that already has every migration applied.
func TestAlertChannelsWithMigratedPostgres(t *testing.T) {
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

	var account int64
	if err := pool.QueryRow(ctx, `INSERT INTO accounts (email, password_hash, role)
		VALUES ('channels@example.test', 'x', 'user') RETURNING id`).Scan(&account); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, account) })
	if _, err := pool.Exec(ctx, `INSERT INTO alert_settings (account_id, alert_time, time_zone, days, minimum_risk, enabled)
		VALUES ($1, '07:00', 'UTC', '{0,1,2,3,4,5,6}', 'Medium', true)`, account); err != nil {
		t.Fatal(err)
	}

	store := NewAlertStore(pool)
	now := time.Now()

	record, err := store.GetContacts(ctx, account)
	if err != nil || !record.EmailEnabled || record.SlackEnabled || record.SMSEnabled {
		t.Fatalf("defaults: %+v %v", record, err)
	}
	if err := store.SaveChannels(ctx, account, true, true, false); err == nil {
		t.Fatal("Slack enabled without a webhook was stored")
	}
	if err := store.SaveSlackWebhook(ctx, account, []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	if err := store.StartPhoneVerification(ctx, account, "+15551234567", []byte("h"), now.Add(10*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	record, _ = store.GetContacts(ctx, account)
	if !record.SlackEnabled || record.PendingPhone != "+15551234567" || record.PhoneVerified {
		t.Fatalf("after webhook and code: %+v", record)
	}
	v, found, err := store.ConsumeVerificationAttempt(ctx, account, 5, now)
	if err != nil || !found || v.FailedAttempts != 1 {
		t.Fatalf("verification: %+v %v %v", v, found, err)
	}
	// Parallel guesses must never obtain more than the remaining attempts.
	var granted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, err := store.ConsumeVerificationAttempt(ctx, account, 5, now); err == nil && ok {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()
	if granted.Load() != 4 {
		t.Fatalf("parallel attempts granted = %d, want 4", granted.Load())
	}
	if _, ok, _ := store.ConsumeVerificationAttempt(ctx, account, 5, now.Add(11*time.Minute)); ok {
		t.Fatal("expired code consumed an attempt")
	}
	if err := store.StartPhoneVerification(ctx, account, "+15551234567", []byte("h"), now.Add(10*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmPhone(ctx, account, "+15551234567", now); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.ConsumeVerificationAttempt(ctx, account, 5, now); found {
		t.Fatal("verification kept after confirmation")
	}

	recipients, err := store.ListRecipients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got *alerting.Recipient
	for i := range recipients {
		if recipients[i].AccountID == account {
			got = &recipients[i]
		}
	}
	if got == nil || !got.Contacts.SMSEnabled || !got.Contacts.PhoneVerified || got.Contacts.Phone != "+15551234567" ||
		string(got.Contacts.SlackWebhookSealed) != "sealed" {
		t.Fatalf("recipient: %+v", got)
	}

	slot := now.Truncate(time.Minute)
	if err := store.RecordFailure(ctx, account, "slack", slot, now, "Slack returned HTTP 500"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSuccess(ctx, account, "sms", slot, now, now, 2); err != nil {
		t.Fatal(err)
	}
	recipients, _ = store.ListRecipients(ctx)
	for _, r := range recipients {
		if r.AccountID == account && (r.States["slack"].RetryAttempts != 1 || r.States["sms"].LastSentSlotAt == nil || r.States["email"].LastSentSlotAt != nil) {
			t.Fatalf("states: %+v", r.States)
		}
	}

	if err := store.DisableSMS(ctx, account); err != nil {
		t.Fatal(err)
	}
	record, _ = store.GetContacts(ctx, account)
	if record.SMSEnabled || !record.PhoneVerified {
		t.Fatalf("after opt-out: %+v", record)
	}

	quota := alerting.Quota{Kind: "sms_code", PerAccount: 3, Window: time.Hour}
	for i := 0; i < 3; i++ {
		if ok, err := store.ReserveMessage(ctx, account, quota, now); !ok || err != nil {
			t.Fatalf("reservation %d: %v %v", i, ok, err)
		}
	}
	if ok, _ := store.ReserveMessage(ctx, account, quota, now); ok {
		t.Fatal("per-account limit not enforced")
	}
	if ok, _ := store.ReserveMessage(ctx, account, alerting.Quota{Kind: "sms_code", GlobalDaily: 3}, now); ok {
		t.Fatal("daily cap not enforced")
	}
	if ok, _ := store.ReserveMessage(ctx, account, quota, now.Add(2*time.Hour)); !ok {
		t.Fatal("limit did not reset after the window")
	}
}
