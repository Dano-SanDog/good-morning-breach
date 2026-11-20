package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/alerting"
	"github.com/jackc/pgx/v5"
)

// GetContacts returns the channel state of one account. An account without a
// row uses email only.
func (s *AlertStore) GetContacts(ctx context.Context, accountID int64) (alerting.ContactRecord, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	record := alerting.ContactRecord{EmailEnabled: true}
	err := s.pool.QueryRow(queryCtx, `SELECT email_enabled, slack_enabled, sms_enabled, slack_webhook_sealed,
		COALESCE(phone_e164, ''), phone_verified_at IS NOT NULL
		FROM alert_channel_settings WHERE account_id = $1`, accountID).Scan(
		&record.EmailEnabled, &record.SlackEnabled, &record.SMSEnabled, &record.SlackWebhookSealed,
		&record.Phone, &record.PhoneVerified)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return record, fmt.Errorf("read alert channels: %w", err)
	}
	var pending string
	err = s.pool.QueryRow(queryCtx, `SELECT phone_e164 FROM phone_verifications
		WHERE account_id = $1 AND expires_at > now()`, accountID).Scan(&pending)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return record, fmt.Errorf("read pending phone verification: %w", err)
	}
	record.PendingPhone = pending
	return record, nil
}

func (s *AlertStore) SaveChannels(ctx context.Context, accountID int64, email, slack, sms bool) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	_, err := s.pool.Exec(queryCtx, `INSERT INTO alert_channel_settings (account_id, email_enabled, slack_enabled, sms_enabled)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (account_id) DO UPDATE SET email_enabled = EXCLUDED.email_enabled,
		slack_enabled = EXCLUDED.slack_enabled, sms_enabled = EXCLUDED.sms_enabled`, accountID, email, slack, sms)
	if err != nil {
		return fmt.Errorf("save alert channels: %w", err)
	}
	return nil
}

// SaveSlackWebhook stores the sealed webhook and turns Slack on.
func (s *AlertStore) SaveSlackWebhook(ctx context.Context, accountID int64, sealed []byte) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	_, err := s.pool.Exec(queryCtx, `INSERT INTO alert_channel_settings (account_id, slack_enabled, slack_webhook_sealed)
		VALUES ($1, true, $2)
		ON CONFLICT (account_id) DO UPDATE SET slack_enabled = true, slack_webhook_sealed = EXCLUDED.slack_webhook_sealed`,
		accountID, sealed)
	if err != nil {
		return fmt.Errorf("save Slack webhook: %w", err)
	}
	return nil
}

func (s *AlertStore) StartPhoneVerification(ctx context.Context, accountID int64, phone string, codeHash []byte, expires, now time.Time) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	_, err := s.pool.Exec(queryCtx, `INSERT INTO phone_verifications (account_id, phone_e164, code_hash, expires_at, failed_attempts, created_at)
		VALUES ($1, $2, $3, $4, 0, $5)
		ON CONFLICT (account_id) DO UPDATE SET phone_e164 = EXCLUDED.phone_e164, code_hash = EXCLUDED.code_hash,
		expires_at = EXCLUDED.expires_at, failed_attempts = 0, created_at = EXCLUDED.created_at`,
		accountID, phone, codeHash, expires, now)
	if err != nil {
		return fmt.Errorf("save phone verification: %w", err)
	}
	return nil
}

// ConsumeVerificationAttempt takes one attempt in a single UPDATE, so
// concurrent guesses cannot read the same counter (SC-056).
func (s *AlertStore) ConsumeVerificationAttempt(ctx context.Context, accountID int64, maxAttempts int, now time.Time) (alerting.Verification, bool, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	var v alerting.Verification
	err := s.pool.QueryRow(queryCtx, `UPDATE phone_verifications SET failed_attempts = failed_attempts + 1
		WHERE account_id = $1 AND failed_attempts < $2 AND expires_at > $3
		RETURNING phone_e164, code_hash, expires_at, failed_attempts`, accountID, maxAttempts, now).
		Scan(&v.Phone, &v.CodeHash, &v.ExpiresAt, &v.FailedAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, false, nil
	}
	if err != nil {
		return v, false, fmt.Errorf("read phone verification: %w", err)
	}
	return v, true, nil
}

// ConfirmPhone marks the number verified and removes the pending code. Changing
// the number turns text alerts off until the new number is verified.
func (s *AlertStore) ConfirmPhone(ctx context.Context, accountID int64, phone string, now time.Time) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return fmt.Errorf("begin phone confirmation: %w", err)
	}
	defer rollback(tx)
	if _, err := tx.Exec(queryCtx, `INSERT INTO alert_channel_settings (account_id, phone_e164, phone_verified_at, sms_enabled)
		VALUES ($1, $2, $3, true)
		ON CONFLICT (account_id) DO UPDATE SET phone_e164 = EXCLUDED.phone_e164,
		phone_verified_at = EXCLUDED.phone_verified_at, sms_enabled = true`, accountID, phone, now); err != nil {
		return fmt.Errorf("save verified phone: %w", err)
	}
	if _, err := tx.Exec(queryCtx, `DELETE FROM phone_verifications WHERE account_id = $1`, accountID); err != nil {
		return fmt.Errorf("remove phone verification: %w", err)
	}
	return tx.Commit(queryCtx)
}

// DisableSMS turns text alerts off after the recipient opted out.
func (s *AlertStore) DisableSMS(ctx context.Context, accountID int64) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	_, err := s.pool.Exec(queryCtx, `UPDATE alert_channel_settings SET sms_enabled = false WHERE account_id = $1`, accountID)
	if err != nil {
		return fmt.Errorf("disable text alerts: %w", err)
	}
	return nil
}

// ReserveMessage records one outbound message if the per-account and daily
// limits allow it. The slot is not returned when the send later fails, so a
// failing provider cannot be used to bypass a cap (SC-058).
func (s *AlertStore) ReserveMessage(ctx context.Context, accountID int64, q alerting.Quota, now time.Time) (bool, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return false, fmt.Errorf("begin message reservation: %w", err)
	}
	defer rollback(tx)
	if _, err := tx.Exec(queryCtx, `SELECT pg_advisory_xact_lock(hashtext('outbound_message_log'))`); err != nil {
		return false, fmt.Errorf("lock message quota: %w", err)
	}
	if q.PerAccount > 0 {
		var used int
		if err := tx.QueryRow(queryCtx, `SELECT count(*) FROM outbound_message_log
			WHERE account_id = $1 AND kind = $2 AND sent_at > $3`, accountID, q.Kind, now.Add(-q.Window)).Scan(&used); err != nil {
			return false, fmt.Errorf("count account messages: %w", err)
		}
		if used >= q.PerAccount {
			return false, nil
		}
	}
	if q.GlobalDaily > 0 {
		var used int
		if err := tx.QueryRow(queryCtx, `SELECT count(*) FROM outbound_message_log
			WHERE kind = $1 AND sent_at > $2`, q.Kind, now.Add(-24*time.Hour)).Scan(&used); err != nil {
			return false, fmt.Errorf("count daily text messages: %w", err)
		}
		if used >= q.GlobalDaily {
			return false, nil
		}
	}
	if _, err := tx.Exec(queryCtx, `INSERT INTO outbound_message_log (account_id, kind, sent_at) VALUES ($1, $2, $3)`,
		accountID, q.Kind, now); err != nil {
		return false, fmt.Errorf("record outbound message: %w", err)
	}
	return true, tx.Commit(queryCtx)
}

var _ alerting.ContactStore = (*AlertStore)(nil)
