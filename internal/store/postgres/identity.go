package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const adminBootstrapLockID int64 = 0x474241444d

type IdentityStore struct {
	pool *pgxpool.Pool
}

func NewIdentityStore(pool *pgxpool.Pool) *IdentityStore {
	return &IdentityStore{pool: pool}
}

func (s *IdentityStore) CreateAdmin(ctx context.Context, email, passwordHash string) (int64, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()

	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return 0, fmt.Errorf("begin administrator bootstrap: %w", err)
	}
	defer rollback(tx)

	if _, err := tx.Exec(queryCtx, `SELECT pg_advisory_xact_lock($1)`, adminBootstrapLockID); err != nil {
		return 0, fmt.Errorf("lock administrator bootstrap: %w", err)
	}
	var exists bool
	if err := tx.QueryRow(queryCtx,
		`SELECT EXISTS (SELECT 1 FROM accounts WHERE role = 'admin')`,
	).Scan(&exists); err != nil {
		return 0, fmt.Errorf("check administrator account: %w", err)
	}
	if exists {
		return 0, identity.ErrAdminExists
	}
	var accountID int64
	if err := tx.QueryRow(queryCtx,
		`INSERT INTO accounts (email, password_hash, role)
		VALUES ($1, $2, 'admin')
		RETURNING id`,
		email, passwordHash,
	).Scan(&accountID); err != nil {
		return 0, fmt.Errorf("create administrator account: %w", err)
	}
	if err := tx.Commit(queryCtx); err != nil {
		return 0, fmt.Errorf("commit administrator bootstrap: %w", err)
	}
	return accountID, nil
}

func (s *IdentityStore) AccountByEmail(ctx context.Context, email string) (identity.Account, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	account, err := scanAccount(s.pool.QueryRow(queryCtx, `SELECT
		id, email, role, password_hash, enabled,
		totp_secret_ciphertext, totp_nonce, totp_enrolled_at IS NOT NULL,
		last_totp_step, locked_until
		FROM accounts WHERE email = $1`, email))
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Account{}, identity.ErrNotFound
	}
	if err != nil {
		return identity.Account{}, fmt.Errorf("query account for sign-in: %w", err)
	}
	return account, nil
}

func (s *IdentityStore) RecordFailedLogin(ctx context.Context, accountID int64, now time.Time) (bool, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	var lockedUntil *time.Time
	err := s.pool.QueryRow(queryCtx, `UPDATE accounts SET
		failure_window_started_at = CASE
			WHEN failure_window_started_at IS NULL OR failure_window_started_at <= $2 - interval '15 minutes'
			THEN $2 ELSE failure_window_started_at END,
		failed_login_count = CASE
			WHEN failure_window_started_at IS NULL OR failure_window_started_at <= $2 - interval '15 minutes'
			THEN 1 ELSE failed_login_count + 1 END,
		locked_until = CASE
			WHEN locked_until > $2 THEN locked_until
			WHEN failure_window_started_at IS NULL OR failure_window_started_at <= $2 - interval '15 minutes'
			THEN NULL
			WHEN failed_login_count + 1 >= 5 THEN $2 + interval '15 minutes'
			ELSE NULL END
		WHERE id = $1
		RETURNING locked_until`, accountID, now).Scan(&lockedUntil)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, identity.ErrNotFound
		}
		return false, fmt.Errorf("record failed sign-in: %w", err)
	}
	return lockedUntil != nil && lockedUntil.After(now), nil
}

func (s *IdentityStore) CreatePartialSession(
	ctx context.Context,
	previousHash, tokenHash []byte,
	accountID int64,
	now, partialExpiresAt time.Time,
) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return fmt.Errorf("begin sign-in session: %w", err)
	}
	defer rollback(tx)

	if len(previousHash) == 32 {
		if _, err := tx.Exec(queryCtx, `DELETE FROM auth_sessions WHERE token_hash = $1`, previousHash); err != nil {
			return fmt.Errorf("rotate previous sign-in session: %w", err)
		}
	}
	if _, err := tx.Exec(queryCtx, `INSERT INTO auth_sessions (
		token_hash, account_id, created_at, last_seen_at, expires_at, partial_expires_at
	) VALUES ($1, $2, $3, $3, $4, $5)`,
		tokenHash, accountID, now, now.Add(8*time.Hour), partialExpiresAt,
	); err != nil {
		return fmt.Errorf("create partial sign-in session: %w", err)
	}
	if err := tx.Commit(queryCtx); err != nil {
		return fmt.Errorf("commit partial sign-in session: %w", err)
	}
	return nil
}

func (s *IdentityStore) LoadSession(ctx context.Context, tokenHash []byte, now time.Time) (identity.Session, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	var session identity.Session
	var enrolledAt *time.Time
	err := s.pool.QueryRow(queryCtx, `SELECT
		a.id, a.email, a.role, a.password_hash, a.enabled,
		a.totp_secret_ciphertext, a.totp_nonce, a.totp_enrolled_at, a.last_totp_step, a.locked_until,
		s.created_at, s.last_seen_at, s.expires_at, s.partial_expires_at
		FROM auth_sessions s JOIN accounts a ON a.id = s.account_id
		WHERE s.token_hash = $1`, tokenHash).Scan(
		&session.Account.ID,
		&session.Account.Email,
		&session.Account.Role,
		&session.Account.PasswordHash,
		&session.Account.Enabled,
		&session.Account.TOTPSecretCiphertext,
		&session.Account.TOTPNonce,
		&enrolledAt,
		&session.Account.LastTOTPStep,
		&session.Account.LockedUntil,
		&session.CreatedAt,
		&session.LastSeenAt,
		&session.ExpiresAt,
		&session.PartialExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Session{}, identity.ErrSession
	}
	if err != nil {
		return identity.Session{}, fmt.Errorf("load sign-in session: %w", err)
	}
	session.Account.TOTPEnrolled = enrolledAt != nil

	expired := !session.ExpiresAt.After(now) ||
		now.Sub(session.LastSeenAt) > 30*time.Minute ||
		(session.PartialExpiresAt != nil && !session.PartialExpiresAt.After(now)) ||
		!session.Account.Enabled
	if expired {
		if _, err := s.pool.Exec(queryCtx, `DELETE FROM auth_sessions WHERE token_hash = $1`, tokenHash); err != nil {
			return identity.Session{}, fmt.Errorf("remove expired sign-in session: %w", err)
		}
		return identity.Session{}, identity.ErrSession
	}
	return session, nil
}

func (s *IdentityStore) TouchSession(ctx context.Context, tokenHash []byte, now time.Time) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	tag, err := s.pool.Exec(queryCtx, `UPDATE auth_sessions SET last_seen_at = $2
		WHERE token_hash = $1
			AND partial_expires_at IS NULL
			AND expires_at > $2
			AND last_seen_at > $2 - interval '30 minutes'
			AND EXISTS (
				SELECT 1 FROM accounts WHERE accounts.id = auth_sessions.account_id AND accounts.enabled
			)`, tokenHash, now)
	if err != nil {
		return fmt.Errorf("refresh sign-in session: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return identity.ErrSession
	}
	return nil
}

func (s *IdentityStore) BeginTOTPSetup(
	ctx context.Context,
	sessionHash []byte,
	accountID int64,
	ciphertext, nonce []byte,
	now time.Time,
) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	tag, err := s.pool.Exec(queryCtx, `UPDATE accounts a SET
		totp_secret_ciphertext = $3, totp_nonce = $4
		WHERE a.id = $2 AND a.totp_enrolled_at IS NULL AND EXISTS (
			SELECT 1 FROM auth_sessions s
			WHERE s.token_hash = $1 AND s.account_id = a.id
				AND s.partial_expires_at > $5
		)`,
		sessionHash, accountID, ciphertext, nonce, now,
	)
	if err != nil {
		return fmt.Errorf("save pending time-based code: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return identity.ErrTOTPSetup
	}
	return nil
}

func (s *IdentityStore) CompleteTOTP(
	ctx context.Context,
	oldHash, newHash []byte,
	step int64,
	now time.Time,
	setup bool,
) (identity.Account, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return identity.Account{}, fmt.Errorf("begin time-based code verification: %w", err)
	}
	defer rollback(tx)

	var account identity.Account
	var enrolledAt, partialExpiresAt *time.Time
	err = tx.QueryRow(queryCtx, `SELECT
		a.id, a.email, a.role, a.password_hash, a.enabled,
		a.totp_secret_ciphertext, a.totp_nonce, a.totp_enrolled_at, a.last_totp_step, a.locked_until,
		s.partial_expires_at
		FROM auth_sessions s JOIN accounts a ON a.id = s.account_id
		WHERE s.token_hash = $1
		FOR UPDATE OF s, a`, oldHash).Scan(
		&account.ID,
		&account.Email,
		&account.Role,
		&account.PasswordHash,
		&account.Enabled,
		&account.TOTPSecretCiphertext,
		&account.TOTPNonce,
		&enrolledAt,
		&account.LastTOTPStep,
		&account.LockedUntil,
		&partialExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Account{}, identity.ErrSession
	}
	if err != nil {
		return identity.Account{}, fmt.Errorf("load time-based code verification state: %w", err)
	}
	account.TOTPEnrolled = enrolledAt != nil
	if !account.Enabled || partialExpiresAt == nil || !partialExpiresAt.After(now) {
		return identity.Account{}, identity.ErrSession
	}
	if setup == account.TOTPEnrolled {
		return identity.Account{}, identity.ErrTOTPSetup
	}
	if account.TOTPEnrolled && (account.TOTPSecretCiphertext == nil || account.TOTPNonce == nil) {
		return identity.Account{}, errors.New("enrolled account has no time-based code")
	}
	if step <= account.LastTOTPStep {
		return identity.Account{}, identity.ErrOTPReplay
	}
	if account.LockedUntil != nil && account.LockedUntil.After(now) {
		return identity.Account{}, identity.ErrCredentials
	}
	if _, err := tx.Exec(queryCtx, `UPDATE accounts SET
		last_totp_step = $2,
		totp_enrolled_at = CASE WHEN $3 THEN $4 ELSE totp_enrolled_at END,
		failure_window_started_at = NULL,
		failed_login_count = 0,
		locked_until = NULL
		WHERE id = $1`, account.ID, step, setup, now); err != nil {
		return identity.Account{}, fmt.Errorf("complete time-based code verification: %w", err)
	}
	if _, err := tx.Exec(queryCtx, `DELETE FROM auth_sessions WHERE token_hash = $1`, oldHash); err != nil {
		return identity.Account{}, fmt.Errorf("rotate partial sign-in session: %w", err)
	}
	if _, err := tx.Exec(queryCtx, `INSERT INTO auth_sessions (
		token_hash, account_id, created_at, last_seen_at, expires_at
	) VALUES ($1, $2, $3, $3, $4)`, newHash, account.ID, now, now.Add(8*time.Hour)); err != nil {
		return identity.Account{}, fmt.Errorf("create authenticated session: %w", err)
	}
	if err := tx.Commit(queryCtx); err != nil {
		return identity.Account{}, fmt.Errorf("commit time-based code verification: %w", err)
	}
	account.TOTPEnrolled = true
	account.LastTOTPStep = step
	account.LockedUntil = nil
	return account, nil
}

func (s *IdentityStore) DeleteSession(ctx context.Context, tokenHash []byte) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	if _, err := s.pool.Exec(queryCtx, `DELETE FROM auth_sessions WHERE token_hash = $1`, tokenHash); err != nil {
		return fmt.Errorf("delete sign-in session: %w", err)
	}
	return nil
}

func (s *IdentityStore) ListStories(ctx context.Context, after time.Time) ([]identity.Story, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	rows, err := s.pool.Query(queryCtx, `SELECT
		stories.id, stories.title, stories.canonical_url,
		COALESCE(stories.published_at, stories.created_at),
		array_agg(DISTINCT data_sources.name ORDER BY data_sources.name)
		FROM stories
		JOIN story_sources ON story_sources.story_id = stories.id
		JOIN data_sources ON data_sources.id = story_sources.source_id
		WHERE COALESCE(stories.published_at, stories.created_at) >= $1
		GROUP BY stories.id
		ORDER BY COALESCE(stories.published_at, stories.created_at) DESC
		LIMIT 100`, after)
	if err != nil {
		return nil, fmt.Errorf("query recent stories: %w", err)
	}
	defer rows.Close()
	var stories []identity.Story
	for rows.Next() {
		var story identity.Story
		if err := rows.Scan(
			&story.ID,
			&story.Title,
			&story.URL,
			&story.PublishedAt,
			&story.Sources,
		); err != nil {
			return nil, fmt.Errorf("scan recent story: %w", err)
		}
		stories = append(stories, story)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read recent stories: %w", err)
	}
	return stories, nil
}

func scanAccount(row pgx.Row) (identity.Account, error) {
	var account identity.Account
	var enrolledAt *time.Time
	err := row.Scan(
		&account.ID,
		&account.Email,
		&account.Role,
		&account.PasswordHash,
		&account.Enabled,
		&account.TOTPSecretCiphertext,
		&account.TOTPNonce,
		&enrolledAt,
		&account.LastTOTPStep,
		&account.LockedUntil,
	)
	account.TOTPEnrolled = enrolledAt != nil
	return account, err
}

func rollback(tx pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(rollbackCtx)
}

var _ identity.Store = (*IdentityStore)(nil)
