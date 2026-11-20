package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/analyzer"
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

func (s *IdentityStore) ListAccounts(ctx context.Context) ([]identity.ManagedAccount, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()

	rows, err := s.pool.Query(queryCtx, `SELECT
		id, email, role, enabled, totp_required, totp_enrolled_at IS NOT NULL, created_at
		FROM accounts
		ORDER BY email`)
	if err != nil {
		return nil, fmt.Errorf("query managed accounts: %w", err)
	}
	defer rows.Close()

	var accounts []identity.ManagedAccount
	for rows.Next() {
		var account identity.ManagedAccount
		if err := rows.Scan(
			&account.ID,
			&account.Email,
			&account.Role,
			&account.Enabled,
			&account.TOTPRequired,
			&account.TOTPEnrolled,
			&account.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan managed account: %w", err)
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read managed accounts: %w", err)
	}
	return accounts, nil
}

func (s *IdentityStore) CreateAccount(
	ctx context.Context,
	actorID int64,
	email, passwordHash, role string,
) (identity.ManagedAccount, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()

	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return identity.ManagedAccount{}, fmt.Errorf("begin account creation: %w", err)
	}
	defer rollback(tx)
	if err := lockAccountAdministration(queryCtx, tx); err != nil {
		return identity.ManagedAccount{}, err
	}
	if err := requireActiveAdmin(queryCtx, tx, actorID); err != nil {
		return identity.ManagedAccount{}, err
	}

	var account identity.ManagedAccount
	err = tx.QueryRow(queryCtx, `INSERT INTO accounts (email, password_hash, role)
		VALUES ($1, $2, $3)
		ON CONFLICT (email) DO NOTHING
		RETURNING id, email, role, enabled, totp_required, false, created_at`,
		email, passwordHash, role,
	).Scan(
		&account.ID,
		&account.Email,
		&account.Role,
		&account.Enabled,
		&account.TOTPRequired,
		&account.TOTPEnrolled,
		&account.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ManagedAccount{}, identity.ErrAccountExists
	}
	if err != nil {
		return identity.ManagedAccount{}, fmt.Errorf("create account: %w", err)
	}
	details, err := json.Marshal(map[string]string{"role": role})
	if err != nil {
		return identity.ManagedAccount{}, fmt.Errorf("encode account creation audit details: %w", err)
	}
	if err := insertAdminAudit(queryCtx, tx, actorID, account.ID, "account_created", details); err != nil {
		return identity.ManagedAccount{}, err
	}
	if err := tx.Commit(queryCtx); err != nil {
		return identity.ManagedAccount{}, fmt.Errorf("commit account creation: %w", err)
	}
	return account, nil
}

func (s *IdentityStore) UpdateAccount(
	ctx context.Context,
	actorID, targetID int64,
	role *string,
	enabled *bool,
) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()

	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return fmt.Errorf("begin account update: %w", err)
	}
	defer rollback(tx)
	if err := lockAccountAdministration(queryCtx, tx); err != nil {
		return err
	}
	if err := requireActiveAdmin(queryCtx, tx, actorID); err != nil {
		return err
	}

	var currentRole string
	var currentEnabled bool
	err = tx.QueryRow(queryCtx, `SELECT role, enabled FROM accounts
		WHERE id = $1 FOR UPDATE`, targetID).Scan(&currentRole, &currentEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("load account for update: %w", err)
	}

	updatedRole := currentRole
	if role != nil {
		updatedRole = *role
	}
	updatedEnabled := currentEnabled
	if enabled != nil {
		updatedEnabled = *enabled
	}
	if currentRole == "admin" && currentEnabled &&
		(updatedRole != "admin" || !updatedEnabled) {
		if err := requireAnotherActiveAdmin(queryCtx, tx); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(queryCtx, `UPDATE accounts SET role = $2, enabled = $3
		WHERE id = $1`, targetID, updatedRole, updatedEnabled); err != nil {
		return fmt.Errorf("update account: %w", err)
	}
	if currentEnabled && !updatedEnabled {
		if _, err := tx.Exec(queryCtx, `DELETE FROM auth_sessions WHERE account_id = $1`, targetID); err != nil {
			return fmt.Errorf("revoke disabled account sessions: %w", err)
		}
	}

	details := make(map[string]any, 2)
	if role != nil {
		details["role"] = updatedRole
	}
	if enabled != nil {
		details["enabled"] = updatedEnabled
	}
	encodedDetails, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode account update audit details: %w", err)
	}
	if err := insertAdminAudit(queryCtx, tx, actorID, targetID, "account_updated", encodedDetails); err != nil {
		return err
	}
	if err := tx.Commit(queryCtx); err != nil {
		return fmt.Errorf("commit account update: %w", err)
	}
	return nil
}

func (s *IdentityStore) DeleteAccount(ctx context.Context, actorID, targetID int64) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()

	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return fmt.Errorf("begin account deletion: %w", err)
	}
	defer rollback(tx)
	if err := lockAccountAdministration(queryCtx, tx); err != nil {
		return err
	}
	if err := requireActiveAdmin(queryCtx, tx, actorID); err != nil {
		return err
	}

	var role string
	var enabled bool
	err = tx.QueryRow(queryCtx, `SELECT role, enabled FROM accounts
		WHERE id = $1 FOR UPDATE`, targetID).Scan(&role, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("load account for deletion: %w", err)
	}
	if role == "admin" && enabled {
		if err := requireAnotherActiveAdmin(queryCtx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(queryCtx, `DELETE FROM accounts WHERE id = $1`, targetID); err != nil {
		return fmt.Errorf("delete account: %w", err)
	}
	if err := insertAdminAudit(queryCtx, tx, actorID, targetID, "account_deleted", []byte(`{}`)); err != nil {
		return err
	}
	if err := tx.Commit(queryCtx); err != nil {
		return fmt.Errorf("commit account deletion: %w", err)
	}
	return nil
}

func (s *IdentityStore) ListAdminAudit(ctx context.Context) ([]identity.AdminAuditRecord, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()

	rows, err := s.pool.Query(queryCtx, `SELECT
		id, actor_account_id, COALESCE(target_account_id, 0), target_kind,
		COALESCE(target_id, target_account_id::text, ''), action, details::text, created_at
		FROM admin_audit_log
		ORDER BY created_at DESC, id DESC
		LIMIT 200`)
	if err != nil {
		return nil, fmt.Errorf("query administrator audit log: %w", err)
	}
	defer rows.Close()

	var records []identity.AdminAuditRecord
	for rows.Next() {
		var record identity.AdminAuditRecord
		if err := rows.Scan(
			&record.ID,
			&record.ActorAccountID,
			&record.TargetAccountID,
			&record.TargetKind,
			&record.TargetID,
			&record.Action,
			&record.Details,
			&record.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan administrator audit record: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read administrator audit log: %w", err)
	}
	return records, nil
}

func lockAccountAdministration(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, adminBootstrapLockID); err != nil {
		return fmt.Errorf("lock account administration: %w", err)
	}
	return nil
}

func requireActiveAdmin(ctx context.Context, tx pgx.Tx, actorID int64) error {
	var role string
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT role, enabled FROM accounts
		WHERE id = $1 FOR UPDATE`, actorID).Scan(&role, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ErrAdminRequired
	}
	if err != nil {
		return fmt.Errorf("verify administrator account: %w", err)
	}
	if role != "admin" || !enabled {
		return identity.ErrAdminRequired
	}
	return nil
}

func requireAnotherActiveAdmin(ctx context.Context, tx pgx.Tx) error {
	var activeAdmins int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM accounts
		WHERE role = 'admin' AND enabled`).Scan(&activeAdmins); err != nil {
		return fmt.Errorf("count active administrator accounts: %w", err)
	}
	if activeAdmins <= 1 {
		return identity.ErrLastAdmin
	}
	return nil
}

func insertAdminAudit(
	ctx context.Context,
	tx pgx.Tx,
	actorID, targetID int64,
	action string,
	details []byte,
) error {
	if _, err := tx.Exec(ctx, `INSERT INTO admin_audit_log (
		actor_account_id, target_account_id, action, details
	) VALUES ($1, $2, $3, $4)`, actorID, targetID, action, details); err != nil {
		return fmt.Errorf("record administrator action: %w", err)
	}
	return nil
}

func (s *IdentityStore) AccountByEmail(ctx context.Context, email string) (identity.Account, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	account, err := scanAccount(s.pool.QueryRow(queryCtx, `SELECT
		id, email, role, password_hash, enabled, totp_required,
		totp_secret_ciphertext, totp_nonce, totp_enrolled_at,
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
	return s.createSession(ctx, previousHash, tokenHash, accountID, now, &partialExpiresAt)
}

func (s *IdentityStore) CreateSession(
	ctx context.Context,
	previousHash, tokenHash []byte,
	accountID int64,
	now time.Time,
) error {
	return s.createSession(ctx, previousHash, tokenHash, accountID, now, nil)
}

func (s *IdentityStore) createSession(
	ctx context.Context,
	previousHash, tokenHash []byte,
	accountID int64,
	now time.Time,
	partialExpiresAt *time.Time,
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
		return fmt.Errorf("create sign-in session: %w", err)
	}
	if err := tx.Commit(queryCtx); err != nil {
		return fmt.Errorf("commit sign-in session: %w", err)
	}
	return nil
}

func (s *IdentityStore) LoadSession(ctx context.Context, tokenHash []byte, now time.Time) (identity.Session, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	var session identity.Session
	var enrolledAt *time.Time
	err := s.pool.QueryRow(queryCtx, `SELECT
		a.id, a.email, a.role, a.password_hash, a.enabled, a.totp_required,
		a.totp_secret_ciphertext, a.totp_nonce, a.totp_enrolled_at, a.last_totp_step, a.locked_until,
		s.created_at, s.last_seen_at, s.expires_at, s.partial_expires_at
		FROM auth_sessions s JOIN accounts a ON a.id = s.account_id
		WHERE s.token_hash = $1`, tokenHash).Scan(
		&session.Account.ID,
		&session.Account.Email,
		&session.Account.Role,
		&session.Account.PasswordHash,
		&session.Account.Enabled,
		&session.Account.TOTPRequired,
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
		a.id, a.email, a.role, a.password_hash, a.enabled, a.totp_required,
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
		&account.TOTPRequired,
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

func (s *IdentityStore) ListStories(ctx context.Context, filter identity.StoryFilter) ([]identity.Story, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	rows, err := s.pool.Query(queryCtx, `SELECT
		stories.id, stories.title, stories.canonical_url,
		COALESCE(stories.published_at, stories.created_at),
		array_agg(DISTINCT data_sources.name ORDER BY data_sources.name),
		array_agg(DISTINCT data_sources.attribution ORDER BY data_sources.attribution),
		stories.risk,
		stories.sentiment,
		array_agg(DISTINCT categories.name ORDER BY categories.name),
		COALESCE(
			(SELECT jsonb_agg(jsonb_build_object(
				'id', attack_techniques.technique_id,
				'name', attack_techniques.name,
				'tactics', attack_techniques.tactics
			) ORDER BY attack_techniques.technique_id)
			FROM story_techniques
			JOIN attack_techniques ON attack_techniques.technique_id = story_techniques.technique_id
			WHERE story_techniques.story_id = stories.id),
			'[]'::jsonb
		)
		FROM stories
		JOIN story_sources ON story_sources.story_id = stories.id
		JOIN data_sources ON data_sources.id = story_sources.source_id
		JOIN story_categories ON story_categories.story_id = stories.id
		JOIN categories ON categories.id = story_categories.category_id
		WHERE COALESCE(stories.published_at, stories.created_at) >= $1
		AND ($2::timestamptz IS NULL OR COALESCE(stories.published_at, stories.created_at) < $2)
		AND ($3 = '' OR to_tsvector('english', stories.title) @@ plainto_tsquery('english', $3))
		AND ($4 = '' OR stories.risk = $4)
		AND ($5 = '' OR EXISTS (SELECT 1 FROM story_categories sc
			JOIN categories cat ON cat.id = sc.category_id
			WHERE sc.story_id = stories.id AND lower(cat.name) = lower($5)))
		AND ($6 = '' OR EXISTS (SELECT 1 FROM story_sources ss
			JOIN data_sources src ON src.id = ss.source_id
			WHERE ss.story_id = stories.id AND lower(src.name) = lower($6)))
		AND ($7 = '' OR EXISTS (SELECT 1 FROM story_techniques st
			JOIN attack_techniques at ON at.technique_id = st.technique_id
			WHERE st.story_id = stories.id AND (lower(at.technique_id) = lower($7) OR lower(at.name) = lower($7)
				OR EXISTS (SELECT 1 FROM unnest(at.tactics) tactic WHERE lower(tactic) = lower($7)))))
		GROUP BY stories.id
		ORDER BY CASE stories.risk
			WHEN 'Critical' THEN 0
			WHEN 'High' THEN 1
			WHEN 'Medium' THEN 2
			WHEN 'Low' THEN 3
			ELSE 4
		END,
		COALESCE(stories.published_at, stories.created_at) DESC, stories.id DESC
		LIMIT 101 OFFSET $8`, filter.After, filter.Before, filter.Search, filter.Risk,
		filter.Category, filter.Source, filter.Attack, filter.Offset)
	if err != nil {
		return nil, fmt.Errorf("query recent stories: %w", err)
	}
	defer rows.Close()
	var stories []identity.Story
	for rows.Next() {
		var story identity.Story
		var attackTechniquesJSON []byte
		if err := rows.Scan(
			&story.ID,
			&story.Title,
			&story.URL,
			&story.PublishedAt,
			&story.Sources,
			&story.Attributions,
			&story.Risk,
			&story.Sentiment,
			&story.Categories,
			&attackTechniquesJSON,
		); err != nil {
			return nil, fmt.Errorf("scan recent story: %w", err)
		}
		if err := json.Unmarshal(attackTechniquesJSON, &story.AttackTechniques); err != nil {
			return nil, fmt.Errorf("decode recent story ATT&CK techniques: %w", err)
		}
		for i := range story.AttackTechniques {
			url, ok := analyzer.TechniqueURL(story.AttackTechniques[i].ID)
			if !ok {
				return nil, fmt.Errorf("stored ATT&CK technique ID %q is invalid", story.AttackTechniques[i].ID)
			}
			story.AttackTechniques[i].URL = url
		}
		stories = append(stories, story)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read recent stories: %w", err)
	}
	return stories, nil
}

func (s *IdentityStore) ListSourceStatuses(ctx context.Context) ([]identity.SourceStatus, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	rows, err := s.pool.Query(queryCtx, `SELECT sources.id, sources.name, sources.enabled,
		sources.last_success_at, sources.last_failure_at, sources.last_failure_cause,
		(SELECT MIN(runs.finished_at) FROM collection_runs AS runs
		 WHERE runs.source_id = sources.id AND runs.outcome = 'failure'
		   AND (sources.last_success_at IS NULL OR runs.finished_at > sources.last_success_at))
		FROM data_sources AS sources ORDER BY sources.name, sources.id`)
	if err != nil {
		return nil, fmt.Errorf("query source statuses: %w", err)
	}
	defer rows.Close()
	var statuses []identity.SourceStatus
	for rows.Next() {
		var status identity.SourceStatus
		if err := rows.Scan(&status.ID, &status.Name, &status.Enabled, &status.LastSuccessAt,
			&status.LastFailureAt, &status.LastFailureCause, &status.FailingSince); err != nil {
			return nil, fmt.Errorf("scan source status: %w", err)
		}
		statuses = append(statuses, status)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read source statuses: %w", err)
	}
	return statuses, nil
}

func (s *IdentityStore) GetAlertSettings(ctx context.Context, accountID int64) (identity.AlertSettings, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	var settings identity.AlertSettings
	err := s.pool.QueryRow(queryCtx, `SELECT enabled, alert_time, time_zone, days, minimum_risk
		FROM alert_settings WHERE account_id = $1`, accountID).Scan(
		&settings.Enabled, &settings.Time, &settings.TimeZone, &settings.Days, &settings.MinimumRisk)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.AlertSettings{Enabled: true, Time: "07:00", Days: []int16{0, 1, 2, 3, 4, 5, 6}, MinimumRisk: "Medium"}, nil
	}
	if err != nil {
		return identity.AlertSettings{}, fmt.Errorf("read alert settings: %w", err)
	}
	return settings, nil
}

func (s *IdentityStore) SaveAlertSettings(ctx context.Context, accountID int64, settings identity.AlertSettings) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	_, err := s.pool.Exec(queryCtx, `INSERT INTO alert_settings (account_id, enabled, alert_time, time_zone, days, minimum_risk)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (account_id) DO UPDATE SET enabled = EXCLUDED.enabled, alert_time = EXCLUDED.alert_time,
		time_zone = EXCLUDED.time_zone, days = EXCLUDED.days, minimum_risk = EXCLUDED.minimum_risk`,
		accountID, settings.Enabled, settings.Time, settings.TimeZone, settings.Days, settings.MinimumRisk)
	if err != nil {
		return fmt.Errorf("save alert settings: %w", err)
	}
	return nil
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
		&account.TOTPRequired,
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

func (s *IdentityStore) CreateResetToken(ctx context.Context, email string, tokenHash []byte, now, expires time.Time, limit int, window time.Duration) (string, bool, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return "", false, fmt.Errorf("begin password reset request: %w", err)
	}
	defer rollback(tx)
	var accountID int64
	var accountEmail string
	err = tx.QueryRow(queryCtx, `SELECT id, email FROM accounts WHERE email = $1 AND enabled FOR UPDATE`, email).
		Scan(&accountID, &accountEmail)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("find password reset account: %w", err)
	}
	var recent int
	if err := tx.QueryRow(queryCtx, `SELECT count(*) FROM password_reset_tokens
		WHERE account_id = $1 AND created_at > $2`, accountID, now.Add(-window)).Scan(&recent); err != nil {
		return "", false, fmt.Errorf("count password reset requests: %w", err)
	}
	if recent >= limit {
		return "", false, nil
	}
	if _, err := tx.Exec(queryCtx, `DELETE FROM password_reset_tokens WHERE account_id = $1 AND expires_at <= $2 AND created_at <= $3`,
		accountID, now, now.Add(-window)); err != nil {
		return "", false, fmt.Errorf("delete expired password reset tokens: %w", err)
	}
	if _, err := tx.Exec(queryCtx, `INSERT INTO password_reset_tokens (token_hash, account_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4)`, tokenHash, accountID, now, expires); err != nil {
		return "", false, fmt.Errorf("save password reset token: %w", err)
	}
	if err := tx.Commit(queryCtx); err != nil {
		return "", false, fmt.Errorf("commit password reset request: %w", err)
	}
	return accountEmail, true, nil
}

func (s *IdentityStore) ConsumeResetToken(ctx context.Context, tokenHash []byte, passwordHash string, now time.Time) (int64, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return 0, fmt.Errorf("begin password reset: %w", err)
	}
	defer rollback(tx)
	var accountID int64
	err = tx.QueryRow(queryCtx, `DELETE FROM password_reset_tokens AS tokens USING accounts
		WHERE tokens.token_hash = $1 AND tokens.expires_at > $2
		AND accounts.id = tokens.account_id AND accounts.enabled
		RETURNING tokens.account_id`, tokenHash, now).Scan(&accountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, identity.ErrResetToken
	}
	if err != nil {
		return 0, fmt.Errorf("use password reset token: %w", err)
	}
	if _, err := tx.Exec(queryCtx, `UPDATE accounts SET password_hash = $2 WHERE id = $1`, accountID, passwordHash); err != nil {
		return 0, fmt.Errorf("set reset password: %w", err)
	}
	if _, err := tx.Exec(queryCtx, `DELETE FROM password_reset_tokens WHERE account_id = $1`, accountID); err != nil {
		return 0, fmt.Errorf("delete other password reset tokens: %w", err)
	}
	if _, err := tx.Exec(queryCtx, `DELETE FROM auth_sessions WHERE account_id = $1`, accountID); err != nil {
		return 0, fmt.Errorf("end sessions after password reset: %w", err)
	}
	if err := tx.Commit(queryCtx); err != nil {
		return 0, fmt.Errorf("commit password reset: %w", err)
	}
	return accountID, nil
}

var _ identity.ResetStore = (*IdentityStore)(nil)
