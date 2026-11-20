package postgres

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_ingestion.sql
var ingestionMigration string

//go:embed migrations/002_identity.sql
var identityMigration string

//go:embed migrations/003_analysis.sql
var analysisMigration string

//go:embed migrations/004_attack_techniques.sql
var attackMigration string

//go:embed migrations/005_sans_isc.sql
var sansMigration string

//go:embed migrations/006_cert_fr.sql
var certFRMigration string

//go:embed migrations/007_cisa_advisories.sql
var cisaAdvisoriesMigration string

//go:embed migrations/008_eff_deeplinks.sql
var effDeeplinksMigration string

//go:embed migrations/009_admin_management.sql
var adminManagementMigration string

//go:embed migrations/010_per_account_totp_requirement.sql
var perAccountTOTPRequirementMigration string

//go:embed migrations/011_alert_settings.sql
var alertSettingsMigration string

//go:embed migrations/012_alert_delivery.sql
var alertDeliveryMigration string

//go:embed migrations/013_password_reset.sql
var passwordResetMigration string

//go:embed migrations/014_ncsc_cccs_securelist.sql
var ncscCCCSSecurelistMigration string

//go:embed migrations/015_json_sources.sql
var jsonSourcesMigration string

//go:embed migrations/016_threat_news_sources.sql
var threatNewsSourcesMigration string

//go:embed migrations/017_catalog_administration.sql
var catalogAdministrationMigration string

const migrationLockID int64 = 0x47424d

type migration struct {
	version int
	sql     string
}

var migrations = []migration{
	{version: 1, sql: ingestionMigration},
	{version: 2, sql: identityMigration},
	{version: 3, sql: analysisMigration},
	{version: 4, sql: attackMigration},
	{version: 5, sql: sansMigration},
	{version: 6, sql: certFRMigration},
	{version: 7, sql: cisaAdvisoriesMigration},
	{version: 8, sql: effDeeplinksMigration},
	{version: 9, sql: adminManagementMigration},
	{version: 10, sql: perAccountTOTPRequirementMigration},
	{version: 11, sql: alertSettingsMigration},
	{version: 12, sql: alertDeliveryMigration},
	{version: 13, sql: passwordResetMigration},
	{version: 14, sql: ncscCCCSSecurelistMigration},
	{version: 15, sql: jsonSourcesMigration},
	{version: 16, sql: threatNewsSourcesMigration},
	{version: 17, sql: catalogAdministrationMigration},
}

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	migrationCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	_, err := pool.Exec(migrationCtx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
	)`)
	if err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}

	tx, err := pool.Begin(migrationCtx)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer func() {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer rollbackCancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	if _, err := tx.Exec(migrationCtx, `SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	for _, current := range migrations {
		var applied bool
		if err := tx.QueryRow(migrationCtx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`,
			current.version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("check migration version %d: %w", current.version, err)
		}
		if applied {
			continue
		}
		for _, statement := range strings.Split(current.sql, ";") {
			statement = strings.TrimSpace(statement)
			if statement == "" {
				continue
			}
			if _, err := tx.Exec(migrationCtx, statement); err != nil {
				return fmt.Errorf("apply migration %d: %w", current.version, err)
			}
		}
		if _, err := tx.Exec(migrationCtx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`,
			current.version,
		); err != nil {
			return fmt.Errorf("record migration %d: %w", current.version, err)
		}
	}
	if err := tx.Commit(migrationCtx); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}
