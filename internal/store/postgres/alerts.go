package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Dano-SanDog/good-morning-breach/internal/alerting"
	"github.com/Dano-SanDog/good-morning-breach/internal/analyzer"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AlertStore struct {
	pool *pgxpool.Pool
}

func NewAlertStore(pool *pgxpool.Pool) *AlertStore {
	return &AlertStore{pool: pool}
}

func (s *AlertStore) ListRecipients(ctx context.Context) ([]alerting.Recipient, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	rows, err := s.pool.Query(queryCtx, `SELECT accounts.id, accounts.email,
		settings.alert_time, settings.time_zone, settings.days, settings.minimum_risk,
		state.last_sent_slot_at, state.last_alert_at, state.retry_slot_at,
		COALESCE(state.retry_attempts, 0), state.last_attempt_at
		FROM alert_settings AS settings
		JOIN accounts ON accounts.id = settings.account_id
		LEFT JOIN alert_state AS state ON state.account_id = accounts.id
		WHERE settings.enabled AND accounts.enabled
		ORDER BY accounts.id`)
	if err != nil {
		return nil, fmt.Errorf("query alert recipients: %w", err)
	}
	defer rows.Close()
	var recipients []alerting.Recipient
	for rows.Next() {
		var r alerting.Recipient
		if err := rows.Scan(&r.AccountID, &r.Email,
			&r.Settings.Time, &r.Settings.TimeZone, &r.Settings.Days, &r.Settings.MinimumRisk,
			&r.State.LastSentSlotAt, &r.State.LastAlertAt, &r.State.RetrySlotAt,
			&r.State.RetryAttempts, &r.State.LastAttemptAt); err != nil {
			return nil, fmt.Errorf("scan alert recipient: %w", err)
		}
		recipients = append(recipients, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read alert recipients: %w", err)
	}
	return recipients, nil
}

func (s *AlertStore) StoriesForAlert(ctx context.Context, risks []string, since, until time.Time, limit int) ([]alerting.Story, error) {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	rows, err := s.pool.Query(queryCtx, `SELECT
		stories.id, stories.title, stories.canonical_url, stories.published_at,
		array_agg(DISTINCT data_sources.name ORDER BY data_sources.name),
		array_agg(DISTINCT data_sources.attribution ORDER BY data_sources.attribution),
		stories.risk, stories.sentiment,
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
		),
		COALESCE((SELECT array_agg(story_cves.cve_id ORDER BY story_cves.cve_id)
			FROM story_cves WHERE story_cves.story_id = stories.id), '{}'::text[])
		FROM stories
		JOIN story_sources ON story_sources.story_id = stories.id
		JOIN data_sources ON data_sources.id = story_sources.source_id
		JOIN story_categories ON story_categories.story_id = stories.id
		JOIN categories ON categories.id = story_categories.category_id
		WHERE stories.created_at > $1 AND stories.created_at <= $2 AND stories.risk = ANY($3)
		GROUP BY stories.id
		ORDER BY CASE stories.risk
			WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4
		END,
		COALESCE(stories.published_at, stories.created_at) DESC, stories.id DESC
		LIMIT $4`, since, until, risks, limit)
	if err != nil {
		return nil, fmt.Errorf("query alert stories: %w", err)
	}
	defer rows.Close()
	var stories []alerting.Story
	for rows.Next() {
		var story alerting.Story
		var techniquesJSON []byte
		if err := rows.Scan(&story.ID, &story.Title, &story.URL, &story.PublishedAt, &story.Sources, &story.Attributions,
			&story.Risk, &story.Sentiment, &story.Categories, &techniquesJSON, &story.CVEs); err != nil {
			return nil, fmt.Errorf("scan alert story: %w", err)
		}
		var techniques []struct {
			ID      string   `json:"id"`
			Name    string   `json:"name"`
			Tactics []string `json:"tactics"`
		}
		if err := json.Unmarshal(techniquesJSON, &techniques); err != nil {
			return nil, fmt.Errorf("decode alert story ATT&CK techniques: %w", err)
		}
		for _, technique := range techniques {
			url, ok := analyzer.TechniqueURL(technique.ID)
			if !ok {
				return nil, fmt.Errorf("stored ATT&CK technique ID %q is invalid", technique.ID)
			}
			story.Techniques = append(story.Techniques, alerting.Technique{
				ID: technique.ID, Name: technique.Name, Tactics: technique.Tactics, URL: url})
		}
		stories = append(stories, story)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read alert stories: %w", err)
	}
	if err := s.attachRelated(queryCtx, stories); err != nil {
		return nil, err
	}
	return stories, nil
}

const maxRelatedPerAlertStory = 3

// attachRelated adds headline-and-link references to other stories that name
// the same CVE (FR-1.13).
func (s *AlertStore) attachRelated(ctx context.Context, stories []alerting.Story) error {
	byID := make(map[int64]*alerting.Story)
	ids := make([]int64, 0, len(stories))
	for i := range stories {
		if len(stories[i].CVEs) > 0 {
			byID[stories[i].ID] = &stories[i]
			ids = append(ids, stories[i].ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := s.pool.Query(ctx, `SELECT story_id, title, canonical_url, cve_id FROM (
			SELECT pairs.story_id, other.title, other.canonical_url, pairs.cve_id,
				row_number() OVER (PARTITION BY pairs.story_id
					ORDER BY COALESCE(other.published_at, other.created_at) DESC, other.id DESC) AS rank
			FROM (
				SELECT DISTINCT ON (mine.story_id, theirs.story_id)
					mine.story_id, theirs.story_id AS other_id, mine.cve_id
				FROM story_cves AS mine
				JOIN story_cves AS theirs ON theirs.cve_id = mine.cve_id AND theirs.story_id <> mine.story_id
				WHERE mine.story_id = ANY($1)
				ORDER BY mine.story_id, theirs.story_id, mine.cve_id
			) AS pairs
			JOIN stories AS other ON other.id = pairs.other_id
		) AS ranked
		WHERE rank <= $2
		ORDER BY story_id, rank`, ids, maxRelatedPerAlertStory)
	if err != nil {
		return fmt.Errorf("query related alert stories: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var storyID int64
		var related alerting.RelatedStory
		if err := rows.Scan(&storyID, &related.Title, &related.URL, &related.CVE); err != nil {
			return fmt.Errorf("scan related alert story: %w", err)
		}
		if story := byID[storyID]; story != nil {
			story.Related = append(story.Related, related)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read related alert stories: %w", err)
	}
	return nil
}

func (s *AlertStore) RecordSuccess(ctx context.Context, accountID int64, slot, until, attemptedAt time.Time, stories int) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return fmt.Errorf("begin alert success record: %w", err)
	}
	defer rollback(tx)
	if _, err := tx.Exec(queryCtx, `INSERT INTO alert_state
		(account_id, last_sent_slot_at, last_alert_at, retry_slot_at, retry_attempts, last_attempt_at)
		VALUES ($1, $2, $3, NULL, 0, $4)
		ON CONFLICT (account_id) DO UPDATE SET last_sent_slot_at = EXCLUDED.last_sent_slot_at,
		last_alert_at = EXCLUDED.last_alert_at, retry_slot_at = NULL, retry_attempts = 0,
		last_attempt_at = EXCLUDED.last_attempt_at`, accountID, slot, until, attemptedAt); err != nil {
		return fmt.Errorf("save alert state: %w", err)
	}
	if _, err := tx.Exec(queryCtx, `INSERT INTO alert_deliveries
		(account_id, channel, slot_at, attempted_at, outcome, story_count)
		VALUES ($1, 'email', $2, $3, 'success', $4)`, accountID, slot, attemptedAt, stories); err != nil {
		return fmt.Errorf("save alert delivery record: %w", err)
	}
	return tx.Commit(queryCtx)
}

func (s *AlertStore) RecordFailure(ctx context.Context, accountID int64, slot, attemptedAt time.Time, cause string) error {
	queryCtx, cancel := databaseContext(ctx)
	defer cancel()
	if len(cause) > 500 {
		cause = cause[:500]
	}
	tx, err := s.pool.Begin(queryCtx)
	if err != nil {
		return fmt.Errorf("begin alert failure record: %w", err)
	}
	defer rollback(tx)
	if _, err := tx.Exec(queryCtx, `INSERT INTO alert_state
		(account_id, retry_slot_at, retry_attempts, last_attempt_at)
		VALUES ($1, $2, 1, $3)
		ON CONFLICT (account_id) DO UPDATE SET
		retry_attempts = CASE WHEN alert_state.retry_slot_at = EXCLUDED.retry_slot_at
			THEN alert_state.retry_attempts + 1 ELSE 1 END,
		retry_slot_at = EXCLUDED.retry_slot_at,
		last_attempt_at = EXCLUDED.last_attempt_at`, accountID, slot, attemptedAt); err != nil {
		return fmt.Errorf("save alert retry state: %w", err)
	}
	if _, err := tx.Exec(queryCtx, `INSERT INTO alert_deliveries
		(account_id, channel, slot_at, attempted_at, outcome, story_count, failure_cause)
		VALUES ($1, 'email', $2, $3, 'failure', 0, $4)`, accountID, slot, attemptedAt, cause); err != nil {
		return fmt.Errorf("save alert delivery record: %w", err)
	}
	return tx.Commit(queryCtx)
}

var _ alerting.Store = (*AlertStore)(nil)
