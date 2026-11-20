package postgres

import (
	"strings"
	"testing"
)

func TestMigrationVersionsAreStrictlyIncreasing(t *testing.T) {
	previous := 0
	for _, m := range migrations {
		if m.version <= previous {
			t.Fatalf("migration version %d does not follow %d", m.version, previous)
		}
		previous = m.version
		if strings.TrimSpace(m.sql) == "" {
			t.Fatalf("migration %d is empty", m.version)
		}
	}
}

func TestNCSCCCCSSecurelistSeedsAreHeadlineOnly(t *testing.T) {
	sql := ncscCCCSSecurelistMigration
	for _, id := range []string{"uk-ncsc", "cccs-alerts-advisories", "cccs-news-events-guidance", "kaspersky-securelist"} {
		if !strings.Contains(sql, "'"+id+"'") {
			t.Errorf("missing source %s", id)
		}
	}
	if got := strings.Count(sql, "'headline_link'"); got != 4 {
		t.Errorf("headline_link count = %d, want 4", got)
	}
	for _, banned := range []string{"'full_text'", "'system_summary'", "'verbatim_excerpt'", "http://"} {
		if strings.Contains(sql, banned) {
			t.Errorf("unexpected %s", banned)
		}
	}
	if !strings.Contains(sql, "Open Government Licence v3.0") || !strings.Contains(sql, "Securelist blog") {
		t.Error("required attribution text missing")
	}
}
