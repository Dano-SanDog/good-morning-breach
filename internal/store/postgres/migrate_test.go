package postgres

import (
	"strings"
	"testing"
)

func TestMigrationVersionsAreSequential(t *testing.T) {
	for i, m := range migrations {
		if m.version != i+1 {
			t.Fatalf("migration %d has version %d", i+1, m.version)
		}
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
