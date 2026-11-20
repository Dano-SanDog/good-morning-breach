package analyzer

import (
	"fmt"
	"reflect"
	"testing"
)

func newTestIndex(t *testing.T) *AttackIndex {
	t.Helper()
	index, err := NewAttackIndex()
	if err != nil {
		t.Fatalf("NewAttackIndex returned error: %v", err)
	}
	return index
}

func TestAnalyzeStoryCategoriesRiskAndSentiment(t *testing.T) {
	index := newTestIndex(t)
	tests := []struct {
		name       string
		input      Input
		categories []string
		risk       Risk
		sentiment  Sentiment
	}{
		{
			name:       "exploited critical vulnerability",
			input:      Input{Title: "Critical Fortinet VPN flaw CVE-2026-1234 actively exploited"},
			categories: []string{"exploited-vulnerability", "vulnerability"},
			risk:       RiskCritical,
			sentiment:  SentimentNegative,
		},
		{
			name:       "negated exploitation is not exploited",
			input:      Input{Title: "Vendor patches security flaw, no evidence of exploitation"},
			categories: []string{"vulnerability"},
			risk:       RiskMedium,
			sentiment:  SentimentPositive,
		},
		{
			name:       "word boundaries avoid substring hits",
			input:      Input{Title: "New laws on lawful intercept debated"},
			categories: nil,
		},
		{
			name:       "law enforcement takedown",
			input:      Input{Title: "Police dismantled ransomware gang and arrested suspects"},
			categories: []string{"ransomware"},
			risk:       RiskHigh,
			sentiment:  SentimentPositive,
		},
		{
			name:       "source hint raises KEV floor",
			input:      Input{Title: "Acme Router Command Injection", SourceFormats: []string{"cisa_kev_json"}},
			categories: []string{"exploited-vulnerability", "vulnerability"},
			risk:       RiskHigh,
			sentiment:  SentimentNegative,
		},
		{
			name:       "HIBP hint",
			input:      Input{Title: "Example Corp", SourceFormats: []string{"hibp_breaches_json"}},
			categories: []string{"data-breach"},
			risk:       RiskHigh,
			sentiment:  SentimentNegative,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got := AnalyzeStory(index, testCase.input)
			if testCase.categories == nil {
				if got.Engine != EngineBaseline {
					t.Fatalf("engine = %q; want baseline fallback when there is no semantic signal", got.Engine)
				}
				return
			}
			if got.Engine != EngineSemantic {
				t.Errorf("engine = %q; want semantic", got.Engine)
			}
			if !reflect.DeepEqual(got.Categories, testCase.categories) {
				t.Errorf("categories = %#v; want %#v", got.Categories, testCase.categories)
			}
			if got.Risk != testCase.risk {
				t.Errorf("risk = %q; want %q", got.Risk, testCase.risk)
			}
			if got.Sentiment != testCase.sentiment {
				t.Errorf("sentiment = %q; want %q", got.Sentiment, testCase.sentiment)
			}
		})
	}
}

func TestAnalyzeStoryFallsBackToBaseline(t *testing.T) {
	got := AnalyzeStory(newTestIndex(t), Input{Title: "Agency publishes its annual report"})
	if got.Engine != EngineBaseline || !reflect.DeepEqual(got.Categories, []string{"other"}) {
		t.Fatalf("got engine %q categories %#v; want baseline and other", got.Engine, got.Categories)
	}
}

func TestAnalyzeStoryFallsBackWhenSemanticPathPanics(t *testing.T) {
	original := semanticAnalyzer
	semanticAnalyzer = func(*AttackIndex, Input) (Result, bool) { panic("boom") }
	defer func() { semanticAnalyzer = original }()

	got := AnalyzeStory(newTestIndex(t), Input{Title: "Ransomware gang hits hospital"})
	if got.Engine != EngineBaseline || !reflect.DeepEqual(got.Categories, []string{"ransomware"}) {
		t.Fatalf("got engine %q categories %#v; want baseline ransomware", got.Engine, got.Categories)
	}
}

func TestExtractCVEsNormalizesDeduplicatesAndCaps(t *testing.T) {
	got := ExtractCVEs("cve-2026-0001 and CVE-2026-0001, CVE-2025-12345; XCVE-2026-9999 CVE-26-1")
	want := []string{"CVE-2025-12345", "CVE-2026-0001"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractCVEs = %#v; want %#v", got, want)
	}
	long := ""
	for i := 0; i < 30; i++ {
		long += fmt.Sprintf(" CVE-2026-%04d", 1000+i)
	}
	if got := ExtractCVEs(long); len(got) != maxCVEsPerStory {
		t.Fatalf("got %d CVEs; want %d", len(got), maxCVEsPerStory)
	}
}

func TestAttackCueTechniquesExistInPinnedBundle(t *testing.T) {
	index := newTestIndex(t)
	for _, cue := range attackCues {
		for _, id := range cue.ids {
			if _, ok := index.Lookup(id); !ok {
				t.Errorf("curated technique %s is not in the pinned ATT&CK bundle", id)
			}
		}
	}
}

func TestAnalyzeStoryTagsTechniquesFromCues(t *testing.T) {
	got := AnalyzeStory(newTestIndex(t), Input{Title: "Phishing kits deliver ransomware to hospitals"})
	ids := map[string]bool{}
	for _, technique := range got.AttackTechniques {
		ids[technique.ID] = true
		if technique.URL == "" || len(technique.Tactics) == 0 {
			t.Errorf("technique %s lacks URL or tactics", technique.ID)
		}
	}
	if !ids["T1566"] || !ids["T1486"] {
		t.Fatalf("techniques = %#v; want T1566 and T1486", ids)
	}
	if got := AnalyzeStory(newTestIndex(t), Input{Title: "Agency lists phished users"}); len(got.AttackTechniques) != 0 {
		t.Fatalf("unrelated headline got techniques %#v", got.AttackTechniques)
	}
}

func TestAnalyzeStoryExtractsCVEs(t *testing.T) {
	got := AnalyzeStory(newTestIndex(t), Input{Title: "Patch for CVE-2026-1111 released"})
	if !reflect.DeepEqual(got.CVEs, []string{"CVE-2026-1111"}) {
		t.Fatalf("CVEs = %#v", got.CVEs)
	}
}
