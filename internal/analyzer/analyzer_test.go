package analyzer

import (
	"reflect"
	"testing"
)

func TestAnalyzeAssignsDeterministicCategoriesRiskAndSentiment(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		categories []string
		risk       Risk
		sentiment  Sentiment
	}{
		{
			name:       "actively exploited vulnerability",
			title:      "Actively exploited critical vulnerability in network software",
			categories: []string{"vulnerability", "exploited-vulnerability"},
			risk:       RiskCritical,
			sentiment:  SentimentNegative,
		},
		{
			name:       "patched software issue",
			title:      "Vendor releases patch for a security flaw",
			categories: []string{"vulnerability"},
			risk:       RiskMedium,
			sentiment:  SentimentPositive,
		},
		{
			name:       "cloud outage",
			title:      "Cloud provider reports regional outage",
			categories: []string{"cloud-infrastructure", "internet-outage-ddos"},
			risk:       RiskLow,
			sentiment:  SentimentNeutral,
		},
		{
			name:       "unmatched headline",
			title:      "Agency publishes its annual report",
			categories: []string{"other"},
			risk:       RiskInformational,
			sentiment:  SentimentNeutral,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got := Analyze(testCase.title)
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
