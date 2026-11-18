package analyzer

import "strings"

type Risk string

const (
	RiskCritical      Risk = "Critical"
	RiskHigh          Risk = "High"
	RiskMedium        Risk = "Medium"
	RiskLow           Risk = "Low"
	RiskInformational Risk = "Informational"
)

type Sentiment string

const (
	SentimentNegative Sentiment = "Negative"
	SentimentNeutral  Sentiment = "Neutral"
	SentimentPositive Sentiment = "Positive"
)

type Result struct {
	Categories []string
	Risk       Risk
	Sentiment  Sentiment
}

type categoryRule struct {
	id       string
	keywords []string
}

var categoryRules = []categoryRule{
	{id: "vulnerability", keywords: []string{"cve-", "vulnerability", "vulnerabilities", "security flaw", "zero-day", "zero day", "patch", "remote code execution"}},
	{id: "exploited-vulnerability", keywords: []string{"actively exploited", "exploited in the wild", "known exploited", "cisa kev"}},
	{id: "ransomware", keywords: []string{"ransomware"}},
	{id: "malware", keywords: []string{"malware", "botnet", "trojan", "infostealer", "spyware", "backdoor"}},
	{id: "data-breach", keywords: []string{"data breach", "breach exposes", "exposed data", "records exposed", "data leak"}},
	{id: "phishing-social-engineering", keywords: []string{"phishing", "social engineering", "credential theft", "scam"}},
	{id: "nation-state-activity", keywords: []string{"nation-state", "nation state", "state-sponsored", "state sponsored", "state-backed", "state backed"}},
	{id: "supply-chain", keywords: []string{"supply chain", "third-party", "third party", "dependency", "software package"}},
	{id: "cloud-infrastructure", keywords: []string{"cloud", "infrastructure", "aws", "azure", "kubernetes"}},
	{id: "internet-outage-ddos", keywords: []string{"outage", "ddos", "denial of service", "bgp", "route leak", "route hijack"}},
	{id: "policy-regulation", keywords: []string{"policy", "regulation", "legislation", "sanction"}},
}

func Analyze(title string) Result {
	normalized := strings.ToLower(title)
	categories := make([]string, 0, len(categoryRules))
	for _, rule := range categoryRules {
		if containsAny(normalized, rule.keywords) {
			categories = append(categories, rule.id)
		}
	}
	if len(categories) == 0 {
		categories = append(categories, "other")
	}

	return Result{
		Categories: categories,
		Risk:       scoreRisk(normalized, categories),
		Sentiment:  scoreSentiment(normalized, categories),
	}
}

func scoreRisk(title string, categories []string) Risk {
	switch {
	case containsAny(title, []string{
		"actively exploited",
		"zero-day exploited",
		"zero day exploited",
		"emergency patch",
		"critical vulnerability exploited",
	}):
		return RiskCritical
	case containsAny(title, []string{
		"ransomware",
		"data breach",
		"remote code execution",
		"exploited in the wild",
		"known exploited",
		"critical vulnerability",
	}):
		return RiskHigh
	case hasCategory(categories,
		"vulnerability",
		"exploited-vulnerability",
		"malware",
		"data-breach",
		"phishing-social-engineering",
		"nation-state-activity",
		"supply-chain",
	):
		return RiskMedium
	case hasCategory(categories, "cloud-infrastructure", "internet-outage-ddos"):
		return RiskLow
	default:
		return RiskInformational
	}
}

func scoreSentiment(title string, categories []string) Sentiment {
	if containsAny(title, []string{"patch", "fixed", "resolved", "mitigated", "recovered"}) &&
		!hasCategory(categories,
			"exploited-vulnerability",
			"ransomware",
			"malware",
			"data-breach",
			"phishing-social-engineering",
		) {
		return SentimentPositive
	}
	if hasCategory(categories,
		"vulnerability",
		"exploited-vulnerability",
		"ransomware",
		"malware",
		"data-breach",
		"phishing-social-engineering",
		"nation-state-activity",
		"supply-chain",
	) || containsAny(title, []string{"attack", "compromise", "breach", "leak", "exploited"}) {
		return SentimentNegative
	}
	return SentimentNeutral
}

func containsAny(value string, candidates []string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func hasCategory(categories []string, candidates ...string) bool {
	for _, category := range categories {
		for _, candidate := range candidates {
			if category == candidate {
				return true
			}
		}
	}
	return false
}
