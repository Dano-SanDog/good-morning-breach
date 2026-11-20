package analyzer

import (
	"regexp"
	"sort"
	"strings"
)

// Engine names the analysis path that produced a Result.
type Engine string

const (
	EngineBaseline Engine = "baseline"
	EngineSemantic Engine = "semantic"
)

const (
	maxCVEsPerStory     = 10
	categoryThreshold   = 2
	confidenceFullScore = 6
)

var cvePattern = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,7}\b`)

// Input is everything the semantic analyzer may read. It holds only the stored
// headline and the collection formats of the sources that reported the story,
// so no content beyond what a source's license already lets the system store is
// analyzed, and nothing leaves the machine.
type Input struct {
	Title         string
	SourceFormats []string
}

type weightedCue struct {
	phrase string
	weight int
}

var semanticCategoryCues = map[string][]weightedCue{
	"vulnerability": {
		{"vulnerability", 2}, {"vulnerabilities", 2}, {"security flaw", 2}, {"security flaws", 2},
		{"zero-day", 2}, {"zero day", 2}, {"0-day", 2}, {"remote code execution", 2}, {"rce", 2},
		{"privilege escalation", 2}, {"authentication bypass", 2}, {"sql injection", 2},
		{"buffer overflow", 2}, {"cvss", 2}, {"security update", 1}, {"security updates", 1},
		{"patch", 1}, {"patches", 1}, {"patched", 1}, {"security advisory", 1}, {"flaw", 1}, {"flaws", 1},
	},
	"exploited-vulnerability": {
		{"actively exploited", 3}, {"exploited in the wild", 3}, {"known exploited", 3},
		{"under active attack", 3}, {"being exploited", 3}, {"exploited as a zero-day", 3},
		{"exploited as zero-day", 3}, {"in-the-wild exploitation", 3}, {"active exploitation", 3},
		{"exploitation", 1}, {"exploited", 1}, {"exploit", 1}, {"cisa kev", 2}, {"kev catalog", 2},
	},
	"ransomware": {
		{"ransomware", 3}, {"ransom demand", 2}, {"double extortion", 2}, {"extortion gang", 2},
		{"lockbit", 3}, {"blackcat", 3}, {"alphv", 3}, {"akira", 2}, {"clop", 2}, {"play ransomware", 3},
	},
	"malware": {
		{"malware", 3}, {"botnet", 3}, {"trojan", 3}, {"infostealer", 3}, {"info-stealer", 3},
		{"stealer", 2}, {"spyware", 3}, {"backdoor", 3}, {"rootkit", 3}, {"loader", 1}, {"wiper", 3},
		{"keylogger", 3}, {"remote access trojan", 3}, {"malicious package", 2}, {"malicious extension", 2},
		{"malicious app", 2}, {"cryptominer", 2}, {"rat", 1},
	},
	"data-breach": {
		{"data breach", 3}, {"breach exposes", 3}, {"breached", 2}, {"exposed data", 3},
		{"records exposed", 3}, {"data leak", 3}, {"leaked data", 2}, {"data exposure", 3},
		{"customer data", 1}, {"personal data", 1}, {"stolen data", 2}, {"data theft", 2},
		{"exfiltrated", 2}, {"exposed database", 3}, {"breach", 2}, {"leak", 1},
	},
	"phishing-social-engineering": {
		{"phishing", 3}, {"spear-phishing", 3}, {"spearphishing", 3}, {"social engineering", 3},
		{"credential theft", 3}, {"credential harvesting", 3}, {"scam", 2}, {"scams", 2},
		{"smishing", 3}, {"vishing", 3}, {"business email compromise", 3}, {"bec", 2},
		{"impersonation", 1}, {"fake", 1}, {"mfa fatigue", 3}, {"clickfix", 3},
	},
	"nation-state-activity": {
		{"nation-state", 3}, {"nation state", 3}, {"state-sponsored", 3}, {"state sponsored", 3},
		{"state-backed", 3}, {"state backed", 3}, {"apt", 2}, {"espionage", 2}, {"cyber espionage", 3},
		{"north korea", 2}, {"north korean", 2}, {"lazarus", 3}, {"russia-linked", 3}, {"china-linked", 3},
		{"iran-linked", 3}, {"russian hackers", 2}, {"chinese hackers", 2}, {"iranian hackers", 2},
		{"sandworm", 3}, {"volt typhoon", 3}, {"salt typhoon", 3}, {"apt28", 3}, {"apt29", 3},
	},
	"supply-chain": {
		{"supply chain", 3}, {"supply-chain", 3}, {"third-party", 1}, {"third party", 1},
		{"dependency", 1}, {"dependencies", 1}, {"software package", 2}, {"npm", 2}, {"pypi", 2},
		{"rubygems", 2}, {"typosquatting", 3}, {"malicious package", 2}, {"compromised package", 3},
		{"build system", 1}, {"github action", 1}, {"github actions", 1},
	},
	"cloud-infrastructure": {
		{"cloud", 2}, {"aws", 2}, {"azure", 2}, {"google cloud", 2}, {"gcp", 2}, {"kubernetes", 2},
		{"docker", 1}, {"container", 1}, {"s3 bucket", 2}, {"misconfigured", 2}, {"saas", 2},
		{"infrastructure", 1}, {"data center", 1}, {"datacenter", 1},
	},
	"internet-outage-ddos": {
		{"ddos", 3}, {"denial of service", 3}, {"denial-of-service", 3}, {"outage", 3},
		{"bgp", 3}, {"route leak", 3}, {"route hijack", 3}, {"bgp hijack", 3}, {"dns outage", 3},
		{"internet disruption", 3}, {"service disruption", 2}, {"botnet attack", 1}, {"traffic spike", 1},
	},
	"policy-regulation": {
		{"policy", 2}, {"regulation", 3}, {"regulations", 3}, {"legislation", 3}, {"sanction", 2},
		{"sanctions", 2}, {"sanctioned", 2}, {"law", 1}, {"lawmakers", 2}, {"congress", 2},
		{"senate", 2}, {"gdpr", 3}, {"fine", 1}, {"fined", 2}, {"executive order", 3},
		{"compliance", 1}, {"bill", 1}, {"directive", 1}, {"surveillance", 1}, {"privacy", 1},
	},
}

var sourceFormatHints = map[string]struct {
	categories []string
	floor      Risk
}{
	"cisa_kev_json":          {categories: []string{"vulnerability", "exploited-vulnerability"}, floor: RiskHigh},
	"nvd_json":               {categories: []string{"vulnerability"}, floor: RiskHigh},
	"github_advisories_json": {categories: []string{"vulnerability"}, floor: RiskMedium},
	"hibp_breaches_json":     {categories: []string{"data-breach"}, floor: RiskMedium},
}

var negatedExploitation = []string{
	"no evidence of", "not been exploited", "no known exploitation", "not exploited", "unexploited",
	"no signs of exploitation", "no sign of exploitation", "no active exploitation", "not under active attack",
	"not actively exploited", "no exploitation",
}

var positiveSentimentCues = []string{
	"patch", "patches", "patched", "fixed", "fixes", "resolved", "mitigated", "recovered", "restored",
	"arrested", "arrests", "charged", "sentenced", "convicted", "extradited", "seized", "takedown",
	"taken down", "dismantled", "disrupted", "disrupts", "guidance", "best practices", "released a fix",
}

var negativeSentimentCues = []string{
	"attack", "attacks", "attacked", "compromise", "compromised", "breach", "breached", "leak", "leaked",
	"exploited", "exploitation", "hijack", "hijacked", "stolen", "outage", "ransom", "malicious", "hacked",
	"zero-day", "backdoor", "targeted", "campaign",
}

type attackCue struct {
	any  []string
	also []string
	ids  []string
}

// attackCues map headline concepts to techniques. Every ID is checked against
// the pinned ATT&CK bundle at run time, so an ID that is not in the bundle is
// never emitted (SC-024).
var attackCues = []attackCue{
	{any: []string{"phishing", "spear-phishing", "spearphishing", "smishing", "vishing", "clickfix"}, ids: []string{"T1566"}},
	{any: []string{"ransomware"}, ids: []string{"T1486"}},
	{any: []string{"ddos", "denial of service", "denial-of-service"}, ids: []string{"T1498"}},
	{any: []string{"brute force", "brute-force", "password spraying", "credential stuffing"}, ids: []string{"T1110"}},
	{any: []string{"infostealer", "info-stealer", "credential theft", "credential harvesting"}, ids: []string{"T1555"}},
	{any: []string{"supply chain attack", "supply-chain attack", "malicious package", "compromised package", "typosquatting"}, ids: []string{"T1195"}},
	{any: []string{"keylogger"}, ids: []string{"T1056"}},
	{any: []string{"mfa fatigue", "push bombing"}, ids: []string{"T1621"}},
	{any: []string{"drive-by"}, ids: []string{"T1189"}},
	{any: []string{"wiper"}, ids: []string{"T1485"}},
	{
		any:  []string{"actively exploited", "exploited in the wild", "being exploited", "under active attack", "known exploited"},
		also: []string{"vpn", "firewall", "gateway", "exchange server", "web server", "router", "edge device", "sharepoint", "citrix", "fortinet", "ivanti"},
		ids:  []string{"T1190"},
	},
}

// semanticAnalyzer is a variable so tests can prove the baseline fallback.
var semanticAnalyzer = analyzeSemantic

// AnalyzeStory runs the local semantic analysis and falls back to the baseline
// analyzer when the semantic path finds no signal or fails.
func AnalyzeStory(index *AttackIndex, input Input) (result Result) {
	defer func() {
		if recover() != nil {
			result = baselineResult(index, input)
		}
	}()
	semantic, ok := semanticAnalyzer(index, input)
	if !ok {
		return baselineResult(index, input)
	}
	return semantic
}

func baselineResult(index *AttackIndex, input Input) Result {
	result := Analyze(input.Title)
	result.AttackTechniques = index.Match(input.Title)
	result.CVEs = ExtractCVEs(input.Title)
	result.Engine = EngineBaseline
	return result
}

// ExtractCVEs returns the distinct, upper-cased CVE identifiers in text, sorted
// and capped.
func ExtractCVEs(text string) []string {
	seen := make(map[string]struct{})
	for _, match := range cvePattern.FindAllString(text, -1) {
		seen[strings.ToUpper(match)] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > maxCVEsPerStory {
		ids = ids[:maxCVEsPerStory]
	}
	return ids
}

func analyzeSemantic(index *AttackIndex, input Input) (Result, bool) {
	title := normalizePhrase(input.Title)
	cves := ExtractCVEs(input.Title)
	negated := containsAnyPhrase(title, negatedExploitation)

	scores := make(map[string]int)
	for id, cues := range semanticCategoryCues {
		for _, cue := range cues {
			if containsPhrase(title, cue.phrase) {
				scores[id] += cue.weight
			}
		}
	}
	if len(cves) > 0 {
		scores["vulnerability"] += 2
	}
	if negated {
		scores["exploited-vulnerability"] = 0
	}

	floor := RiskInformational
	for _, format := range input.SourceFormats {
		hint, ok := sourceFormatHints[format]
		if !ok {
			continue
		}
		for _, id := range hint.categories {
			scores[id] += categoryThreshold
		}
		if riskRank(hint.floor) < riskRank(floor) {
			floor = hint.floor
		}
	}

	var categories []string
	top := 0
	for id, score := range scores {
		if score >= categoryThreshold {
			categories = append(categories, id)
			if score > top {
				top = score
			}
		}
	}
	if len(categories) == 0 {
		return Result{}, false
	}
	sort.Strings(categories)

	risk := semanticRisk(title, categories, negated, floor)
	techniques := semanticTechniques(index, input.Title, title)
	confidence := top * 100 / confidenceFullScore
	if confidence > 100 {
		confidence = 100
	}

	return Result{
		Categories:       categories,
		Risk:             risk,
		Sentiment:        semanticSentiment(title, categories, negated),
		AttackTechniques: techniques,
		CVEs:             cves,
		Engine:           EngineSemantic,
		Confidence:       confidence,
	}, true
}

func semanticRisk(title string, categories []string, negated bool, floor Risk) Risk {
	has := func(ids ...string) bool { return hasCategory(categories, ids...) }
	exploited := has("exploited-vulnerability") && !negated
	severe := containsAnyPhrase(title, []string{"critical", "remote code execution", "rce", "zero-day", "zero day", "0-day", "cvss 10", "cvss 9", "emergency"})

	risk := RiskInformational
	switch {
	case exploited && (has("vulnerability") && severe || containsAnyPhrase(title, []string{"zero-day", "zero day", "0-day", "emergency"})):
		risk = RiskCritical
	case exploited, has("ransomware", "data-breach"),
		has("vulnerability") && severe,
		has("nation-state-activity") && has("malware", "phishing-social-engineering", "supply-chain", "vulnerability"):
		risk = RiskHigh
	case has("vulnerability", "malware", "data-breach", "phishing-social-engineering", "nation-state-activity", "supply-chain", "exploited-vulnerability"):
		risk = RiskMedium
	case has("cloud-infrastructure", "internet-outage-ddos"):
		risk = RiskLow
	}
	if riskRank(floor) < riskRank(risk) {
		risk = floor
	}
	return risk
}

func semanticSentiment(title string, categories []string, negated bool) Sentiment {
	threat := hasCategory(categories, "exploited-vulnerability", "ransomware", "malware", "data-breach",
		"phishing-social-engineering", "nation-state-activity", "supply-chain")
	if negated {
		threat = hasCategory(categories, "ransomware", "malware", "data-breach", "phishing-social-engineering", "nation-state-activity", "supply-chain")
	}
	positive := containsAnyPhrase(title, positiveSentimentCues)
	negative := containsAnyPhrase(title, negativeSentimentCues)
	switch {
	case positive && !(threat && negative):
		return SentimentPositive
	case threat || negative || hasCategory(categories, "vulnerability"):
		return SentimentNegative
	default:
		return SentimentNeutral
	}
}

func semanticTechniques(index *AttackIndex, rawTitle, title string) []AttackTechnique {
	found := make(map[string]AttackTechnique)
	for _, technique := range index.Match(rawTitle) {
		found[technique.ID] = technique
	}
	for _, cue := range attackCues {
		if !containsAnyPhrase(title, cue.any) {
			continue
		}
		if len(cue.also) > 0 && !containsAnyPhrase(title, cue.also) {
			continue
		}
		for _, id := range cue.ids {
			if technique, ok := index.Lookup(id); ok {
				found[id] = technique
			}
		}
	}
	ids := make([]string, 0, len(found))
	for id := range found {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	techniques := make([]AttackTechnique, 0, len(ids))
	for _, id := range ids {
		techniques = append(techniques, found[id])
	}
	return techniques
}

func containsAnyPhrase(title string, phrases []string) bool {
	for _, phrase := range phrases {
		if containsPhrase(title, phrase) {
			return true
		}
	}
	return false
}

func riskRank(risk Risk) int {
	switch risk {
	case RiskCritical:
		return 0
	case RiskHigh:
		return 1
	case RiskMedium:
		return 2
	case RiskLow:
		return 3
	default:
		return 4
	}
}
