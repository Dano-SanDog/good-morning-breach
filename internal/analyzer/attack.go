package analyzer

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	attackCompressedSHA256 = "2d1200b4278440105b6004d0f6e3789c5e3670614787f4ce256e199ad85870fa"
	attackBundleSHA256     = "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5"
	maxCompressedBundle    = 16 << 20
	maxUncompressedBundle  = 64 << 20
)

var techniqueIDPattern = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

//go:embed data/enterprise-attack-v20.1.json.gz
var embeddedAttackBundle []byte

type AttackTechnique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
	URL     string   `json:"url"`
}

type attackTerm struct {
	phrase    string
	technique AttackTechnique
}

type AttackIndex struct {
	terms      []attackTerm
	techniques map[string]AttackTechnique
}

type stixBundle struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type               string                  `json:"type"`
	Name               string                  `json:"name"`
	ShortName          string                  `json:"x_mitre_shortname"`
	Deprecated         bool                    `json:"x_mitre_deprecated"`
	Revoked            bool                    `json:"revoked"`
	Aliases            []string                `json:"aliases"`
	ExternalReferences []stixExternalReference `json:"external_references"`
	KillChainPhases    []stixKillChainPhase    `json:"kill_chain_phases"`
}

type stixExternalReference struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
}

type stixKillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

func NewAttackIndex() (*AttackIndex, error) {
	return LoadAttackIndex(bytes.NewReader(embeddedAttackBundle), attackCompressedSHA256, attackBundleSHA256)
}

func LoadAttackIndex(source io.Reader, compressedSHA256, bundleSHA256 string) (*AttackIndex, error) {
	compressed, err := io.ReadAll(io.LimitReader(source, maxCompressedBundle+1))
	if err != nil {
		return nil, fmt.Errorf("read pinned ATT&CK bundle: %w", err)
	}
	if len(compressed) > maxCompressedBundle {
		return nil, errors.New("pinned ATT&CK bundle exceeds the compressed size limit")
	}
	if !matchesSHA256(compressed, compressedSHA256) {
		return nil, errors.New("pinned ATT&CK bundle compressed SHA-256 does not match")
	}

	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("open pinned ATT&CK bundle: %w", err)
	}
	defer reader.Close()

	limited := &io.LimitedReader{R: reader, N: maxUncompressedBundle + 1}
	hash := sha256.New()
	decoded := io.TeeReader(limited, hash)
	var bundle stixBundle
	decoder := json.NewDecoder(decoded)
	if err := decoder.Decode(&bundle); err != nil {
		return nil, fmt.Errorf("parse pinned ATT&CK STIX bundle: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("pinned ATT&CK bundle contains extra JSON data")
		}
		return nil, fmt.Errorf("read pinned ATT&CK STIX bundle: %w", err)
	}
	if limited.N == 0 {
		return nil, errors.New("pinned ATT&CK bundle exceeds the uncompressed size limit")
	}
	if hex.EncodeToString(hash.Sum(nil)) != bundleSHA256 {
		return nil, errors.New("pinned ATT&CK bundle SHA-256 does not match")
	}
	if len(bundle.Objects) == 0 {
		return nil, errors.New("pinned ATT&CK bundle contains no STIX objects")
	}

	return buildAttackIndex(bundle), nil
}

func TechniqueURL(id string) (string, bool) {
	if !techniqueIDPattern.MatchString(id) {
		return "", false
	}
	pathID := strings.ReplaceAll(id, ".", "/")
	return "https://attack.mitre.org/techniques/" + pathID + "/", true
}

// Lookup returns a technique from the pinned bundle by ID.
func (index *AttackIndex) Lookup(id string) (AttackTechnique, bool) {
	if index == nil {
		return AttackTechnique{}, false
	}
	technique, ok := index.techniques[id]
	return technique, ok
}

func (index *AttackIndex) Match(title string) []AttackTechnique {
	if index == nil || title == "" {
		return []AttackTechnique{}
	}
	normalizedTitle := normalizePhrase(title)
	matches := make(map[string]AttackTechnique)
	for _, term := range index.terms {
		if containsPhrase(normalizedTitle, term.phrase) {
			matches[term.technique.ID] = term.technique
		}
	}
	ids := make([]string, 0, len(matches))
	for id := range matches {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]AttackTechnique, 0, len(ids))
	for _, id := range ids {
		result = append(result, matches[id])
	}
	return result
}

func buildAttackIndex(bundle stixBundle) *AttackIndex {
	tacticsByShortName := make(map[string]string)
	for _, object := range bundle.Objects {
		if object.Type == "x-mitre-tactic" && object.Name != "" && object.ShortName != "" &&
			!object.Deprecated && !object.Revoked {
			tacticsByShortName[object.ShortName] = object.Name
		}
	}

	techniques := make(map[string]AttackTechnique)
	aliasesByID := make(map[string][]string)
	for _, object := range bundle.Objects {
		if object.Type != "attack-pattern" || object.Name == "" || object.Deprecated || object.Revoked {
			continue
		}
		id := ""
		for _, reference := range object.ExternalReferences {
			if reference.SourceName == "mitre-attack" && techniqueIDPattern.MatchString(reference.ExternalID) {
				id = reference.ExternalID
				break
			}
		}
		if id == "" {
			continue
		}

		tactics := make(map[string]struct{})
		for _, phase := range object.KillChainPhases {
			if phase.KillChainName != "mitre-attack" {
				continue
			}
			if tactic, ok := tacticsByShortName[phase.PhaseName]; ok {
				tactics[tactic] = struct{}{}
			}
		}
		if len(tactics) == 0 {
			continue
		}
		tacticNames := make([]string, 0, len(tactics))
		for tactic := range tactics {
			tacticNames = append(tacticNames, tactic)
		}
		sort.Strings(tacticNames)
		url, _ := TechniqueURL(id)
		techniques[id] = AttackTechnique{ID: id, Name: object.Name, Tactics: tacticNames, URL: url}
		aliasesByID[id] = object.Aliases
	}

	index := &AttackIndex{techniques: techniques}
	for _, technique := range techniques {
		terms := append([]string{technique.Name}, aliasesByID[technique.ID]...)
		for _, term := range terms {
			phrase := normalizePhrase(term)
			if len(strings.Fields(phrase)) < 2 {
				continue
			}
			index.terms = append(index.terms, attackTerm{phrase: phrase, technique: technique})
		}
	}
	sort.Slice(index.terms, func(i, j int) bool {
		if index.terms[i].phrase == index.terms[j].phrase {
			return index.terms[i].technique.ID < index.terms[j].technique.ID
		}
		return index.terms[i].phrase < index.terms[j].phrase
	})
	return index
}

func matchesSHA256(content []byte, expected string) bool {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]) == expected
}

func normalizePhrase(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(value)), " ")
}

func containsPhrase(value, phrase string) bool {
	start := 0
	for start <= len(value)-len(phrase) {
		offset := strings.Index(value[start:], phrase)
		if offset < 0 {
			return false
		}
		begin := start + offset
		end := begin + len(phrase)
		leftBoundary := begin == 0 || !isWordRune(previousRune(value, begin))
		rightBoundary := end == len(value) || !isWordRune(nextRune(value, end))
		if leftBoundary && rightBoundary {
			return true
		}
		start = begin + 1
	}
	return false
}

func previousRune(value string, offset int) rune {
	char, _ := utf8.DecodeLastRuneInString(value[:offset])
	return char
}

func nextRune(value string, offset int) rune {
	char, _ := utf8.DecodeRuneInString(value[offset:])
	return char
}

func isWordRune(char rune) bool {
	return unicode.IsLetter(char) || unicode.IsNumber(char) || char == '_'
}
