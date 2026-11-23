// Package contentrights is the single content-rights gate (FR-1.21, FR-8.8, FR-8.9,
// SC-023, DR-4). Every output path (dashboard API, email, Slack) obtains the
// displayable fields of a story from Gate and nowhere else. It fails closed: when
// the rights of a story's sources are unknown, only the headline and link show.
package contentrights

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Policy values mirror data_sources.content_policy (FR-8.8).
const (
	PolicyFullText        = "full_text"
	PolicyVerbatimExcerpt = "verbatim_excerpt"
	PolicySystemSummary   = "system_summary"
	PolicyHeadlineLink    = "headline_link"
)

// Rights values mirror data_sources.rights_class (FR-1.21).
const (
	RightsLicensed          = "licensed"
	RightsAllRightsReserved = "all_rights_reserved"
)

// Source is the rights record of one data source.
type Source struct {
	Policy string `json:"policy"`
	Rights string `json:"rights"`
}

// ValidPolicy reports whether policy is a known content policy.
func ValidPolicy(policy string) bool {
	switch policy {
	case PolicyFullText, PolicyVerbatimExcerpt, PolicySystemSummary, PolicyHeadlineLink:
		return true
	}
	return false
}

// ValidRights reports whether rights is a known rights class.
func ValidRights(rights string) bool {
	return rights == RightsLicensed || rights == RightsAllRightsReserved
}

// ValidateSource enforces the invariants of one source record: both values are
// known, and an "all rights reserved" source is headline and link only (FR-1.21).
func ValidateSource(s Source) error {
	if !ValidPolicy(s.Policy) {
		return errors.New("source content policy is invalid")
	}
	if !ValidRights(s.Rights) {
		return errors.New("source rights class is invalid")
	}
	if s.Rights == RightsAllRightsReserved && s.Policy != PolicyHeadlineLink {
		return errors.New("an all rights reserved source can show only the headline, source name, and link")
	}
	return nil
}

// Allowance says what beyond the headline and link a story may show. The zero
// value allows nothing.
type Allowance struct {
	Excerpt bool
	Summary bool
}

// permits returns the allowance of one source. Anything unknown permits nothing.
// A verbatim-only source never permits a summary because its license forbids
// changes (FR-8.9).
func permits(s Source) Allowance {
	if ValidateSource(s) != nil || s.Rights == RightsAllRightsReserved {
		return Allowance{}
	}
	switch s.Policy {
	case PolicyFullText:
		return Allowance{Excerpt: true, Summary: true}
	case PolicyVerbatimExcerpt:
		return Allowance{Excerpt: true}
	case PolicySystemSummary:
		return Allowance{Summary: true}
	}
	return Allowance{}
}

// Resolve returns what a story reported by all of the given sources may show:
// the most restrictive source wins. No sources means nothing beyond headline and
// link, so a story whose sources cannot be determined fails closed.
func Resolve(sources []Source) Allowance {
	if len(sources) == 0 {
		return Allowance{}
	}
	out := Allowance{Excerpt: true, Summary: true}
	for _, s := range sources {
		a := permits(s)
		out.Excerpt = out.Excerpt && a.Excerpt
		out.Summary = out.Summary && a.Summary
	}
	return out
}

// ParseSources decodes the JSON array of source records that the story queries
// aggregate. Invalid input is an error, never a permissive default.
func ParseSources(raw []byte) ([]Source, error) {
	var sources []Source
	if err := json.Unmarshal(raw, &sources); err != nil {
		return nil, fmt.Errorf("decode source rights: %w", err)
	}
	return sources, nil
}

// Raw is stored story content before the gate. Only store code builds it.
type Raw struct {
	Title   string
	URL     string
	Excerpt string
	Summary string
}

// Content is the displayable content of a story. Output structs embed it and
// receive it only from Gate.
type Content struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Excerpt string `json:"excerpt,omitempty"`
	Summary string `json:"summary,omitempty"`
}

// Gate returns the fields of raw that the allowance permits. The headline and
// link are always permitted (FR-1.21, FR-8.8).
func (a Allowance) Gate(raw Raw) Content {
	out := Content{Title: raw.Title, URL: raw.URL}
	if a.Excerpt {
		out.Excerpt = raw.Excerpt
	}
	if a.Summary {
		out.Summary = raw.Summary
	}
	return out
}

// Gate resolves the sources and gates raw in one step.
func Gate(raw Raw, sources []Source) Content {
	return Resolve(sources).Gate(raw)
}

// ExcerptPolicies lists the content policies whose licensed sources permit an
// excerpt, so SQL search over excerpt text agrees with Gate.
func ExcerptPolicies() []string {
	var out []string
	for _, p := range []string{PolicyFullText, PolicyVerbatimExcerpt, PolicySystemSummary, PolicyHeadlineLink} {
		if permits(Source{Policy: p, Rights: RightsLicensed}).Excerpt {
			out = append(out, p)
		}
	}
	return out
}
