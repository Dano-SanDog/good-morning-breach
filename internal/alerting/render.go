package alerting

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// logoEmailPNG is the 360 px logo sent inline (CID) with the HTML part, so no
// remote image is needed.
//
//go:embed assets/logo-email.png
var logoEmailPNG []byte

// logoCID is the Content-ID that the HTML part references as cid:good-morning-breach-logo.
const logoCID = "good-morning-breach-logo"

type Message struct {
	Subject string
	Text    string
	HTML    string
	// LogoPNG, when set, is attached inline to the HTML part under logoCID.
	LogoPNG []byte
}

type linkView struct {
	Text string
	URL  string // empty when the link is not a safe https link
}

type storyView struct {
	Story
	Link         linkView
	Published    string
	SourceList   string
	CategoryList string
	ChipColor    string
	CVEList      string
	Related      []relatedView
}

type relatedView struct {
	Link linkView
	CVE  string
}

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

// plain removes control characters and caps the length of untrusted text so it
// cannot inject headers or break the layout (NFR-3.4, SC-032).
func plain(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if runes := []rune(value); len(runes) > limit {
		value = string(runes[:limit-1]) + "…"
	}
	return value
}

// safeLink returns the link target only for an absolute https URL with a host and
// no credentials; otherwise it returns an empty string so no link is rendered.
func safeLink(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
		return ""
	}
	return parsed.String()
}

func plainList(values []string, limit int) string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if value = plain(value, limit); value != "" {
			cleaned = append(cleaned, value)
		}
	}
	return strings.Join(cleaned, ", ")
}

func validCVEs(values []string) []string {
	var valid []string
	for _, value := range values {
		if cvePattern.MatchString(value) && len(valid) < 10 {
			valid = append(valid, value)
		}
	}
	return valid
}

var chipColors = map[string]string{
	"Critical":      "#A3142E",
	"High":          "#A8420A",
	"Medium":        "#7A5B00",
	"Low":           "#2C6A47",
	"Informational": "#4B5574",
}

var htmlTemplate = template.Must(template.New("alert").Parse(`<!doctype html>
<html lang="en"><body style="margin:0;padding:16px;background:#EFEEF5;color:#1D1A3B;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;font-size:16px;line-height:1.5">
<div style="max-width:600px;margin:0 auto;background:#FFFFFF;padding:16px">
<img src="cid:good-morning-breach-logo" width="300" alt="Good Morning Breach" style="display:block;width:300px;max-width:100%;height:auto;margin:0 0 12px;border:0">
<h1 style="font-size:24px;margin:0 0 8px">Good morning</h1>
<p style="margin:0 0 16px;color:#4E4A6B">{{.Heading}}</p>
{{range .Stories}}<div style="border-left:6px solid {{.ChipColor}};padding:8px 12px;margin:0 0 16px;border-top:1px solid #D9D7E5">
<span style="background:{{.ChipColor}};color:#FFFFFF;font-size:13px;font-weight:700;padding:2px 6px;border-radius:3px">{{.Risk}}</span>
<div style="font-size:18px;font-weight:600;margin:6px 0">{{if .Link.URL}}<a href="{{.Link.URL}}" style="color:#2E2A8C">{{.Link.Text}}</a>{{else}}{{.Link.Text}}{{end}}</div>
<div style="font-size:14px;color:#4E4A6B">Source: {{.SourceList}}. Published: {{.Published}}. Tone: {{.Sentiment}}.</div>
<div style="font-size:14px;color:#4E4A6B">Categories: {{.CategoryList}}</div>
{{if .CVEList}}<div style="font-size:14px;color:#4E4A6B">CVE: {{.CVEList}}</div>{{end}}
{{if .Techniques}}<div style="font-size:14px">ATT&amp;CK: {{range $i, $t := .Techniques}}{{if $i}}, {{end}}<a href="{{$t.URL}}" style="color:#2E2A8C">{{$t.ID}} {{$t.Name}}</a> ({{range $j, $tac := $t.Tactics}}{{if $j}}, {{end}}{{$tac}}{{end}}){{end}}</div>{{end}}
{{if .Related}}<div style="font-size:14px;color:#4E4A6B">Related ({{range $i, $r := .Related}}{{if $i}}; {{end}}{{$r.CVE}}: {{if $r.Link.URL}}<a href="{{$r.Link.URL}}" style="color:#2E2A8C">{{$r.Link.Text}}</a>{{else}}{{$r.Link.Text}}{{end}}{{end}})</div>{{end}}
{{range .Attributions}}<div style="font-size:13px;color:#4E4A6B">{{.}}</div>
{{end}}</div>
{{end}}{{if .Techniques}}<p style="font-size:13px;color:#4E4A6B;margin:0">Technique tags: &copy; 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.</p>{{end}}
</div></body></html>
`))

// Render builds the alert. Stories must already be filtered and sorted. Only
// headline, source, and link data is stored today, so no summary is shown (FR-8.8, FR-8.9).
func Render(stories []Story, settings Settings, now time.Time) (Message, error) {
	location, err := time.LoadLocation(settings.TimeZone)
	if err != nil {
		return Message{}, fmt.Errorf("load alert time zone: %w", err)
	}
	var subject, heading string
	if len(stories) == 0 {
		subject = "Good Morning Breach: no new stories"
		heading = "There are no new stories at or above " + settings.MinimumRisk + " since your last alert."
	} else {
		noun := "stories"
		if len(stories) == 1 {
			noun = "story"
		}
		subject = fmt.Sprintf("Good Morning Breach: %d %s, highest risk %s", len(stories), noun, stories[0].Risk)
		heading = fmt.Sprintf("%d new %s at or above %s, highest risk first.", len(stories), noun, settings.MinimumRisk)
	}

	views := make([]storyView, 0, len(stories))
	var text strings.Builder
	text.WriteString("Good morning\n" + heading + "\n")
	anyTechniques := false
	for _, original := range stories {
		story := original
		story.Techniques = nil
		for _, technique := range original.Techniques {
			link := safeLink(technique.URL)
			if link == "" || len(story.Techniques) >= 8 {
				continue
			}
			story.Techniques = append(story.Techniques, Technique{
				ID: plain(technique.ID, 16), Name: plain(technique.Name, 100), URL: link,
				Tactics: strings.Split(plainList(technique.Tactics, 40), ", ")})
		}
		anyTechniques = anyTechniques || len(story.Techniques) > 0
		story.Attributions = nil
		for _, attribution := range original.Attributions {
			if cleaned := plain(attribution, 1000); cleaned != "" {
				story.Attributions = append(story.Attributions, cleaned)
			}
		}
		view := storyView{
			Story:        story,
			Link:         linkView{Text: plain(story.Title, 300), URL: safeLink(story.URL)},
			Published:    "unknown",
			SourceList:   plainList(story.Sources, 100),
			CategoryList: plainList(story.Categories, 60),
			ChipColor:    chipColors[story.Risk],
			CVEList:      strings.Join(validCVEs(story.CVEs), ", "),
		}
		for _, related := range story.Related {
			if len(view.Related) < 3 && cvePattern.MatchString(related.CVE) {
				view.Related = append(view.Related, relatedView{
					CVE: related.CVE, Link: linkView{Text: plain(related.Title, 200), URL: safeLink(related.URL)}})
			}
		}
		if story.PublishedAt != nil {
			view.Published = story.PublishedAt.In(location).Format("2 Jan 2006 15:04 MST")
		}
		views = append(views, view)

		fmt.Fprintf(&text, "\n[%s] %s\n", story.Risk, view.Link.Text)
		if view.Link.URL != "" {
			text.WriteString(view.Link.URL + "\n")
		}
		fmt.Fprintf(&text, "Source: %s. Published: %s. Tone: %s.\nCategories: %s\n",
			view.SourceList, view.Published, story.Sentiment, view.CategoryList)
		if view.CVEList != "" {
			text.WriteString("CVE: " + view.CVEList + "\n")
		}
		for _, technique := range story.Techniques {
			fmt.Fprintf(&text, "ATT&CK: %s %s (%s) %s\n", technique.ID, technique.Name, strings.Join(technique.Tactics, ", "), technique.URL)
		}
		for _, related := range view.Related {
			text.WriteString("Related (" + related.CVE + "): " + related.Link.Text)
			if related.Link.URL != "" {
				text.WriteString(" " + related.Link.URL)
			}
			text.WriteString("\n")
		}
		for _, attribution := range story.Attributions {
			text.WriteString(attribution + "\n")
		}
	}
	if anyTechniques {
		text.WriteString("\nTechnique tags: (c) 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.\n")
	}

	var body bytes.Buffer
	if err := htmlTemplate.Execute(&body, struct {
		Heading    string
		Stories    []storyView
		Techniques bool
	}{heading, views, anyTechniques}); err != nil {
		return Message{}, fmt.Errorf("render alert HTML: %w", err)
	}
	return Message{Subject: subject, Text: text.String(), HTML: body.String(), LogoPNG: logoEmailPNG}, nil
}
