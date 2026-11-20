package alerting

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"
)

type Message struct {
	Subject string
	Text    string
	HTML    string
}

type storyView struct {
	Story
	Published    string
	SourceList   string
	CategoryList string
	ChipColor    string
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
<h1 style="font-size:24px;margin:0 0 8px">Good morning</h1>
<p style="margin:0 0 16px;color:#4E4A6B">{{.Heading}}</p>
{{range .Stories}}<div style="border-left:6px solid {{.ChipColor}};padding:8px 12px;margin:0 0 16px;border-top:1px solid #D9D7E5">
<span style="background:{{.ChipColor}};color:#FFFFFF;font-size:13px;font-weight:700;padding:2px 6px;border-radius:3px">{{.Risk}}</span>
<div style="font-size:18px;font-weight:600;margin:6px 0"><a href="{{.URL}}" style="color:#2E2A8C">{{.Title}}</a></div>
<div style="font-size:14px;color:#4E4A6B">Source: {{.SourceList}}. Published: {{.Published}}. Tone: {{.Sentiment}}.</div>
<div style="font-size:14px;color:#4E4A6B">Categories: {{.CategoryList}}</div>
{{if .Techniques}}<div style="font-size:14px">ATT&amp;CK: {{range $i, $t := .Techniques}}{{if $i}}, {{end}}<a href="{{$t.URL}}" style="color:#2E2A8C">{{$t.ID}} {{$t.Name}}</a> ({{range $j, $tac := $t.Tactics}}{{if $j}}, {{end}}{{$tac}}{{end}}){{end}}</div>{{end}}
{{range .Attributions}}<div style="font-size:13px;color:#4E4A6B">{{.}}</div>
{{end}}</div>
{{end}}<p style="font-size:13px;color:#4E4A6B;margin:0">Technique tags: &copy; 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.</p>
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
	for _, story := range stories {
		view := storyView{
			Story:        story,
			Published:    "unknown",
			SourceList:   strings.Join(story.Sources, ", "),
			CategoryList: strings.Join(story.Categories, ", "),
			ChipColor:    chipColors[story.Risk],
		}
		if story.PublishedAt != nil {
			view.Published = story.PublishedAt.In(location).Format("2 Jan 2006 15:04 MST")
		}
		views = append(views, view)

		fmt.Fprintf(&text, "\n[%s] %s\n%s\nSource: %s. Published: %s. Tone: %s.\nCategories: %s\n",
			story.Risk, story.Title, story.URL, view.SourceList, view.Published, story.Sentiment, view.CategoryList)
		for _, technique := range story.Techniques {
			fmt.Fprintf(&text, "ATT&CK: %s %s (%s) %s\n", technique.ID, technique.Name, strings.Join(technique.Tactics, ", "), technique.URL)
		}
		for _, attribution := range story.Attributions {
			text.WriteString(attribution + "\n")
		}
	}
	text.WriteString("\nTechnique tags: (c) 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.\n")

	var body bytes.Buffer
	if err := htmlTemplate.Execute(&body, struct {
		Heading string
		Stories []storyView
	}{heading, views}); err != nil {
		return Message{}, fmt.Errorf("render alert HTML: %w", err)
	}
	return Message{Subject: subject, Text: text.String(), HTML: body.String()}, nil
}
