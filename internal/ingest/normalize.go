package ingest

import (
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

const maxTitleRunes = 300
const maxLinkBytes = 2048

func normalizeTitle(input string) string {
	tokenizer := html.NewTokenizer(strings.NewReader(html.UnescapeString(input)))
	var output strings.Builder
	runeCount := 0
	skipRawText := false

	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.ErrorToken:
			return strings.Join(strings.Fields(output.String()), " ")
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			name, _ := tokenizer.TagName()
			if strings.EqualFold(string(name), "script") || strings.EqualFold(string(name), "style") {
				skipRawText = tokenType != html.EndTagToken
			}
		case html.TextToken:
			if skipRawText {
				continue
			}
			for _, char := range string(tokenizer.Text()) {
				if runeCount >= maxTitleRunes {
					return strings.Join(strings.Fields(output.String()), " ")
				}
				if unicode.IsControl(char) {
					continue
				}
				if unicode.IsSpace(char) {
					char = ' '
				}
				output.WriteRune(char)
				runeCount++
			}
		}
	}
}

func normalizeLink(raw string) string {
	link, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !link.IsAbs() || link.Host == "" || link.User != nil || link.Opaque != "" {
		return ""
	}
	link.Scheme = strings.ToLower(link.Scheme)
	if link.Scheme != "http" && link.Scheme != "https" {
		return ""
	}
	link.Host = strings.ToLower(link.Host)
	if (link.Scheme == "http" && link.Port() == "80") ||
		(link.Scheme == "https" && link.Port() == "443") {
		host := link.Hostname()
		if strings.Contains(host, ":") {
			link.Host = "[" + host + "]"
		} else {
			link.Host = host
		}
	}
	link.Fragment = ""
	link.RawFragment = ""
	normalized := link.String()
	if len(normalized) > maxLinkBytes {
		return ""
	}
	return normalized
}
