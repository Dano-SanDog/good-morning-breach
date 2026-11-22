package contentrights

import "testing"

func src(policy, rights string) Source { return Source{Policy: policy, Rights: rights} }

func TestResolve(t *testing.T) {
	tests := []struct {
		name    string
		sources []Source
		want    Allowance
	}{
		{"no sources fails closed", nil, Allowance{}},
		{"headline only", []Source{src(PolicyHeadlineLink, RightsLicensed)}, Allowance{}},
		{"verbatim excerpt has no summary (FR-8.9)", []Source{src(PolicyVerbatimExcerpt, RightsLicensed)}, Allowance{Excerpt: true}},
		{"system summary", []Source{src(PolicySystemSummary, RightsLicensed)}, Allowance{Summary: true}},
		{"full text", []Source{src(PolicyFullText, RightsLicensed)}, Allowance{Excerpt: true, Summary: true}},
		{"all rights reserved is headline only (FR-1.21)", []Source{src(PolicyFullText, RightsAllRightsReserved)}, Allowance{}},
		{"unknown policy", []Source{src("everything", RightsLicensed)}, Allowance{}},
		{"unknown rights", []Source{src(PolicyFullText, "")}, Allowance{}},
		{"most restrictive source wins", []Source{src(PolicyFullText, RightsLicensed), src(PolicyHeadlineLink, RightsLicensed)}, Allowance{}},
		{"excerpt and summary sources intersect", []Source{src(PolicyVerbatimExcerpt, RightsLicensed), src(PolicyFullText, RightsLicensed)}, Allowance{Excerpt: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Resolve(tt.sources); got != tt.want {
				t.Fatalf("Resolve = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestGateAlwaysKeepsHeadlineAndLink(t *testing.T) {
	raw := Raw{Title: "T", URL: "https://example.org/a", Excerpt: "E", Summary: "S"}
	if got := Gate(raw, nil); got != (Content{Title: "T", URL: raw.URL}) {
		t.Fatalf("no sources: %+v", got)
	}
	if got := Gate(raw, []Source{src(PolicyVerbatimExcerpt, RightsLicensed)}); got.Excerpt != "E" || got.Summary != "" {
		t.Fatalf("verbatim: %+v", got)
	}
	if got := Gate(raw, []Source{src(PolicyHeadlineLink, RightsAllRightsReserved)}); got.Excerpt != "" || got.Summary != "" {
		t.Fatalf("all rights reserved: %+v", got)
	}
}

func TestValidateSource(t *testing.T) {
	if err := ValidateSource(src(PolicySystemSummary, RightsAllRightsReserved)); err == nil {
		t.Fatal("all rights reserved with a summary must be rejected")
	}
	if err := ValidateSource(src(PolicyHeadlineLink, RightsAllRightsReserved)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSource(src(PolicyHeadlineLink, "")); err == nil {
		t.Fatal("empty rights class must be rejected")
	}
}

func TestParseSourcesRejectsBadJSON(t *testing.T) {
	if _, err := ParseSources([]byte("{")); err == nil {
		t.Fatal("expected error")
	}
	got, err := ParseSources([]byte(`[{"policy":"headline_link","rights":"licensed"}]`))
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
}
