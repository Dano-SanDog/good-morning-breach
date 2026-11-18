package analyzer

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestLoadAttackIndexVerifiesBundleAndIgnoresInvalidTechniqueIDs(t *testing.T) {
	bundle := []byte(`{
		"objects": [
			{"type":"x-mitre-tactic","name":"Initial Access","x_mitre_shortname":"initial-access"},
			{"type":"attack-pattern","name":"Exploit Public-Facing Application","aliases":["Public-Facing App Exploitation"],
			 "external_references":[{"source_name":"mitre-attack","external_id":"T1190","url":"https://evil.example/techniques/T1190/"}],
			 "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"initial-access"}]},
			{"type":"attack-pattern","name":"Malicious Technique",
			 "external_references":[{"source_name":"mitre-attack","external_id":"T1190\"><script"}],
			 "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"initial-access"}]}
		]
	}`)
	compressed := gzipBundle(t, bundle)
	index, err := LoadAttackIndex(bytes.NewReader(compressed), digest(compressed), digest(bundle))
	if err != nil {
		t.Fatalf("LoadAttackIndex returned error: %v", err)
	}

	got := index.Match("Threat actors use public-facing app exploitation")
	if len(got) != 1 {
		t.Fatalf("Match returned %d techniques; want 1", len(got))
	}
	if got[0].ID != "T1190" || got[0].Name != "Exploit Public-Facing Application" {
		t.Fatalf("Match returned unexpected technique: %#v", got[0])
	}
	if len(got[0].Tactics) != 1 || got[0].Tactics[0] != "Initial Access" {
		t.Fatalf("technique tactics = %#v; want [Initial Access]", got[0].Tactics)
	}
	if got[0].URL != "https://attack.mitre.org/techniques/T1190/" {
		t.Fatalf("technique URL = %q", got[0].URL)
	}
	if got := index.Match("Unrelated headline"); len(got) != 0 {
		t.Fatalf("unrelated headline matched techniques: %#v", got)
	}

	if _, err := LoadAttackIndex(bytes.NewReader(compressed), digest(compressed), "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("LoadAttackIndex accepted a bundle with a mismatched source hash")
	}
	if _, err := LoadAttackIndex(bytes.NewReader(compressed), "0000000000000000000000000000000000000000000000000000000000000000", digest(bundle)); err == nil {
		t.Fatal("LoadAttackIndex accepted a bundle with a mismatched compressed hash")
	}
}

func TestNewAttackIndexLoadsPinnedEnterpriseBundle(t *testing.T) {
	index, err := NewAttackIndex()
	if err != nil {
		t.Fatalf("NewAttackIndex returned error: %v", err)
	}
	got := index.Match("Exploit Public-Facing Application")
	if len(got) == 0 || got[0].ID != "T1190" {
		t.Fatalf("pinned bundle did not map T1190: %#v", got)
	}
}

func TestTechniqueURLRequiresAValidTechniqueID(t *testing.T) {
	tests := []struct {
		id   string
		want string
		ok   bool
	}{
		{id: "T1190", want: "https://attack.mitre.org/techniques/T1190/", ok: true},
		{id: "T1059.001", want: "https://attack.mitre.org/techniques/T1059/001/", ok: true},
		{id: `T1190"><script`, ok: false},
	}
	for _, testCase := range tests {
		got, ok := TechniqueURL(testCase.id)
		if got != testCase.want || ok != testCase.ok {
			t.Errorf("TechniqueURL(%q) = (%q, %t); want (%q, %t)", testCase.id, got, ok, testCase.want, testCase.ok)
		}
	}
}

func gzipBundle(t *testing.T, data []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("gzip.Write returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip.Close returned error: %v", err)
	}
	return compressed.Bytes()
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
