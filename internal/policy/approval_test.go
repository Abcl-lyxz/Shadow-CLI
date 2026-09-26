package policy

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRuleApprovalBindsExactRulesOriginAndExpiry(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x53}, 32)
	rules := TrustedRules{Version: 1, Origin: "https://example.test", Actions: []ActionRule{{URL: "https://example.test/safe", Method: "GET", Effect: EffectRead}}}
	a, err := SignRuleApproval(rules, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRuleApproval(rules, a, key, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	changed := rules
	changed.Actions = []ActionRule{{URL: "https://example.test/other", Method: "GET", Effect: EffectRead}}
	if err := VerifyRuleApproval(changed, a, key, now.Add(time.Hour)); err == nil {
		t.Fatal("changed route retained approval")
	}
	changed = rules
	changed.Actions = []ActionRule{{URL: "https://example.test/safe", Method: "GET", Effect: EffectBlocked}}
	if err := VerifyRuleApproval(changed, a, key, now.Add(time.Hour)); err == nil {
		t.Fatal("changed effect retained approval")
	}
	if err := VerifyRuleApproval(rules, a, bytes.Repeat([]byte{0x54}, 32), now.Add(time.Hour)); err == nil {
		t.Fatal("wrong local key verified")
	}
	if err := VerifyRuleApproval(rules, a, key, now.Add(24*time.Hour)); err == nil {
		t.Fatal("expired approval verified")
	}
	a.ExpiresAt = now.Add(48 * time.Hour).Format(time.RFC3339)
	if err := VerifyRuleApproval(rules, a, key, now.Add(time.Hour)); err == nil {
		t.Fatal("extended approval verified")
	}
}

func TestRuleApprovalParsingRejectsAmbiguity(t *testing.T) {
	for _, raw := range []string{
		`{"version":1,"version":1}`,
		`{"version":1,"unknown":true}`,
		`{"version":1} {"version":1}`,
		strings.Repeat("x", 4097),
	} {
		if _, err := ParseRuleApproval(strings.NewReader(raw)); err == nil {
			t.Fatalf("ambiguous approval accepted: %q", raw[:min(len(raw), 100)])
		}
	}
}
