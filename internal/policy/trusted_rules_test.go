package policy

import (
	"fmt"
	"strings"
	"testing"
)

func trustedFixtureDocument(origin string) string {
	return fmt.Sprintf(`{"version":1,"origin":%q,"actions":[{"url":%q,"method":"POST","effect":"test_write","resource":"shadow_marker_1","cleanup_url":%q,"cleanup_method":"DELETE"},{"url":%q,"method":"GET","effect":"read"}]}`, origin, origin+"/markers", origin+"/markers/shadow_marker_1", origin+"/markers/shadow_marker_1")
}

func TestTrustedRulesRequireExactOperatorScopeAndTypedCleanup(t *testing.T) {
	origin := "http://127.0.0.1:40123"
	doc, err := ParseTrustedRules(strings.NewReader(trustedFixtureDocument(origin)), origin)
	if err != nil || len(doc.Actions) != 2 || doc.Actions[0].CleanupURL != origin+"/markers/shadow_marker_1" {
		t.Fatalf("valid rules rejected: %+v %v", doc, err)
	}
	scope, _ := FromTarget(origin)
	compiled, err := NewActionPolicy(scope, doc.Actions)
	if err != nil || !compiled.Classify("POST", origin+"/markers").Allowed {
		t.Fatalf("validated rule unusable: %v", err)
	}
	for _, request := range []struct{ method, url string }{
		{"POST", origin + "/markers?other=1"},
		{"DELETE", origin + "/markers/shadow_marker_1"},
		{"GET", "http://127.0.0.1:40124/markers/shadow_marker_1"},
		{"POST", "http://evil.test/markers"},
	} {
		if compiled.Classify(request.method, request.url).Allowed {
			t.Fatalf("scope escape accepted: %s %s", request.method, request.url)
		}
	}
	invalid := []string{
		strings.Replace(trustedFixtureDocument(origin), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(trustedFixtureDocument(origin), `"effect":"test_write"`, `"effect":"test_write","effect":"read"`, 1),
		strings.Replace(trustedFixtureDocument(origin), `"origin":"`+origin+`"`, `"origin":"http://evil.test"`, 1),
		strings.Replace(trustedFixtureDocument(origin), `"cleanup_method":"DELETE"`, `"cleanup_method":"POST"`, 1),
		strings.Replace(trustedFixtureDocument(origin), `"version":1`, `"version":1,"surprise":true`, 1),
		strings.Replace(trustedFixtureDocument(origin), `"method":"GET","effect":"read"`, `"method":"GET","effect":"blocked"`, 1),
		strings.Replace(trustedFixtureDocument(origin), `"resource":"shadow_marker_1"`, `"resource":"customer"`, 1),
		strings.Replace(trustedFixtureDocument(origin), `"version":1`, `"version":2`, 1),
		trustedFixtureDocument(origin) + `{"extra":true}`,
		strings.Repeat(" ", maxTrustedRulesBytes+1),
	}
	for i, text := range invalid {
		if _, err := ParseTrustedRules(strings.NewReader(text), origin); err == nil {
			t.Errorf("invalid case %d accepted", i)
		}
	}
	if _, err := ParseTrustedRules(strings.NewReader(trustedFixtureDocument(origin)), "http://127.0.0.1:40124"); err == nil {
		t.Fatal("rules from another target accepted")
	}
}
