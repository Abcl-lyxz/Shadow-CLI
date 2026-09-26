package policy

import "testing"

func TestActionPolicyRequiresExactTrustedRule(t *testing.T) {
	scope, _ := FromTarget("https://example.test")
	p, err := NewActionPolicy(scope, []ActionRule{
		{URL: scope.Origin + "/profile", Method: "GET", Effect: EffectRead},
		{URL: scope.Origin + "/login", Method: "POST", Effect: EffectAuth},
		{URL: scope.Origin + "/test-markers", Method: "POST", Effect: EffectTestWrite, Resource: "shadow_marker_1", CleanupURL: scope.Origin + "/test-markers/shadow_marker_1", CleanupMethod: "DELETE"},
		{URL: scope.Origin + "/danger", Method: "GET", Effect: EffectBlocked},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, url string
		want        Effect
	}{
		{"GET", scope.Origin + "/profile", EffectRead},
		{"POST", scope.Origin + "/login", EffectAuth},
		{"POST", scope.Origin + "/test-markers", EffectTestWrite},
	} {
		d := p.Classify(tc.method, tc.url)
		if !d.Allowed || d.Rule.Effect != tc.want {
			t.Errorf("%s %s: %#v", tc.method, tc.url, d)
		}
	}
	for _, tc := range []struct{ method, url string }{
		{"GET", scope.Origin + "/danger"},
		{"GET", scope.Origin + "/logout"},
		{"GET", scope.Origin + "/profile?delete=1"},
		{"POST", scope.Origin + "/profile"},
		{"DELETE", scope.Origin + "/test-markers/shadow_marker_1"},
		{"GET", "https://sub.example.test/profile"},
		{"GET", scope.Origin + "/profile#fragment"},
		{"get", scope.Origin + "/profile"},
	} {
		if d := p.Classify(tc.method, tc.url); d.Allowed {
			t.Errorf("unexpected permission for %s %s: %#v", tc.method, tc.url, d)
		}
	}
}

func TestActionPolicyRejectsUnsafeDeclarations(t *testing.T) {
	scope, _ := FromTarget("https://example.test")
	if _, err := NewActionPolicy(Scope{}, nil); err == nil {
		t.Fatal("empty scope accepted")
	}
	base := ActionRule{URL: scope.Origin + "/markers", Method: "POST", Effect: EffectTestWrite, Resource: "shadow_marker_1", CleanupURL: scope.Origin + "/markers/shadow_marker_1", CleanupMethod: "DELETE"}
	invalid := []ActionRule{
		{URL: scope.Origin + "/logout", Method: "GET", Effect: EffectTestWrite, Resource: base.Resource, CleanupURL: base.CleanupURL, CleanupMethod: "DELETE"},
		{URL: scope.Origin + "/logout", Method: "GET", Effect: EffectRead, Resource: base.Resource},
		{URL: scope.Origin + "/markers", Method: "POST", Effect: EffectRead},
		{URL: scope.Origin + "/markers", Method: "POST", Effect: Effect("unknown")},
		{URL: "https://other.test/markers", Method: "POST", Effect: EffectAuth},
		{URL: scope.Origin + "/markers#part", Method: "POST", Effect: EffectAuth},
		{URL: scope.Origin + "/markers", Method: "post", Effect: EffectAuth},
	}
	for _, rule := range invalid {
		if _, err := NewActionPolicy(scope, []ActionRule{rule}); err == nil {
			t.Errorf("accepted unsafe rule: %#v", rule)
		}
	}
	for _, change := range []func(*ActionRule){
		func(r *ActionRule) { r.Resource = "" },
		func(r *ActionRule) { r.Resource = "customer_account" },
		func(r *ActionRule) { r.Resource = "private@example.com" },
		func(r *ActionRule) { r.CleanupURL = "https://other.test/delete" },
		func(r *ActionRule) { r.CleanupMethod = "POST" },
		func(r *ActionRule) { r.CleanupURL = "" },
	} {
		rule := base
		change(&rule)
		if _, err := NewActionPolicy(scope, []ActionRule{rule}); err == nil {
			t.Errorf("accepted incomplete cleanup rule: %#v", rule)
		}
	}
	if _, err := NewActionPolicy(scope, []ActionRule{base, base}); err == nil {
		t.Fatal("duplicate route accepted")
	}
}
