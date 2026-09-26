package policy

import "testing"

func TestExactOriginScope(t *testing.T) {
	scope, err := FromTarget("https://Example.COM:8443/admin")
	if err != nil {
		t.Fatal(err)
	}
	if scope.Origin != "https://example.com:8443" {
		t.Fatalf("origin = %q", scope.Origin)
	}
	for _, u := range []string{"https://example.com:8443/", "https://EXAMPLE.com:8443/users"} {
		if !scope.Allows(u) {
			t.Errorf("should allow %s", u)
		}
	}
	for _, u := range []string{
		"https://example.com/", "http://example.com:8443/",
		"https://sub.example.com:8443/", "https://example.com.evil.test:8443/",
		"https://user@example.com:8443/",
	} {
		if scope.Allows(u) {
			t.Errorf("should block %s", u)
		}
	}
}

func TestTargetRejectsNonWebSchemesAndUserinfo(t *testing.T) {
	for _, u := range []string{"file:///etc/passwd", "ssh://example.com", "https://user:password@example.com", "https://"} {
		if _, err := FromTarget(u); err == nil {
			t.Errorf("accepted %s", u)
		}
	}
}
