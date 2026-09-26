package redact

import (
	"strings"
	"testing"
)

func TestCommonSecretsAreRemoved(t *testing.T) {
	input := "Authorization: Bearer secret123\napi_key=abcdef\nemail admin@example.com"
	result := Text(input)
	for _, secret := range []string{"secret123", "abcdef", "admin@example.com"} {
		if strings.Contains(result, secret) {
			t.Fatalf("secret %q remained: %s", secret, result)
		}
	}
}
