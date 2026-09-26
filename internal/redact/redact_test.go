package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCommonSecretsAreRemoved(t *testing.T) {
	input := "Authorization: Bearer secret123\napi_key=abcdef\nemail admin@example.com\nSet-Cookie: sid=session-secret; HttpOnly\nCookie: sid=session-secret\nProxy-Authorization: Basic aGVsbG8=\nhttps://alice:password123@example.com/path?token=query-secret\n{\"session\":\"json-secret\"}"
	result := Text(input)
	for _, secret := range []string{"secret123", "abcdef", "admin@example.com", "session-secret", "aGVsbG8=", "password123", "query-secret", "json-secret"} {
		if strings.Contains(result, secret) {
			t.Fatalf("secret %q remained: %s", secret, result)
		}
	}
}

func TestNestedStructuredOutputMasksFieldsBeforeAgentContext(t *testing.T) {
	input := `{"status":200,"headers":{"Authorization":["Bearer nested-secret"],"X_API_KEY":"header-secret"},"items":[{"refresh-token":{"value":"refresh-secret"},"count":3},{"url":"https://alice:uri-secret@example.test/path?access_token=query-secret&mode=safe"}],"request_body":{"customer":"body-secret"},"note":"visible"}`
	result := Text(input)
	for _, secret := range []string{"nested-secret", "header-secret", "refresh-secret", "uri-secret", "query-secret", "body-secret"} {
		if strings.Contains(result, secret) {
			t.Fatalf("structured secret %q remained: %s", secret, result)
		}
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(result), &document); err != nil {
		t.Fatalf("redacted result is invalid JSON: %v; output=%s", err, result)
	}
	if document["status"] != float64(200) || document["note"] != "visible" {
		t.Fatalf("non-sensitive fields were lost: %v", document)
	}
	items := document["items"].([]any)
	url := items[1].(map[string]any)["url"].(string)
	if !strings.Contains(url, "mode=safe") || strings.Contains(url, "alice") {
		t.Fatalf("URL was not selectively sanitized: %s", url)
	}
}

func TestEscapedJSONKeysAndJSONLines(t *testing.T) {
	input := "{\"\\u0061uthorization\":\"Bearer escaped-secret\",\"count\":1}\n{\"nested\":[{\"client.secret\":123456789}]}"
	result := Text(input)
	if strings.Contains(result, "escaped-secret") || strings.Contains(result, "123456789") {
		t.Fatalf("JSON lines leaked a secret: %s", result)
	}
	if !strings.Contains(result, `"count":1`) || strings.Count(result, "[REDACTED]") != 2 {
		t.Fatalf("JSON lines were not selectively redacted: %s", result)
	}
}

func TestMalformedJSONFallsBackToTextRedaction(t *testing.T) {
	result := Text(`prefix {"password":"plain-secret"}`)
	if strings.Contains(result, "plain-secret") {
		t.Fatalf("text fallback leaked secret: %s", result)
	}
}

func TestOversizedOutputIsWithheld(t *testing.T) {
	result := Text(strings.Repeat("x", maxStructuredBytes) + "secret-after-limit")
	if strings.Contains(result, "secret-after-limit") || !strings.Contains(result, "omitted") {
		t.Fatalf("oversized output was not withheld: %s", result)
	}
}
