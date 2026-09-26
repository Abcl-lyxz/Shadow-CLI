package redact

import (
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"strings"
)

const maxStructuredBytes = 1 << 20

var patterns = []struct {
	re *regexp.Regexp
	to string
}{
	{regexp.MustCompile(`(?is)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), "[PRIVATE KEY REDACTED]"},
	{regexp.MustCompile(`(?im)^(\s*(?:set-cookie|cookie|proxy-authorization|x-api-key)\s*:\s*).*$`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)(https?://)[^\s/@]+:[^\s/@]+@`), "${1}[REDACTED]@"},
	{regexp.MustCompile(`(?i)([?&](?:api[_-]?key|access[_-]?token|token|secret|password|session|auth|key)=)[^&#\s"'\\]+`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)("(?:api[_-]?key|access[_-]?token|secret|password|session|authorization|cookie)"\s*:\s*")[^"]*(")`), "${1}[REDACTED]${2}"},
	{regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)\S+`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)((?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*["']?)[^\s"',;&#]+`), "${1}[REDACTED]"},
	{regexp.MustCompile(`\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b`), "[JWT REDACTED]"},
	{regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), "[EMAIL REDACTED]"},
}

func Text(input string) string {
	if len(input) > maxStructuredBytes {
		return "[output omitted: redaction limit exceeded]"
	}
	if structured, ok := structuredText(input); ok {
		return structured
	}
	return plainText(input)
}

func plainText(input string) string {
	for _, p := range patterns {
		input = p.re.ReplaceAllString(input, p.to)
	}
	return input
}

// structuredText handles complete JSON documents, including newline-delimited
// JSON, before text patterns run. Unknown free-form text still needs the
// fallback patterns and cannot be guaranteed free of secrets or PII.
func structuredText(input string) (string, bool) {
	if len(input) == 0 || len(input) > maxStructuredBytes {
		return "", false
	}
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.UseNumber()
	var documents []string
	for {
		var value any
		err := decoder.Decode(&value)
		if err == io.EOF {
			break
		}
		if err != nil || len(documents) >= 1024 {
			return "", false
		}
		encoded, err := json.Marshal(sanitize(value, 0))
		if err != nil {
			return "", false
		}
		documents = append(documents, string(encoded))
	}
	if len(documents) == 0 {
		return "", false
	}
	return strings.Join(documents, "\n"), true
}

func sanitize(value any, depth int) any {
	if depth >= 64 {
		return "[REDACTED]"
	}
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			normalized := normalizeKey(key)
			switch {
			case sensitiveKey(normalized):
				node[key] = "[REDACTED]"
			case urlKey(normalized):
				if raw, ok := child.(string); ok {
					node[key] = sanitizeURL(raw)
				} else {
					node[key] = sanitize(child, depth+1)
				}
			default:
				node[key] = sanitize(child, depth+1)
			}
		}
	case []any:
		for index, child := range node {
			node[index] = sanitize(child, depth+1)
		}
	case string:
		return plainText(node)
	}
	return value
}

func normalizeKey(key string) string {
	var normalized strings.Builder
	for _, char := range strings.ToLower(key) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			normalized.WriteRune(char)
		}
	}
	return normalized.String()
}

func sensitiveKey(key string) bool {
	switch key {
	case "key", "token", "auth", "authorization", "proxyauthorization", "cookie", "setcookie", "session", "sessionid", "jwt", "csrf", "email", "phone", "ssn", "body", "requestbody", "responsebody", "rawbody", "payload":
		return true
	}
	for _, fragment := range []string{"apikey", "accesstoken", "refreshtoken", "idtoken", "secret", "password", "passwd", "credential", "privatekey"} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}

func urlKey(key string) bool {
	switch key {
	case "url", "uri", "href", "endpoint", "baseurl", "requesturl", "responseurl":
		return true
	}
	return false
}

func sanitizeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.User = nil
	query := parsed.Query()
	for key := range query {
		if sensitiveKey(normalizeKey(key)) {
			query.Set(key, "[REDACTED]")
		}
	}
	parsed.RawQuery = query.Encode()
	return plainText(parsed.String())
}
