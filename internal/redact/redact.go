package redact

import "regexp"

var patterns = []struct {
	re *regexp.Regexp
	to string
}{
	{regexp.MustCompile(`(?is)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), "[PRIVATE KEY REDACTED]"},
	{regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)\S+`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)((?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*["']?)[^\s"',;]+`), "${1}[REDACTED]"},
	{regexp.MustCompile(`\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b`), "[JWT REDACTED]"},
	{regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), "[EMAIL REDACTED]"},
}

func Text(input string) string {
	for _, p := range patterns {
		input = p.re.ReplaceAllString(input, p.to)
	}
	return input
}
