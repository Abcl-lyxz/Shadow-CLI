package agent

import (
	"strings"
	"testing"

	"shadow/internal/provider"
)

func TestCompactionKeepsLatestToolAndReferencesOlderEvidence(t *testing.T) {
	messages := []provider.Message{
		{Role: "system", Content: "policy"},
		{Role: "tool", Content: "event_id=1\n" + strings.Repeat("a", 1000)},
		{Role: "tool", Content: "event_id=2\n" + strings.Repeat("b", 1000)},
	}
	compact(messages, 1200)
	if !strings.Contains(messages[1].Content, "event_id=1") || strings.Contains(messages[1].Content, strings.Repeat("a", 50)) {
		t.Fatalf("older tool result was not compacted: %q", messages[1].Content)
	}
	if !strings.Contains(messages[2].Content, strings.Repeat("b", 50)) {
		t.Fatal("latest tool result was compacted")
	}
}
