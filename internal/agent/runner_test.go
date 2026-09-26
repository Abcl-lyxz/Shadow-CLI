package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"shadow/internal/config"
	"shadow/internal/policy"
	"shadow/internal/provider"
	"shadow/internal/store"
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

func TestRoleToolAllowlistRejectsForgedCall(t *testing.T) {
	r := Runner{AllowedTools: map[string]bool{"read_event": true}}
	call := provider.ToolCall{}
	call.Function.Name = "sandbox_command"
	call.Function.Arguments = `{"args":["sh","-c","true"]}`
	if got := r.call(context.Background(), "run", policy.Scope{}, nil, call); got != "Tool denied for this agent role." {
		t.Fatalf("forged role tool: %q", got)
	}
}

func TestRunPersistsNoNetworkActionSnapshot(t *testing.T) {
	requests := 0
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": "No target request was made."}}}})
	}))
	defer fixture.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runner := Runner{Route: config.Route{Provider: "fixture", Model: "fixture-model", BaseURL: fixture.URL, Protocol: "openai-chat"}, Key: "fixture-key", Store: st}
	runID, err := runner.Run(context.Background(), "Summarize the boundary", "https://example.com/path")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := st.RunSnapshot(context.Background(), runID)
	if err != nil || snapshot.Origin != "https://example.com" || len(snapshot.Actions) != 0 {
		t.Fatalf("agent run snapshot: %#v %v", snapshot, err)
	}
	events, err := st.Events(context.Background(), runID)
	if err != nil || len(events) != 2 || events[0].Kind != "started" || events[1].Kind != "answer" || requests != 1 {
		t.Fatalf("run events=%#v requests=%d err=%v", events, requests, err)
	}
}

func TestFreeformAnswerIsWithheldFromEventStore(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var shown string
	runner := Runner{Store: st, Notify: func(event Event) { shown = event.Text }}
	id := runner.emit(context.Background(), "run-1", "answer", "Customer code 48217 is in this result")
	if id <= 0 || shown == "" {
		t.Fatal("answer was not delivered to the local UI")
	}
	event, err := st.EventInRun(context.Background(), "run-1", id)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(event.Payload), "48217") || !strings.Contains(string(event.Payload), "withheld") {
		t.Fatalf("free-form answer entered the event store: %s", event.Payload)
	}
}
