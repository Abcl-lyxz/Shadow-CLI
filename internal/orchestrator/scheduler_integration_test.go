package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shadow/internal/config"
	"shadow/internal/sandbox"
	"shadow/internal/store"
)

func TestMultiAgentDockerRoleToolFlow(t *testing.T) {
	image := os.Getenv("SHADOW_TEST_IMAGE")
	if image == "" {
		t.Skip("set SHADOW_TEST_IMAGE to an existing local Linux image")
	}
	sb, err := sandbox.New(image)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	var mu sync.Mutex
	toolCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Tools []struct {
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if len(request.Messages) < 2 {
			t.Error("missing task")
			return
		}
		source := strings.Contains(request.Messages[1].Content, "Role: source.")
		var answer any = map[string]string{"role": "assistant", "content": "complete"}
		if source && len(request.Messages) == 2 {
			allowed := false
			for _, tool := range request.Tools {
				if tool.Function.Name == "sandbox_command" {
					allowed = true
				}
			}
			if !allowed {
				t.Error("source role lacks sandbox command")
			}
			answer = map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "c1", "type": "function", "function": map[string]string{"name": "sandbox_command", "arguments": `{"args":["sh","-c","id -u"]}`}}}}
			mu.Lock()
			toolCalls++
			mu.Unlock()
		} else if !source {
			for _, tool := range request.Tools {
				if tool.Function.Name == "sandbox_command" && (strings.Contains(request.Messages[1].Content, "Role: surface.") || strings.Contains(request.Messages[1].Content, "Role: report.")) {
					t.Error("restricted role received sandbox command")
				}
			}
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":` + marshalForTest(t, answer) + `}],"usage":{"prompt_tokens":40,"completion_tokens":6}}`))
	}))
	defer server.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := Scheduler{Store: st, Route: config.Route{Provider: "fixture", Model: "test", BaseURL: server.URL, Protocol: "openai-chat"}, Key: "key", Sandbox: sb, Budget: testBudget()}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	id, err := s.Start(ctx, "Inspect local workspace only", "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := st.AgentPlan(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gotToolCalls := toolCalls
	mu.Unlock()
	if gotToolCalls != 1 {
		t.Fatalf("source tool calls=%d", gotToolCalls)
	}
	for _, job := range plan.Jobs {
		if job.Status != "done" {
			t.Fatalf("job %#v", job)
		}
		if job.Role == "source" && job.ToolCalls != 1 {
			t.Fatalf("source budget %#v", job)
		}
	}
}

func marshalForTest(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
