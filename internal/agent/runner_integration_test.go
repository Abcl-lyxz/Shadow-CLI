package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"shadow/internal/config"
	"shadow/internal/sandbox"
	"shadow/internal/store"
)

func TestAgentToolAndMemoryFlow(t *testing.T) {
	image := os.Getenv("SHADOW_TEST_IMAGE")
	if image == "" {
		t.Skip("set SHADOW_TEST_IMAGE to an existing local Linux image")
	}
	requests := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer fixture-key" {
			t.Errorf("unexpected provider request: %s", r.URL.Path)
		}
		var request struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.Model != "fixture-model" {
			t.Errorf("wrong model: %s", request.Model)
		}
		requests++
		var message any
		switch requests {
		case 1:
			message = map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "c1", "type": "function", "function": map[string]string{"name": "sandbox_command", "arguments": `{"args":["sh","-c","id -u"]}`}}}}
		case 2:
			last := request.Messages[len(request.Messages)-1].Content
			if !strings.Contains(last, "sandbox output withheld") || strings.Contains(last, "65534") {
				t.Errorf("sandbox output was not withheld: %s", last)
			}
			first, _, _ := strings.Cut(last, "\n")
			id, err := strconv.ParseInt(strings.TrimPrefix(first, "event_id="), 10, 64)
			if err != nil {
				t.Error(err)
			}
			args, _ := json.Marshal(map[string]any{"event_id": id, "topic": "sandbox", "summary": "customer-secret"})
			message = map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "c2", "type": "function", "function": map[string]string{"name": "remember_observation", "arguments": string(args)}}}}
		default:
			message = map[string]string{"role": "assistant", "content": "Analysis complete; no live target request was made."}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": message}}})
	}))
	defer provider.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sb, err := sandbox.New(image)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	runner := Runner{Route: config.Route{Provider: "fixture", Model: "fixture-model", BaseURL: provider.URL + "/v1", Protocol: "openai-chat"}, Key: "fixture-key", Store: st, Sandbox: sb}
	runID, err := runner.Run(ctx, "Inspect the sandbox only", "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if requests != 3 {
		t.Fatalf("requests=%d", requests)
	}
	events, err := st.Events(ctx, runID)
	if err != nil || len(events) != 4 {
		t.Fatalf("events=%v err=%v", events, err)
	}
	memories, err := st.Recall(ctx, "https://example.com", 10)
	if err != nil || len(memories) != 1 || memories[0].Summary != "[untrusted note text withheld]" {
		t.Fatalf("memories=%v err=%v", memories, err)
	}
}

func TestAgentSandboxOutputWithheld(t *testing.T) {
	image := os.Getenv("SHADOW_TEST_IMAGE")
	if image == "" {
		t.Skip("set SHADOW_TEST_IMAGE to an existing local Linux image")
	}
	requests := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		requests++
		var message any
		if requests == 1 {
			args, _ := json.Marshal(map[string]any{"args": []string{"sh", "-c", `printf '%s\n' '{"headers":{"Authorization":"Bearer nested-secret"},"count":7}'`}})
			message = map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "c1", "type": "function", "function": map[string]string{"name": "sandbox_command", "arguments": string(args)}}}}
		} else {
			last := request.Messages[len(request.Messages)-1].Content
			if strings.Contains(last, "nested-secret") || strings.Contains(last, `"count":7`) || !strings.Contains(last, "sandbox output withheld") {
				t.Errorf("provider received unsanitized or incomplete tool output: %s", last)
			}
			message = map[string]string{"role": "assistant", "content": "Done."}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": message}}})
	}))
	defer provider.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sb, err := sandbox.New(image)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	runner := Runner{Route: config.Route{Provider: "fixture", Model: "fixture-model", BaseURL: provider.URL + "/v1", Protocol: "openai-chat"}, Key: "fixture-key", Store: st, Sandbox: sb}
	runID, err := runner.Run(ctx, "Inspect local JSON output", "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("provider requests=%d", requests)
	}
	events, err := st.Events(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if strings.Contains(string(event.Payload), "nested-secret") {
			t.Fatalf("secret persisted in event %d", event.ID)
		}
	}
}
