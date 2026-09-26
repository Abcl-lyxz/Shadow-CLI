package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"shadow/internal/broker"
	"shadow/internal/config"
	"shadow/internal/policy"
	"shadow/internal/store"
)

func fixtureReadCall(id, actionID string) map[string]any {
	arguments, _ := json.Marshal(map[string]string{"action_id": actionID})
	return map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{
		"id": id, "type": "function", "function": map[string]string{"name": "fixture_http_read", "arguments": string(arguments)},
	}}}
}

func TestFixtureAgentReadRequiresRunGrantAndKeepsRawResponseOutOfContext(t *testing.T) {
	var targetHits, escapedHits, providerCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if r.URL.Path != "/safe" {
			t.Errorf("unlisted path reached target: %s", r.URL.Path)
		}
		w.Header().Set("Set-Cookie", "session=private")
		w.Write([]byte("private@example.com"))
	}))
	defer target.Close()
	escape := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { escapedHits.Add(1) }))
	defer escape.Close()
	rule := policy.ActionRule{URL: target.URL + "/safe", Method: http.MethodGet, Effect: policy.EffectRead}
	readID := broker.ReadActionID(rule)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Tools []struct {
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if len(request.Tools) != 1 || request.Tools[0].Function.Name != "fixture_http_read" {
			t.Errorf("fixture agent gained unexpected tools: %#v", request.Tools)
		}
		n := providerCalls.Add(1)
		if n == 1 {
			initial := request.Messages[len(request.Messages)-1].Content
			if !strings.Contains(initial, readID) || strings.Contains(initial, "/safe") {
				t.Errorf("fixture action catalog exposed or omitted a route: %q", initial)
			}
		}
		if n > 1 {
			last := request.Messages[len(request.Messages)-1].Content
			if strings.Contains(last, "private@example.com") || strings.Contains(last, "session=private") || strings.Contains(last, "/safe") {
				t.Errorf("raw target response entered model context: %q", last)
			}
			if n == 2 && (!strings.Contains(last, "observation_event_id=") || !strings.Contains(last, "status=200")) {
				t.Errorf("recorded read lacked evidence reference: %q", last)
			}
			if n > 2 && n != 5 && !strings.Contains(last, "Fixture read denied") {
				t.Errorf("denied read was not explained: %q", last)
			}
			if n == 5 && !strings.Contains(last, "Invalid fixture read arguments") {
				t.Errorf("raw URL arguments were accepted: %q", last)
			}
		}
		var message any
		switch n {
		case 1:
			message = fixtureReadCall("allowed", readID)
		case 2:
			message = fixtureReadCall("unlisted", broker.ReadActionID(policy.ActionRule{URL: target.URL + "/unlisted", Method: http.MethodGet, Effect: policy.EffectRead}))
		case 3:
			message = fixtureReadCall("outside", broker.ReadActionID(policy.ActionRule{URL: escape.URL + "/safe", Method: http.MethodGet, Effect: policy.EffectRead}))
		case 4:
			arguments, _ := json.Marshal(map[string]string{"url": target.URL + "/safe"})
			message = map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "raw-url", "type": "function", "function": map[string]string{"name": "fixture_http_read", "arguments": string(arguments)}}}}
		default:
			message = map[string]string{"role": "assistant", "content": "Fixture inspection complete."}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": message}}})
	}))
	defer provider.Close()
	st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runner := Runner{
		Route: config.Route{Provider: "fixture", Model: "fixture-model", BaseURL: provider.URL, Protocol: "openai-chat"},
		Key:   "fixture-key", Store: st, fixtureReadRules: []policy.ActionRule{rule},
	}
	runID, err := runner.Run(context.Background(), "Inspect the local fixture", target.URL)
	if err != nil || targetHits.Load() != 1 || escapedHits.Load() != 0 || providerCalls.Load() != 5 {
		t.Fatalf("agent fixture flow: run=%s err=%v target=%d escaped=%d provider=%d", runID, err, targetHits.Load(), escapedHits.Load(), providerCalls.Load())
	}
	snapshot, err := st.RunSnapshot(context.Background(), runID)
	if err != nil || len(snapshot.Actions) != 1 || !snapshot.AllowsAction(rule) {
		t.Fatalf("agent read grant: %#v %v", snapshot, err)
	}
	events, err := st.Events(context.Background(), runID)
	if err != nil || len(events) != 8 {
		t.Fatalf("agent events: %#v %v", events, err)
	}
	for _, event := range events {
		if bytes.Contains(event.Payload, []byte("private@example.com")) || bytes.Contains(event.Payload, []byte("session=private")) || bytes.Contains(event.Payload, []byte("/safe")) {
			t.Fatalf("raw target data entered event %d", event.ID)
		}
	}
	var evidenceID int64
	for _, event := range events {
		if event.Kind == "observation" {
			evidenceID = event.ID
		}
	}
	_, raw, err := st.ValidatedObservation(context.Background(), runID, evidenceID)
	if err != nil || string(raw.Body) != "private@example.com" || raw.Header.Get("Set-Cookie") != "session=private" {
		t.Fatalf("encrypted raw evidence unavailable: %#v %v", raw, err)
	}
}

func TestFixtureAgentReadNeedsKeyBeforeProviderOrTargetRequest(t *testing.T) {
	var targetHits, providerHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetHits.Add(1) }))
	defer target.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerHits.Add(1) }))
	defer provider.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runner := Runner{
		Route: config.Route{Provider: "fixture", Model: "fixture-model", BaseURL: provider.URL, Protocol: "openai-chat"},
		Key:   "fixture-key", Store: st,
		fixtureReadRules: []policy.ActionRule{{URL: target.URL + "/safe", Method: http.MethodGet, Effect: policy.EffectRead}},
	}
	if _, err := runner.Run(context.Background(), "Inspect fixture", target.URL); err == nil || targetHits.Load() != 0 || providerHits.Load() != 0 {
		t.Fatalf("fixture read ran without evidence key: %v target=%d provider=%d", err, targetHits.Load(), providerHits.Load())
	}
}

func TestDefaultAgentRejectsForgedFixtureToolCall(t *testing.T) {
	var targetHits, providerHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetHits.Add(1) }))
	defer target.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Tools    []any `json:"tools"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if len(request.Tools) != 0 {
			t.Errorf("default agent advertised network tools")
		}
		var message any = fixtureReadCall("forged", target.URL+"/safe")
		if providerHits.Add(1) == 2 {
			last := request.Messages[len(request.Messages)-1].Content
			if !strings.Contains(last, "Fixture read unavailable") {
				t.Errorf("forged tool response: %q", last)
			}
			message = map[string]string{"role": "assistant", "content": "No network request."}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": message}}})
	}))
	defer provider.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runner := Runner{Route: config.Route{Provider: "fixture", Model: "fixture-model", BaseURL: provider.URL, Protocol: "openai-chat"}, Key: "fixture-key", Store: st}
	runID, err := runner.Run(context.Background(), "Summarize the authorized scope", target.URL)
	if err != nil || targetHits.Load() != 0 || providerHits.Load() != 2 {
		t.Fatalf("default network boundary: run=%s err=%v target=%d provider=%d", runID, err, targetHits.Load(), providerHits.Load())
	}
	snapshot, err := st.RunSnapshot(context.Background(), runID)
	if err != nil || len(snapshot.Actions) != 0 {
		t.Fatalf("default agent gained action grants: %#v %v", snapshot, err)
	}
}

func TestFixtureAgentRejectsWriteGrantBeforeRunStarts(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("target reached") }))
	defer target.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("provider reached") }))
	defer provider.Close()
	st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	write := policy.ActionRule{URL: target.URL + "/markers", Method: http.MethodPost, Effect: policy.EffectTestWrite, Resource: "shadow_marker_1", CleanupURL: target.URL + "/markers/shadow_marker_1", CleanupMethod: http.MethodDelete}
	runner := Runner{
		Route: config.Route{Provider: "fixture", Model: "fixture-model", BaseURL: provider.URL, Protocol: "openai-chat"},
		Key:   "fixture-key", Store: st, fixtureReadRules: []policy.ActionRule{write},
	}
	if _, err := runner.Run(context.Background(), "Try fixture write", target.URL); err == nil {
		t.Fatal("fixture agent accepted a write grant")
	}
	runs, err := st.Runs(context.Background(), 10)
	if err != nil || len(runs) != 0 {
		t.Fatalf("rejected write left a run: %#v %v", runs, err)
	}
}
