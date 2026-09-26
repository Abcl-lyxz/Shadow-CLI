package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEndpointRejectsRemotePlainHTTP(t *testing.T) {
	for _, base := range []string{"http://example.com/v1", "file:///tmp", "https://user:pass@example.com/v1"} {
		if _, err := (Client{BaseURL: base}).endpoint("/models"); err == nil {
			t.Errorf("accepted %s", base)
		}
	}
	if _, err := (Client{BaseURL: "http://127.0.0.1:1234/v1"}).endpoint("/models"); err != nil {
		t.Fatal(err)
	}
}

func TestActiveRouteUsesSelectedModelAndKey(t *testing.T) {
	var model string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("authorization was not sent to configured endpoint")
		}
		switch r.URL.Path {
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"data":[{"id":"selected-model"}]}`))
		case "/v1/chat/completions":
			var body struct {
				Model string `json:"model"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			model = body.Model
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL + "/v1", Key: "test-key"}
	ids, err := client.Models(context.Background())
	if err != nil || len(ids) != 1 || ids[0] != "selected-model" {
		t.Fatalf("models = %v, %v", ids, err)
	}
	answer, err := client.Chat(context.Background(), "selected-model", []Message{{Role: "user", Content: "hello"}}, nil)
	if err != nil || answer.Content != "ok" || model != "selected-model" {
		t.Fatalf("answer=%#v model=%s err=%v", answer, model, err)
	}
}

func TestProviderRedirectIsBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/collect", http.StatusFound)
	}))
	defer server.Close()
	_, err := (Client{BaseURL: server.URL, Key: "secret"}).Models(context.Background())
	if err == nil {
		t.Fatal("provider redirect was followed")
	}
}

func TestChatUsageAndOutputRequestLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			MaxTokens int64 `json:"max_tokens"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.MaxTokens != 7 {
			t.Errorf("max_tokens=%d", request.MaxTokens)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":11,"completion_tokens":2}}`))
	}))
	defer server.Close()
	_, usage, err := (Client{BaseURL: server.URL, Key: "key"}).ChatWithUsageLimit(context.Background(), "test", []Message{{Role: "user", Content: "hi"}}, nil, 7)
	if err != nil || !usage.Known || usage.InputTokens != 11 || usage.OutputTokens != 2 {
		t.Fatalf("usage %#v %v", usage, err)
	}
}
