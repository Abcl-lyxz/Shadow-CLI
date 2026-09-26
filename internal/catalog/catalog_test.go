package catalog

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLoadUsesLastValidCatalogWhenOffline(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "catalog.json")
	offline := false
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if offline {
			return nil, errors.New("offline")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"fixture":{"name":"Fixture","api":"https://api.example/v1","npm":"@ai-sdk/openai-compatible","models":{"test-model":{"tool_call":true}}}}`)), Header: make(http.Header)}, nil
	})}
	data, stale, err := Load(context.Background(), client, cache)
	if err != nil || stale || data["fixture"].ID != "fixture" {
		t.Fatalf("live catalog: stale=%v data=%v err=%v", stale, data, err)
	}
	offline = true
	data, stale, err = Load(context.Background(), client, cache)
	if err != nil || !stale || len(data["fixture"].ToolModels()) != 1 {
		t.Fatalf("cached catalog: stale=%v data=%v err=%v", stale, data, err)
	}
	if err := os.WriteFile(cache, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(context.Background(), client, cache); err == nil {
		t.Fatal("accepted empty cached catalog")
	}
}
