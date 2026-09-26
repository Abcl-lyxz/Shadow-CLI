package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"shadow/internal/agent"
	"shadow/internal/config"
	"shadow/internal/policy"
	"shadow/internal/store"
)

func testBudget() agent.Budget {
	return agent.Budget{MaxSteps: 4, MaxTools: 2, MaxInputTokens: 1000000, MaxOutputTokens: 100, MaxContextBytes: 65536, MaxCostMicroUSD: 1000000, InputPriceMicroUSDPerMillion: 1000000, OutputPriceMicroUSDPerMillion: 1000000, KnownPrice: true}
}

func TestSchedulerRunsIndependentJobsAndPersistsBudgets(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	active, maxActive, calls := 0, 0, 0
	barrier := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("wrong provider key")
		}
		var request struct {
			MaxTokens int64 `json:"max_tokens"`
			Messages  []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if request.MaxTokens != 100 || len(request.Messages) < 2 {
			t.Errorf("budget request: %#v", request)
		}
		mu.Lock()
		active++
		calls++
		if active > maxActive {
			maxActive = active
		}
		if calls == 2 {
			close(barrier)
		}
		mu.Unlock()
		select {
		case <-barrier:
		case <-time.After(3 * time.Second):
			t.Error("discovery jobs did not overlap")
		}
		mu.Lock()
		active--
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"done"}}],"usage":{"prompt_tokens":25,"completion_tokens":3}}`))
	}))
	defer server.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := Scheduler{Store: st, Route: config.Route{Provider: "fixture", BaseURL: server.URL, Model: "test", Protocol: "openai-chat"}, Key: "test-key", Budget: testBudget()}
	id, err := s.Start(ctx, "Inspect only local evidence", "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := st.AgentPlan(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gotMaxActive, gotCalls := maxActive, calls
	mu.Unlock()
	if len(plan.Jobs) != 4 || gotMaxActive < 2 || gotCalls != 4 {
		t.Fatalf("jobs=%d active=%d calls=%d", len(plan.Jobs), gotMaxActive, gotCalls)
	}
	for _, job := range plan.Jobs {
		if job.Status != "done" || job.InputTokens != 25 || job.OutputTokens != 3 || job.CostMicroUSD != 28 || job.Step != 1 {
			t.Fatalf("job %#v", job)
		}
	}
	if err := s.RunPending(ctx, id, "changed instruction"); err == nil {
		t.Fatal("changed task was accepted")
	}
	if err := s.RunPending(ctx, id, "Inspect only local evidence"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gotCalls = calls
	mu.Unlock()
	if gotCalls != 4 {
		t.Fatal("completed jobs replayed")
	}
	events, err := st.Events(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if strings.Contains(string(event.Payload), "Inspect only local evidence") || strings.Contains(string(event.Payload), "test-key") {
			t.Fatal("task text or key was persisted")
		}
	}
}

func TestRecoveryNeverReplaysInterruptedToolBoundary(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := policy.FromTarget("https://example.com")
	if err := st.StartRun(ctx, "plan", scope, nil); err != nil {
		t.Fatal(err)
	}
	route := config.Route{Provider: "fixture", Model: "test", BaseURL: "http://127.0.0.1:1", Protocol: "openai-chat"}
	routeJSON, _ := json.Marshal(route)
	budgetJSON, _ := json.Marshal(testBudget())
	if err := st.CreateAgentPlan(ctx, "plan", store.PromptDigest("Task"), routeJSON, budgetJSON, roles); err != nil {
		t.Fatal(err)
	}
	if err := st.AgentJobTransition(ctx, "plan", "surface", "pending", "running", "claimed", 0, 0, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := st.AgentJobTransition(ctx, "plan", "surface", "running", "running", "before_tool", 1, 25, 3, 28, 0); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := Scheduler{Store: st, Route: route, Key: "key", Budget: testBudget()}
	plan, err := s.Recover(ctx, "plan")
	if err != nil {
		t.Fatal(err)
	}
	var surface store.AgentJob
	for _, job := range plan.Jobs {
		if job.Role == "surface" {
			surface = job
		}
	}
	if surface.Status != "interrupted" || surface.Phase != "outcome_unknown" || surface.ToolCalls != 0 {
		t.Fatalf("recovered job %#v", surface)
	}
	if err := st.PurgeRun(ctx, "plan"); err == nil {
		t.Fatal("unknown-outcome plan was purged")
	}
	if err := s.RunPending(ctx, "plan", "Task"); err == nil || !strings.Contains(err.Error(), "outcome review") {
		t.Fatalf("unexpected automatic replay result: %v", err)
	}
	if err := s.RetryInterrupted(ctx, "plan", "surface", ""); err == nil {
		t.Fatal("retry without review accepted")
	}
	if err := s.RetryInterrupted(ctx, "plan", "surface", "no_side_effect"); err != nil {
		t.Fatal(err)
	}
	plan, err = st.AgentPlan(ctx, "plan")
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range plan.Jobs {
		if job.Role == "surface" && (job.Status != "pending" || job.Step != 1 || job.InputTokens != 25) {
			t.Fatalf("retry lost budget: %#v", job)
		}
	}
}

func TestMissingUsageStopsBeforeToolExecution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"x","type":"function","function":{"name":"sandbox_command","arguments":"{}"}}]}}]}`))
	}))
	defer server.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := Scheduler{Store: st, Route: config.Route{Provider: "fixture", Model: "test", BaseURL: server.URL, Protocol: "openai-chat"}, Key: "key", Budget: testBudget()}
	id, err := s.Start(context.Background(), "Task", "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "omitted usage") {
		t.Fatalf("missing usage accepted: %v", err)
	}
	plan, err := st.AgentPlan(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range plan.Jobs {
		if job.Status == "interrupted" && job.ToolCalls != 0 {
			t.Fatalf("tool ran after missing usage: %#v", job)
		}
	}
}

func TestProviderCostOverBudgetStopsBeforeTool(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"x","type":"function","function":{"name":"sandbox_command","arguments":"{}"}}]}}],"usage":{"prompt_tokens":10000,"completion_tokens":20}}`))
	}))
	defer server.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	budget := testBudget()
	budget.MaxCostMicroUSD = 10000
	s := Scheduler{Store: st, Route: config.Route{Provider: "fixture", Model: "test", BaseURL: server.URL, Protocol: "openai-chat"}, Key: "key", Budget: budget}
	id, err := s.Start(context.Background(), "Task", "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "cost budget") {
		t.Fatalf("over-budget reply accepted: %v", err)
	}
	if requests.Load() == 0 {
		t.Fatal("cost test stopped before observing provider response")
	}
	plan, err := st.AgentPlan(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range plan.Jobs {
		if job.Status == "interrupted" && job.ToolCalls != 0 {
			t.Fatalf("tool ran after over-budget reply: %#v", job)
		}
	}
}
