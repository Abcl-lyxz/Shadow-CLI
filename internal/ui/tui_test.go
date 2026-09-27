package ui

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	keyring "github.com/zalando/go-keyring"
	_ "modernc.org/sqlite"
	"shadow/internal/catalog"
	"shadow/internal/config"
	"shadow/internal/policy"
	"shadow/internal/store"
)

func TestRulesCommandRequiresSignedExactReadPlanForSelectedOrigin(t *testing.T) {
	keyring.MockInit()
	key, err := config.PolicyApprovalKey(true)
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://example.com"
	rules := policy.TrustedRules{Version: 1, Origin: origin, Actions: []policy.ActionRule{{URL: origin + "/", Method: "GET", Effect: policy.EffectRead}}}
	approval, err := policy.SignRuleApproval(rules, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rulesPath, approvalPath := filepath.Join(dir, "rules.json"), filepath.Join(dir, "approval.json")
	write := func(path string, value any) {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(rulesPath, rules)
	write(approvalPath, approval)
	m := &Model{target: origin}
	m.handle("/rules " + rulesPath + " " + approvalPath)
	if m.approvedReads == nil || m.approvedReads.Origin() != origin {
		t.Fatalf("signed read plan not loaded: %v", m.lines)
	}
	m.running = true
	m.handle("/target https://other.example")
	m.handle("/rules clear")
	if m.target != origin || m.approvedReads == nil {
		t.Fatal("active run allowed target or approval change")
	}
	m.running = false
	m.handle("/target https://other.example")
	if m.approvedReads != nil {
		t.Fatal("approval survived origin change")
	}
	m.handle("/target " + origin)
	rules.Actions[0].URL = origin + "/changed"
	write(rulesPath, rules)
	m.handle("/rules " + rulesPath + " " + approvalPath)
	if m.approvedReads != nil {
		t.Fatal("changed rule document accepted under old signature")
	}
	rules.Actions[0].URL = origin + "/"
	rules.Actions[0].Effect = policy.EffectBlocked
	write(rulesPath, rules)
	m.handle("/rules " + rulesPath + " " + approvalPath)
	if m.approvedReads != nil {
		t.Fatal("non-read plan accepted")
	}
}

func TestConnectReusesExistingProviderCredentialWithoutPrompting(t *testing.T) {
	keyring.MockInit()
	t.Setenv("APPDATA", t.TempDir())
	if err := config.SetKey("custom-provider", "fixture-secret"); err != nil {
		t.Fatal(err)
	}
	m := &Model{cfg: config.Config{Version: 1, Route: config.Route{Provider: "custom-provider", Model: "old-model", BaseURL: "https://old.example/v1", Protocol: "openai-chat"}}}
	m.handle("/connect custom-provider https://new.example/v1")
	if m.secret || m.cfg.Route.BaseURL != "https://new.example/v1" || m.cfg.Route.Model != "" {
		t.Fatalf("existing credential was not reused safely: %+v", m.cfg.Route)
	}
	if got, err := config.Key("custom-provider"); err != nil || got != "fixture-secret" {
		t.Fatalf("stored credential changed: %v", err)
	}
}

func TestKeyRotateReplacesCredentialAndKeepsRoute(t *testing.T) {
	keyring.MockInit()
	if err := config.SetKey("CyberAPI", "old-fixture-key"); err != nil {
		t.Fatal(err)
	}
	route := config.Route{Provider: "CyberAPI", BaseURL: "provider.example/v1", Model: "selected-model", Protocol: "openai-chat"}
	m := &Model{cfg: config.Config{Version: 1, Route: route}, verifiedToolRoute: route, endpointModels: map[string]bool{"selected-model": true}}
	m.running = true
	m.handle("/key rotate")
	if m.secret {
		t.Fatal("active run accepted key rotation")
	}
	m.running = false
	m.handle("/key rotate")
	if !m.secret || !m.pendingKeyRotate {
		t.Fatal("key rotation did not open hidden input")
	}
	m.input = []rune("new-fixture-key")
	if strings.Contains(m.View().Content, "new-fixture-key") {
		t.Fatal("replacement key was visible before submission")
	}
	m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if got, err := config.Key("CyberAPI"); err != nil || got != "new-fixture-key" {
		t.Fatalf("replacement key unavailable: %v", err)
	}
	if m.cfg.Route != route || m.verifiedToolRoute != (config.Route{}) || m.endpointModels != nil || m.secret || m.pendingKeyRotate {
		t.Fatal("key rotation altered route or retained old capability evidence")
	}
	for _, line := range m.lines {
		if strings.Contains(line, "new-fixture-key") {
			t.Fatal("replacement key appeared in TUI log")
		}
	}
	m.Update(probeMsg{route: route, ok: true, epoch: 0})
	if m.verifiedToolRoute != (config.Route{}) {
		t.Fatal("pre-rotation probe revalidated the new key")
	}
}

func TestAgentBudgetRequiresKnownModelPrice(t *testing.T) {
	m := &Model{cfg: config.Config{Route: config.Route{Provider: "fixture", Model: "priced"}}}
	if _, err := m.agentBudget(); err == nil {
		t.Fatal("unknown model price accepted for cost-capped plan")
	}
	var model catalog.Model
	model.Cost = &struct {
		Input  float64 `json:"input"`
		Output float64 `json:"output"`
	}{Input: 0.5, Output: 2}
	m.catalog = catalog.Catalog{"fixture": catalog.Provider{Models: map[string]catalog.Model{"priced": model}}}
	budget, err := m.agentBudget()
	if err != nil || budget.InputPriceMicroUSDPerMillion != 500000 || budget.OutputPriceMicroUSDPerMillion != 2000000 || budget.MaxCostMicroUSD != 1000000 {
		t.Fatalf("budget %#v %v", budget, err)
	}
	m.cfg.Route.Model = "custom"
	m.manualPriceRoute = m.cfg.Route
	m.manualInputPrice = 1.25
	m.manualOutputPrice = 3
	budget, err = m.agentBudget()
	if err != nil || budget.InputPriceMicroUSDPerMillion != 1250000 || budget.OutputPriceMicroUSDPerMillion != 3000000 {
		t.Fatalf("manual budget %#v %v", budget, err)
	}
}

func TestModelsCommandStillListsCatalogModels(t *testing.T) {
	m := &Model{cfg: config.Config{Route: config.Route{Provider: "fixture"}}, catalog: catalog.Catalog{"fixture": catalog.Provider{Models: map[string]catalog.Model{"model-one": {ToolCall: true}}}}}
	m.handle("/models")
	if len(m.lines) == 0 || !strings.Contains(m.lines[len(m.lines)-1], "model-one") {
		t.Fatalf("model list missing: %#v", m.lines)
	}
}

func TestProviderAndToolModelSearch(t *testing.T) {
	m := &Model{cfg: config.Config{Route: config.Route{Provider: "alpha"}}, catalog: catalog.Catalog{
		"alpha": {ID: "alpha", Name: "Alpha API", Models: map[string]catalog.Model{"qwen-one": {ToolCall: true}, "other": {ToolCall: false}}},
		"beta":  {ID: "beta", Name: "Beta API"},
	}}
	m.handle("/connect search alpha")
	if !strings.Contains(m.lines[len(m.lines)-1], "alpha") || strings.Contains(m.lines[len(m.lines)-1], "beta") {
		t.Fatalf("provider search %v", m.lines)
	}
	m.handle("/models search qwen")
	if !strings.Contains(m.lines[len(m.lines)-1], "qwen-one") {
		t.Fatalf("model search %v", m.lines)
	}
	m.handle("/models search other")
	if !strings.Contains(m.lines[len(m.lines)-1], "No matching") {
		t.Fatalf("non-tool model was listed: %v", m.lines)
	}
}

func TestCapabilityGateUsesFreshCatalogOrRouteBoundProbe(t *testing.T) {
	route := config.Route{Provider: "fixture", Model: "model-one", BaseURL: "https://fixture.test/v1", Protocol: "openai-chat"}
	m := &Model{cfg: config.Config{Route: route}, catalog: catalog.Catalog{"fixture": catalog.Provider{API: route.BaseURL, Models: map[string]catalog.Model{"model-one": {ToolCall: true}}}}, catalogAt: time.Now()}
	if err := m.checkModelCapability(); err != nil {
		t.Fatal(err)
	}
	m.catalogAt = time.Now().Add(-8 * 24 * time.Hour)
	if err := m.checkModelCapability(); err == nil {
		t.Fatal("expired catalog authorized model tools")
	}
	m.catalogAt = time.Now()
	m.cfg.Route.BaseURL = "https://custom.test/v1"
	if err := m.checkModelCapability(); err == nil {
		t.Fatal("catalog capability carried to custom endpoint")
	}
	m.cfg.Route = route
	m.catalogStale = true
	if err := m.checkModelCapability(); err == nil {
		t.Fatal("stale catalog authorized model tools")
	}
	m.verifiedToolRoute = route
	if err := m.checkModelCapability(); err != nil {
		t.Fatal(err)
	}
	m.cfg.Route.BaseURL = "https://different.test/v1"
	if err := m.checkModelCapability(); err == nil {
		t.Fatal("probe carried across endpoint change")
	}
}

func TestEndpointProbeRequiresActualToolCallAndUsage(t *testing.T) {
	keyring.MockInit()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"probe","type":"function","function":{"name":"shadow_capability_probe","arguments":"{}"}}]}}],"usage":{"prompt_tokens":12,"completion_tokens":4}}`))
	}))
	defer server.Close()
	route := config.Route{Provider: "fixture", Model: "model-one", BaseURL: server.URL, Protocol: "openai-chat"}
	if err := config.SetKey(route.Provider, "test-key"); err != nil {
		t.Fatal(err)
	}
	msgs := make(chan tea.Msg, 1)
	m := &Model{cfg: config.Config{Route: route}, send: func(msg tea.Msg) { msgs <- msg }}
	m.handle("/models probe")
	select {
	case msg := <-msgs:
		m.Update(msg)
	case <-time.After(3 * time.Second):
		t.Fatal("probe timed out")
	}
	if err := m.checkModelCapability(); err != nil {
		t.Fatal(err)
	}
}

func TestTraceViewDoesNotRenderEventPayloadAndFitsSmallTerminal(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Append(context.Background(), "run-one", "network_decision", map[string]any{"method": "GET", "allowed": false, "url_sha256": "sensitive-hash"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Append(context.Background(), "run-one", "tool", map[string]any{"secret": "sensitive-payload"}); err != nil {
		t.Fatal(err)
	}
	m := &Model{store: st, currentRunID: "run-one", width: 38, height: 9, lines: []string{"log"}}
	m.handle("/trace")
	view := m.View().Content
	if strings.Contains(view, "sensitive-payload") || strings.Contains(view, "sensitive-hash") || !strings.Contains(view, "GET denied") || !strings.Contains(view, "tool") {
		t.Fatalf("unsafe trace view: %s", view)
	}
	for _, line := range strings.Split(view, "\n") {
		if len([]rune(strings.ReplaceAll(line, "\x1b[1;38;5;45m", ""))) > 60 {
			t.Fatalf("small view overflow: %q", line)
		}
	}
	m.nextPane()
	if m.pane != "memory" {
		t.Fatalf("pane navigation: %s", m.pane)
	}
}

func TestKeyboardPaneNavigationInCompactView(t *testing.T) {
	m := &Model{width: 28, height: 8, lines: []string{"ready"}}
	m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyTab}))
	if m.pane != "board" {
		t.Fatalf("Tab selected %q", m.pane)
	}
	m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape}))
	if m.pane != "log" {
		t.Fatalf("Esc selected %q", m.pane)
	}
	if strings.Contains(m.View().Content, "Store unavailable") {
		t.Fatal("log still displays board contents")
	}
}

func TestTUIRemovesTerminalControlsFromUntrustedText(t *testing.T) {
	m := &Model{width: 40, height: 8}
	m.add("answer \x1b[2Jsecret\x07")
	view := m.View().Content
	if strings.Contains(view, "\x1b[2J") || strings.Contains(view, "\x07") {
		t.Fatalf("terminal control escaped: %q", view)
	}
}

func TestArtifactCommandStaysInsideAttachment(t *testing.T) {
	parent := t.TempDir()
	inside := filepath.Join(parent, "inside")
	if err := os.Mkdir(inside, 0700); err != nil {
		t.Fatal(err)
	}
	makeAPK := func(path string) {
		t.Helper()
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		w := zip.NewWriter(f)
		for _, name := range []string{"AndroidManifest.xml", "classes.dex"} {
			entry, err := w.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write([]byte("fixture")); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	makeAPK(filepath.Join(inside, "app.apk"))
	makeAPK(filepath.Join(parent, "outside.apk"))
	m := &Model{workspace: inside}
	m.handle("/artifact app.apk")
	if len(m.lines) == 0 || !strings.Contains(m.lines[0], "Static APK") {
		t.Fatalf("artifact result: %v", m.lines)
	}
	m.lines = nil
	m.handle("/artifact ../outside.apk")
	if len(m.lines) == 0 || !strings.Contains(m.lines[0], "escapes") {
		t.Fatalf("outside artifact accepted: %v", m.lines)
	}
}

func TestManagedEvidenceKeySurvivesReopenAndRejectsReplacement(t *testing.T) {
	keyring.MockInit()
	path := filepath.Join(t.TempDir(), "data", "shadow.db")
	st, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	url := "http://fixture.test/private"
	body := []byte("private response")
	raw, err := json.Marshal(store.RawHTTP{RequestURL: url, Method: http.MethodGet, Status: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	u := sha256.Sum256([]byte(url))
	b := sha256.Sum256(body)
	id, err := st.RecordObservation(context.Background(), "run-1", store.EvidenceSummary{
		Origin: "http://fixture.test", URLSHA256: hex.EncodeToString(u[:]),
		Status: 200, ContentType: "text/plain", Bytes: len(body), SHA256: hex.EncodeToString(b[:]),
	}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.RawEvidence(context.Background(), "run-1", id)
	st.Close()
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("reopened evidence: %v", err)
	}
	if err := keyring.Set("shadow-cli-evidence", "master-v1", base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))); err != nil {
		t.Fatal(err)
	}
	if st, err := openStore(path); err == nil {
		st.Close()
		t.Fatal("replacement key opened existing evidence")
	}
}

func TestStartupAutomaticallyPrunesExpiredRuns(t *testing.T) {
	keyring.MockInit()
	path := filepath.Join(t.TempDir(), "data", "shadow.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, id := range []string{"old", "new"} {
		if err := st.Append(ctx, id, "note", nil); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	// Use a direct fixture edit before first provenance enrollment to create
	// an expired run without waiting for wall-clock time.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -10).UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx, "UPDATE events SET at=? WHERE run_id='old'", old); err != nil {
		t.Fatal(err)
	}
	db.Close()
	active, result, err := openStoreWithRetention(path, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if result.Purged != 1 {
		t.Fatalf("automatic prune result: %+v", result)
	}
	if events, err := active.Events(ctx, "old"); err != nil || len(events) != 0 {
		t.Fatalf("expired events remain: %v %v", events, err)
	}
	if err := active.AuditProvenance(ctx); err != nil {
		t.Fatal(err)
	}
}
