package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"shadow/internal/policy"
	"shadow/internal/store"
)

func TestFixtureRunNetworkKeepsTypedActionsInsideOneRun(t *testing.T) {
	ctx := context.Background()
	var st *store.Store
	var present atomic.Bool
	var writes, deletes, logins atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		events, err := st.Events(ctx, "run")
		if err != nil || len(events) == 0 || events[len(events)-1].Kind != "network_decision" {
			t.Errorf("%s arrived without a network decision: %#v %v", r.Method, events, err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			if !present.Load() {
				w.WriteHeader(http.StatusNotFound)
			}
			fmt.Fprintf(w, `{"resource":"shadow_marker_1","present":%t}`, present.Load())
		case http.MethodPost:
			if r.URL.Path == "/login" {
				logins.Add(1)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			writes.Add(1)
			present.Store(true)
			w.WriteHeader(http.StatusCreated)
		case http.MethodDelete:
			deletes.Add(1)
			present.Store(false)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()
	write, read := fixtureWriteRules(server.URL)
	auth := policy.ActionRule{URL: server.URL + "/login", Method: http.MethodPost, Effect: policy.EffectAuth}
	rules := []policy.ActionRule{write, read, auth}
	var err error
	st, err = store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	scope, _ := policy.FromTarget(server.URL)
	if err := st.StartRun(ctx, "run", scope, rules); err != nil {
		t.Fatal(err)
	}
	opts := Options{AllowLoopback: true, allowedURLs: []string{server.URL + "/unlisted"}, interval: time.Millisecond}
	if _, err := NewFixtureRunNetwork(ctx, st, "run", rules, Options{}); err == nil {
		t.Fatal("fixture network accepted a missing loopback grant")
	}
	if _, err := NewFixtureRunNetwork(ctx, st, "other", rules, opts); err == nil {
		t.Fatal("fixture network inherited another run's grants")
	}
	changed := read
	changed.URL += "?extra=1"
	if _, err := NewFixtureRunNetwork(ctx, st, "run", []policy.ActionRule{changed}, opts); err == nil {
		t.Fatal("fixture network accepted a route outside the run snapshot")
	}
	network, err := NewFixtureRunNetwork(ctx, st, "run", rules, opts)
	if err != nil {
		t.Fatal(err)
	}
	writeID, readID, authID := FixtureWriteActionID(write), ReadActionID(read), FixtureAuthActionID(auth)
	if ids := network.WriteActionIDs(); len(ids) != 1 || ids[0] != writeID {
		t.Fatalf("write catalog: %v", ids)
	}
	if ids := network.ReadActionIDs(); len(ids) != 1 || ids[0] != readID {
		t.Fatalf("read catalog: %v", ids)
	}
	if ids := network.AuthActionIDs(); len(ids) != 1 || ids[0] != authID {
		t.Fatalf("auth catalog: %v", ids)
	}
	if err := network.Authenticate(ctx, authID); err == nil || logins.Load() != 0 {
		t.Fatalf("authentication request reached fixture: %v logins=%d", err, logins.Load())
	}
	if _, _, err := network.ReadRecorded(ctx, "unknown"); err == nil {
		t.Fatal("unknown read action accepted")
	}
	if _, _, err := network.WriteMarker(ctx, readID); err == nil || writes.Load() != 0 {
		t.Fatalf("read ID became a write grant: %v writes=%d", err, writes.Load())
	}
	if _, err := network.CleanupMarker(ctx, readID, 1, 1); err == nil || deletes.Load() != 0 {
		t.Fatalf("read ID became a cleanup grant: %v deletes=%d", err, deletes.Load())
	}
	actionID, presenceID, err := network.WriteMarker(ctx, writeID)
	if err != nil || actionID <= 0 || presenceID <= 0 || writes.Load() != 1 || !present.Load() {
		t.Fatalf("typed marker write: action=%d presence=%d writes=%d err=%v", actionID, presenceID, writes.Load(), err)
	}
	if _, _, err := network.WriteMarker(ctx, writeID); err == nil || writes.Load() != 1 {
		t.Fatalf("marker write replayed: %v writes=%d", err, writes.Load())
	}
	if _, err := network.CleanupMarker(ctx, writeID, actionID, presenceID); err != nil || deletes.Load() != 1 || present.Load() {
		t.Fatalf("typed cleanup: deletes=%d present=%t err=%v", deletes.Load(), present.Load(), err)
	}
	events, err := st.Events(ctx, "run")
	if err != nil {
		t.Fatal(err)
	}
	var methods []string
	for _, event := range events {
		if event.Kind != "network_decision" {
			continue
		}
		var decision struct {
			Method  string `json:"method"`
			Allowed bool   `json:"allowed"`
		}
		if err := json.Unmarshal(event.Payload, &decision); err != nil {
			t.Fatal(err)
		}
		if decision.Method == http.MethodPost && !decision.Allowed {
			continue // authentication was classified but blocked before dispatch
		}
		if !decision.Allowed {
			t.Fatalf("unexpected denied fixture request: %s", event.Payload)
		}
		methods = append(methods, decision.Method)
	}
	if len(methods) != 6 || methods[0] != "GET" || methods[1] != "POST" || methods[2] != "GET" || methods[3] != "GET" || methods[4] != "DELETE" || methods[5] != "GET" {
		t.Fatalf("fixture decision order: %v", methods)
	}
	if err := st.PurgeRun(ctx, "run"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := network.ReadRecorded(ctx, readID); err == nil {
		t.Fatal("purged run retained a read action")
	}
}
